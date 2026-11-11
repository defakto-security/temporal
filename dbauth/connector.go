package dbauth

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/iancoleman/strcase"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/jmoiron/sqlx"
	"go.temporal.io/server/common/config"
)

// PluginPGX is the only Temporal SQL plugin this package supports. The lib/pq
// plugin has no per-connect password hook that we can feed from a cache.
const PluginPGX = "postgres12_pgx"

const pgxDriverName = "pgx"

// pingTimeout bounds the first connection, so a stalled handshake cannot hold
// up startup (or a reconnect) forever.
const pingTimeout = 30 * time.Second

// reservedAttrs are libpq/pgx settings that connectAttributes must not set:
// they would redirect the connection, change the identity the token was signed
// for, or bypass the cached token.
var reservedAttrs = map[string]bool{
	"host": true, "hostaddr": true, "port": true, "user": true, "password": true,
	"dbname": true, "database": true, "service": true, "passfile": true, "servicefile": true,
}

// attrKey normalizes a connectAttributes key the way pgx matches settings.
func attrKey(k string) string { return strings.ToLower(strings.TrimSpace(k)) }

// Manager owns one TokenSource per (endpoint, user) and builds Temporal SQL
// connections that read from them. Temporal may call Connect again after a
// failover; sharing sources keeps that from starting more refresh loops.
type Manager struct {
	region   string
	creds    aws.CredentialsProvider
	interval time.Duration
	onError  func(error)

	mu      sync.Mutex
	closed  bool
	sources map[string]*TokenSource
}

// NewManager returns a Manager. interval of zero means DefaultRefreshInterval.
// onError may be nil.
func NewManager(region string, creds aws.CredentialsProvider, interval time.Duration, onError func(error)) *Manager {
	return &Manager{
		region:   region,
		creds:    creds,
		interval: interval,
		onError:  onError,
		sources:  map[string]*TokenSource{},
	}
}

// Close stops every refresh loop.
func (m *Manager) Close() {
	m.mu.Lock()
	m.closed = true
	sources := m.sources
	m.sources = map[string]*TokenSource{}
	m.mu.Unlock()
	for _, s := range sources {
		s.Close()
	}
}

// Apply sets the Connect hook on every SQL datastore in cfg. It rejects a
// store that cannot use IAM auth, so a misconfigured store fails at startup
// instead of connecting with the wrong credential.
func (m *Manager) Apply(cfg *config.Config) error {
	var errs []error
	for name, ds := range cfg.Persistence.DataStores {
		if ds.SQL == nil {
			continue
		}
		if err := checkStore(ds.SQL); err != nil {
			errs = append(errs, fmt.Errorf("datastore %q: %w", name, err))
			continue
		}
		// Sign the first token now, so bad AWS credentials stop startup
		// instead of surfacing later as an unavailable database.
		if _, err := m.source(context.Background(), ds.SQL.ConnectAddr, ds.SQL.User); err != nil {
			errs = append(errs, fmt.Errorf("datastore %q: %w", name, err))
			continue
		}
		ds.SQL.Connect = m.Connect
		cfg.Persistence.DataStores[name] = ds
	}
	return errors.Join(errs...)
}

func checkStore(c *config.SQL) error {
	var errs []error
	if c.PluginName != PluginPGX {
		errs = append(errs, fmt.Errorf("pluginName must be %q for IAM auth, got %q", PluginPGX, c.PluginName))
	}
	if c.Password != "" || c.PasswordCommand != nil {
		errs = append(errs, errors.New("password and passwordCommand must be unset for IAM auth"))
	}
	if c.User == "" || c.DatabaseName == "" || c.ConnectAddr == "" {
		errs = append(errs, errors.New("user, databaseName and connectAddr are required for IAM auth"))
	}
	if _, port, err := net.SplitHostPort(c.ConnectAddr); err != nil || port == "" {
		errs = append(errs, fmt.Errorf("connectAddr %q must be the RDS endpoint as host:port", c.ConnectAddr))
	}
	switch {
	case c.TLS == nil || !c.TLS.Enabled:
		errs = append(errs, errors.New("tls.enabled must be true: RDS rejects IAM auth without TLS"))
	case !c.TLS.EnableHostVerification || c.TLS.CaFile == "":
		// The token is a bearer secret for 15 minutes. Never send it to a
		// server whose certificate was not checked.
		errs = append(errs, errors.New("tls.enableHostVerification must be true and tls.caFile set (the RDS CA bundle)"))
	}
	for k, v := range c.ConnectAttributes {
		switch key := attrKey(k); {
		case reservedAttrs[key]:
			errs = append(errs, fmt.Errorf("connectAttributes.%s is not allowed with IAM auth", strings.TrimSpace(k)))
		case key == "sslmode" && strings.TrimSpace(v) != "verify-full":
			errs = append(errs, fmt.Errorf("connectAttributes.sslmode %q is not allowed; IAM auth always uses verify-full", v))
		}
	}
	return errors.Join(errs...)
}

func (m *Manager) source(ctx context.Context, endpoint, user string) (*TokenSource, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return nil, errors.New("dbauth: manager is closed")
	}
	key := endpoint + "|" + user
	if s, ok := m.sources[key]; ok {
		return s, nil
	}
	s, err := NewTokenSource(ctx, Options{
		Endpoint:        endpoint,
		Region:          m.region,
		User:            user,
		Credentials:     m.creds,
		RefreshInterval: m.interval,
		OnError:         m.onError,
	})
	if err != nil {
		return nil, err
	}
	m.sources[key] = s
	return s, nil
}

// Connect is the config.SQL.Connect hook. It opens a pgx pool whose every new
// physical connection takes its password from the cached token.
func (m *Manager) Connect(c *config.SQL) (*sqlx.DB, error) {
	ctx := context.Background()
	src, err := m.source(ctx, c.ConnectAddr, c.User)
	if err != nil {
		return nil, err
	}
	base, err := pgxConfig(c)
	if err != nil {
		return nil, err
	}
	db := sqlx.NewDb(sql.OpenDB(&connector{base: base, src: src}), pgxDriverName)
	pingCtx, cancel := context.WithTimeout(ctx, pingTimeout)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, err
	}
	if c.MaxConns > 0 {
		db.SetMaxOpenConns(c.MaxConns)
	}
	if c.MaxIdleConns > 0 {
		db.SetMaxIdleConns(c.MaxIdleConns)
	}
	if c.MaxConnLifetime > 0 {
		db.SetConnMaxLifetime(c.MaxConnLifetime)
	}
	// Same struct-field mapping the stock Temporal session sets.
	db.MapperFunc(strcase.ToSnake)
	return db, nil
}

// pgxConfig builds the pgx config from Temporal's SQL settings, with TLS
// handled as the stock postgres session does. The password is left empty.
func pgxConfig(c *config.SQL) (*pgx.ConnConfig, error) {
	attrs := url.Values{}
	for k, v := range c.ConnectAttributes {
		if reservedAttrs[attrKey(k)] {
			return nil, fmt.Errorf("connectAttributes.%s is not allowed with IAM auth", strings.TrimSpace(k))
		}
		attrs.Set(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	// Always verify the server certificate; checkStore rejects other modes.
	attrs.Set("sslmode", "verify-full")
	if c.TLS.CaFile != "" && attrs.Get("sslrootcert") == "" {
		attrs.Set("sslrootcert", c.TLS.CaFile)
	}
	if (c.TLS.CertFile == "") != (c.TLS.KeyFile == "") {
		return nil, errors.New("tls certFile and keyFile must be set together")
	}
	if c.TLS.CertFile != "" {
		attrs.Set("sslcert", c.TLS.CertFile)
		attrs.Set("sslkey", c.TLS.KeyFile)
	}
	u := url.URL{
		Scheme:   "postgres",
		User:     url.User(c.User),
		Host:     c.ConnectAddr,
		Path:     "/" + c.DatabaseName,
		RawQuery: attrs.Encode(),
	}
	return pgx.ParseConfig(u.String())
}

// connector is a driver.Connector that reads the cached token on each connect.
type connector struct {
	base *pgx.ConnConfig
	src  *TokenSource
}

func (c *connector) Connect(ctx context.Context) (driver.Conn, error) {
	token, err := c.src.Token()
	if err != nil {
		return nil, err
	}
	cfg := c.base.Copy()
	cfg.Password = token
	return stdlib.GetConnector(*cfg, stdlib.OptionAfterConnect(registerCustomTypes)).Connect(ctx)
}

func (c *connector) Driver() driver.Driver { return stdlib.GetDefaultDriver() }

// registerCustomTypes mirrors Temporal's own pgx setup: it stores
// time.Duration as bigint nanoseconds, not as a Postgres interval.
func registerCustomTypes(_ context.Context, conn *pgx.Conn) error {
	conn.TypeMap().RegisterDefaultPgType(time.Duration(0), "int8")
	conn.TypeMap().RegisterDefaultPgType((*time.Duration)(nil), "int8")
	return nil
}
