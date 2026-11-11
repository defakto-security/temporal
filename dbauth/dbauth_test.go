package dbauth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/stretchr/testify/require"
	"go.temporal.io/server/common/auth"
	"go.temporal.io/server/common/config"
)

// countingCreds counts Retrieve calls and can be made to fail.
type countingCreds struct {
	calls atomic.Int32
	fail  atomic.Bool
}

func (c *countingCreds) Retrieve(context.Context) (aws.Credentials, error) {
	c.calls.Add(1)
	if c.fail.Load() {
		return aws.Credentials{}, errors.New("sts down")
	}
	return aws.Credentials{AccessKeyID: "AKIDEXAMPLE", SecretAccessKey: "secret", SessionToken: "tok"}, nil
}

func TestBuildTokenShape(t *testing.T) {
	t.Parallel()
	now := time.Now()
	tok, expires, err := buildToken(t.Context(), &countingCreds{}, "db.example:5432", "us-east-2", "temporal", now)
	require.NoError(t, err)
	require.NotContains(t, tok, "https://")

	u, err := url.Parse("https://" + tok)
	require.NoError(t, err)
	q := u.Query()
	require.Equal(t, "connect", q.Get("Action"))
	require.Equal(t, "temporal", q.Get("DBUser"))
	require.Equal(t, "900", q.Get("X-Amz-Expires"))
	require.Contains(t, q.Get("X-Amz-Credential"), "/us-east-2/rds-db/aws4_request")
	require.WithinDuration(t, now.Add(TokenLifetime), expires, time.Second)
}

// TestTokenExpiryClampedToCredentials: a token signed with credentials that
// expire in 2 minutes must not be served for 15.
func TestTokenExpiryClampedToCredentials(t *testing.T) {
	t.Parallel()
	soon := time.Now().Add(2 * time.Minute)
	creds := aws.CredentialsProviderFunc(func(context.Context) (aws.Credentials, error) {
		return aws.Credentials{AccessKeyID: "A", SecretAccessKey: "s", CanExpire: true, Expires: soon}, nil
	})
	_, expires, err := buildToken(t.Context(), creds, "db:5432", "us-east-2", "u", time.Now())
	require.NoError(t, err)
	require.WithinDuration(t, soon, expires, time.Second)
}

func TestBuildTokenRejectsEndpointWithoutPort(t *testing.T) {
	t.Parallel()
	_, _, err := buildToken(t.Context(), &countingCreds{}, "db.example", "us-east-2", "u", time.Now())
	require.Error(t, err)
}

func TestTokenIsServedFromCache(t *testing.T) {
	t.Parallel()
	creds := &countingCreds{}
	src, err := NewTokenSource(t.Context(), Options{
		Endpoint: "db:5432", Region: "us-east-2", User: "u", Credentials: creds,
	})
	require.NoError(t, err)
	t.Cleanup(src.Close)

	before := creds.calls.Load()
	for range 1000 {
		_, err := src.Token()
		require.NoError(t, err)
	}
	require.Equal(t, before, creds.calls.Load(), "Token() must not touch credentials")
}

func TestRefreshLoopRenewsToken(t *testing.T) {
	t.Parallel()
	creds := &countingCreds{}
	src, err := NewTokenSource(t.Context(), Options{
		Endpoint: "db:5432", Region: "us-east-2", User: "u", Credentials: creds,
		RefreshInterval: 10 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(src.Close)
	require.Eventually(t, func() bool { return creds.calls.Load() >= 3 }, 5*time.Second, 5*time.Millisecond)
}

func TestFailedRefreshKeepsOldTokenUntilExpiry(t *testing.T) {
	t.Parallel()
	creds := &countingCreds{}
	var mu sync.Mutex
	now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	clock := func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	var errCount atomic.Int32

	src, err := NewTokenSource(t.Context(), Options{
		Endpoint: "db:5432", Region: "us-east-2", User: "u", Credentials: creds,
		RefreshInterval: 10 * time.Millisecond, Now: clock,
		OnError: func(error) { errCount.Add(1) },
	})
	require.NoError(t, err)
	t.Cleanup(src.Close)

	creds.fail.Store(true)
	require.Eventually(t, func() bool { return errCount.Load() > 0 }, 5*time.Second, 5*time.Millisecond)
	_, err = src.Token()
	require.NoError(t, err, "old token is still valid after a failed refresh")

	mu.Lock()
	now = now.Add(TokenLifetime)
	mu.Unlock()
	_, err = src.Token()
	require.ErrorContains(t, err, "expired")
}

func TestFirstTokenFailureFailsFast(t *testing.T) {
	t.Parallel()
	creds := &countingCreds{}
	creds.fail.Store(true)
	_, err := NewTokenSource(t.Context(), Options{
		Endpoint: "db:5432", Region: "us-east-2", User: "u", Credentials: creds,
	})
	require.ErrorContains(t, err, "first token")
}

func TestOptionsValidation(t *testing.T) {
	t.Parallel()
	_, err := NewTokenSource(t.Context(), Options{RefreshInterval: 20 * time.Minute})
	require.Error(t, err)
}

func validSQL() *config.SQL {
	return &config.SQL{
		PluginName: PluginPGX, User: "temporal", DatabaseName: "temporal", ConnectAddr: "db:5432",
		TLS: &auth.TLS{Enabled: true, EnableHostVerification: true, CaFile: "/etc/rds-ca.pem"},
	}
}

func TestApplyRejectsUnsafeStores(t *testing.T) {
	t.Parallel()
	mk := func(mut func(*config.SQL)) *config.Config {
		s := validSQL()
		mut(s)
		return &config.Config{Persistence: config.Persistence{DataStores: map[string]config.DataStore{"default": {SQL: s}}}}
	}
	m := NewManager("us-east-2", &countingCreds{}, 0, nil)
	t.Cleanup(m.Close)

	require.NoError(t, m.Apply(mk(func(*config.SQL) {})))

	for name, mut := range map[string]func(*config.SQL){
		"pq plugin":     func(s *config.SQL) { s.PluginName = "postgres12" },
		"password set":  func(s *config.SQL) { s.Password = "x" },
		"no tls":        func(s *config.SQL) { s.TLS = nil },
		"no verify":     func(s *config.SQL) { s.TLS.EnableHostVerification = false },
		"no ca file":    func(s *config.SQL) { s.TLS.CaFile = "" },
		"sslmode off":   func(s *config.SQL) { s.ConnectAttributes = map[string]string{"sslmode": "disable"} },
		"host override": func(s *config.SQL) { s.ConnectAttributes = map[string]string{" Host ": "evil"} },
		"user override": func(s *config.SQL) { s.ConnectAttributes = map[string]string{"USER": "root"} },
		"port override": func(s *config.SQL) { s.ConnectAttributes = map[string]string{"port": "1"} },
		"no port":       func(s *config.SQL) { s.ConnectAddr = "db.example" },
		"no user":       func(s *config.SQL) { s.User = "" },
	} {
		require.Error(t, m.Apply(mk(mut)), name)
	}
}

func TestApplySetsConnectHook(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{Persistence: config.Persistence{DataStores: map[string]config.DataStore{
		"default": {SQL: validSQL()},
		"es":      {},
	}}}
	m := NewManager("us-east-2", &countingCreds{}, 0, nil)
	t.Cleanup(m.Close)
	require.NoError(t, m.Apply(cfg))
	require.NotNil(t, cfg.Persistence.DataStores["default"].SQL.Connect)
}

// writeCA writes a throwaway self-signed CA certificate and returns its path.
func writeCA(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test-ca"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	path := filepath.Join(t.TempDir(), "ca.pem")
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600))
	return path
}

func TestPgxConfigVerifiesServer(t *testing.T) {
	t.Parallel()
	s := validSQL()
	s.TLS.CaFile = writeCA(t)
	cfg, err := pgxConfig(s)
	require.NoError(t, err)
	require.Equal(t, "db", cfg.Host)
	require.Equal(t, uint16(5432), cfg.Port)
	require.Equal(t, "temporal", cfg.User)
	require.Empty(t, cfg.Password)
	require.NotNil(t, cfg.TLSConfig)
	require.False(t, cfg.TLSConfig.InsecureSkipVerify, "server certificate must be verified")
	require.Equal(t, "db", cfg.TLSConfig.ServerName)
}

func TestPgxConfigCertWithoutKey(t *testing.T) {
	t.Parallel()
	s := validSQL()
	s.TLS.CaFile = writeCA(t)
	s.TLS.CertFile = "c"
	_, err := pgxConfig(s)
	require.Error(t, err)
}

func TestManagerRejectsAfterClose(t *testing.T) {
	t.Parallel()
	m := NewManager("us-east-2", &countingCreds{}, 0, nil)
	m.Close()
	_, err := m.source(t.Context(), "db:5432", "u")
	require.ErrorContains(t, err, "closed")
}

func TestPgxConfigRejectsReservedAttrs(t *testing.T) {
	t.Parallel()
	s := validSQL()
	s.TLS.CaFile = writeCA(t)
	s.ConnectAttributes = map[string]string{"dbname": "other"}
	_, err := pgxConfig(s)
	require.ErrorContains(t, err, "not allowed")
}
