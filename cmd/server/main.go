// Command server is the defakto-spiffe-temporal custom Temporal server build.
//
// It is the stock go.temporal.io/server wired with two hooks:
//   - authn.ClaimMapper   maps a Defakto SPIFFE identity to Temporal Claims.
//   - authz.CedarAuthorizer decides f(role_class, namespace, verb_class).
//
// Everything else — persistence, the frontend, matching, history — is the
// upstream server unchanged. This package compiles those hooks into a single
// binary published as the defakto-spiffe-temporal image. A customer runs it
// on the stock Temporal Helm chart by swapping image: and mounting a ConfigMap
// that carries the trust-domain/issuer config and the Cedar policy.
package main

import (
	"context"
	"errors"
	"fmt"
	stdlog "log"
	"os"
	"strings"
	"time"

	// Persistence plugins the stock server loads; a custom main must import
	// them itself or the server cannot open its datastore.
	_ "go.temporal.io/server/common/persistence/sql/sqlplugin/mysql"
	_ "go.temporal.io/server/common/persistence/sql/sqlplugin/postgresql"
	_ "go.temporal.io/server/common/persistence/sql/sqlplugin/sqlite"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/config"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/common/log/tag"
	"go.temporal.io/server/common/metrics"
	"go.temporal.io/server/temporal"

	"github.com/defakto-security/temporal/authn"
	"github.com/defakto-security/temporal/authz"
	spiffeconfig "github.com/defakto-security/temporal/config"
	"github.com/defakto-security/temporal/dbauth"
)

// EnvServices names the env var selecting which Temporal services this process
// runs, as a comma-separated list (e.g. "frontend,history,matching,worker").
// It mirrors the stock server's TEMPORAL_SERVICES input; unset means run the
// default set. The stock Helm chart sets this per role, so a custom main MUST
// honor it or every pod runs every service.
const EnvServices = "TEMPORAL_SERVICES"

// main runs the server and exits non-zero on error.
func main() {
	if ran, err := runTool(os.Args); ran {
		if err != nil {
			stdlog.Printf("defakto-spiffe-temporal: %s: %v", CmdElasticsearchTool, err)
			os.Exit(1)
		}
		return
	}
	if err := run(); err != nil {
		stdlog.Fatalf("defakto-spiffe-temporal: %v", err)
	}
}

// run starts the Temporal server with the Cedar authorizer.
func run() error {
	logger := log.NewZapLogger(log.BuildZapLogger(log.Config{}))

	// Our own config contract (trust domain, issuer/aud/JWKS, DevID template,
	// policy path), read from the path the customer's ConfigMap mounts.
	appCfg, err := spiffeconfig.Load(os.Getenv(spiffeconfig.EnvConfigPath))
	if err != nil {
		return err
	}

	// The Cedar authorizer loads + validates the customer-owned policy and
	// fails closed on an absent, unparseable, or schema-invalid policy.
	authorizer, err := authz.NewCedarAuthorizer(appCfg, logger)
	if err != nil {
		return err
	}

	// The server builds its metrics handler from the Temporal config AFTER the
	// authorizer is constructed, so the authorizer cannot borrow it. Build it
	// here, the same way the server would, and hand the one instance to both:
	// decision counters then appear on the server's own metrics endpoint.
	metricsHandler, err := temporalMetricsHandler(logger)
	if err != nil {
		return err
	}
	authorizer.WithMetrics(metricsHandler)
	defer func() { _ = authorizer.Close() }()

	// Optional RDS IAM auth: load Temporal's config here so we can hook the
	// SQL stores, then hand the result to the server.
	var iamOpts []temporal.ServerOption
	if appCfg.DatabaseIAM.Enabled {
		mgr, tcfg, err := setupDatabaseIAM(appCfg.DatabaseIAM, logger)
		if err != nil {
			return err
		}
		defer mgr.Close()
		iamOpts = append(iamOpts, temporal.WithConfig(tcfg))
	}

	opts := []temporal.ServerOption{
		// Without ForServices the server starts NO services (upstream skips any
		// service not named), so the process would run no frontend/history/
		// matching/worker and silently idle. Honor TEMPORAL_SERVICES as the
		// stock image does, defaulting to the full set.
		temporal.ForServices(servicesToStart()),
		temporal.WithConfigLoader(
			temporalConfigDir(),
			os.Getenv(config.EnvKeyEnvironment),
			os.Getenv(config.EnvKeyAvailabilityZone),
		),
		temporal.WithLogger(logger),
		temporal.WithCustomMetricsHandler(metricsHandler),
		temporal.WithAuthorizer(authorizer),
		temporal.WithClaimMapper(func(*config.Config) authorization.ClaimMapper {
			return authn.NewClaimMapper(appCfg, logger)
		}),
	}
	s, err := temporal.NewServer(append(opts, iamOpts...)...)
	if err != nil {
		return err
	}

	if err := s.Start(); err != nil {
		return err
	}
	<-temporal.InterruptCh()
	return s.Stop()
}

// temporalMetricsHandler builds the metrics handler from Temporal's own config
// (global.metrics), exactly as the server does when none is supplied.
func temporalMetricsHandler(logger log.Logger) (metrics.Handler, error) {
	cfg, err := config.Load(
		config.WithConfigDir(temporalConfigDir()),
		config.WithEnv(os.Getenv(config.EnvKeyEnvironment)),
		config.WithZone(os.Getenv(config.EnvKeyAvailabilityZone)),
	)
	if err != nil {
		return nil, fmt.Errorf("loading temporal config for metrics: %w", err)
	}
	return metrics.MetricsHandlerFromConfig(logger, cfg.Global.Metrics)
}

// setupDatabaseIAM loads Temporal's config and points every SQL store at the
// cached RDS IAM token. The caller must Close the returned Manager.
func setupDatabaseIAM(iam spiffeconfig.DatabaseIAMConfig, logger log.Logger) (*dbauth.Manager, *config.Config, error) {
	region := iam.Region
	if region == "" {
		region = os.Getenv("AWS_REGION")
	}
	if region == "" {
		return nil, nil, errors.New("databaseIAM: region is unset and AWS_REGION is empty")
	}
	awsCfg, err := awsconfig.LoadDefaultConfig(context.Background(),
		awsconfig.WithRegion(region),
		// Refresh IRSA credentials 5 minutes early, so a token is never
		// signed with credentials that are about to expire.
		awsconfig.WithCredentialsCacheOptions(func(o *aws.CredentialsCacheOptions) {
			o.ExpiryWindow = 5 * time.Minute
		}),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("databaseIAM: loading AWS config: %w", err)
	}
	tcfg, err := config.Load(
		config.WithConfigDir(temporalConfigDir()),
		config.WithEnv(os.Getenv(config.EnvKeyEnvironment)),
		config.WithZone(os.Getenv(config.EnvKeyAvailabilityZone)),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("databaseIAM: loading Temporal config: %w", err)
	}
	mgr := dbauth.NewManager(region, awsCfg.Credentials, iam.RefreshInterval, func(err error) {
		logger.Error("RDS IAM token refresh failed; keeping the previous token", tag.Error(err))
	})
	if err := mgr.Apply(tcfg); err != nil {
		mgr.Close()
		return nil, nil, fmt.Errorf("databaseIAM: %w", err)
	}
	return mgr, tcfg, nil
}

// temporalConfigDir returns the Temporal config directory.
func temporalConfigDir() string {
	if dir := os.Getenv(config.EnvKeyConfigDir); dir != "" {
		return dir
	}
	return "config"
}

// servicesToStart returns the service names this process should run. It reads
// EnvServices as a comma-separated list, trimming blanks, and falls back to
// temporal.DefaultServices (frontend, history, matching, worker) when unset or
// empty — matching the stock server's --service/TEMPORAL_SERVICES behavior.
func servicesToStart() []string {
	raw := os.Getenv(EnvServices)
	if strings.TrimSpace(raw) == "" {
		return temporal.DefaultServices
	}
	var names []string
	for part := range strings.SplitSeq(raw, ",") {
		if name := strings.TrimSpace(part); name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return temporal.DefaultServices
	}
	return names
}
