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
	stdlog "log"
	"os"

	// Persistence plugins the stock server loads; a custom main must import
	// them itself or the server cannot open its datastore.
	_ "go.temporal.io/server/common/persistence/sql/sqlplugin/mysql"
	_ "go.temporal.io/server/common/persistence/sql/sqlplugin/postgresql"
	_ "go.temporal.io/server/common/persistence/sql/sqlplugin/sqlite"

	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/config"
	"go.temporal.io/server/common/log"
	"go.temporal.io/server/temporal"

	"github.com/defakto-security/temporal/authn"
	"github.com/defakto-security/temporal/authz"
	spiffeconfig "github.com/defakto-security/temporal/config"
)

func main() {
	if err := run(); err != nil {
		stdlog.Fatalf("defakto-spiffe-temporal: %v", err)
	}
}

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

	s, err := temporal.NewServer(
		temporal.WithConfigLoader(
			temporalConfigDir(),
			os.Getenv(config.EnvKeyEnvironment),
			os.Getenv(config.EnvKeyAvailabilityZone),
		),
		temporal.WithLogger(logger),
		temporal.WithAuthorizer(authorizer),
		temporal.WithClaimMapper(func(*config.Config) authorization.ClaimMapper {
			return authn.NewClaimMapper(appCfg, logger)
		}),
	)
	if err != nil {
		return err
	}

	if err := s.Start(); err != nil {
		return err
	}
	<-temporal.InterruptCh()
	return s.Stop()
}

func temporalConfigDir() string {
	if dir := os.Getenv(config.EnvKeyConfigDir); dir != "" {
		return dir
	}
	return "config"
}
