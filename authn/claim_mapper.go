// Package authn maps a Defakto SPIFFE identity to Temporal Claims and a derived
// role_class. It performs authentication only — it assigns no verb grants. The
// SVID proves who the caller is; what they may do is decided by the authorizer.
//
// Milestone 1 (FRY-1368): JWT-SVID via authInfo.AuthToken (primary) and
// X.509-SVID via the URI SAN in authInfo.TLSConnection. role_class is a
// structural prefix/issuer test on the SPIFFE ID, forge-resistant because
// issuance policy — not the holder — controls the path.
package authn

import (
	"go.temporal.io/server/common/authorization"
	"go.temporal.io/server/common/log"

	spiffeconfig "github.com/defakto-security/temporal/config"
)

// RoleClass is the single load-bearing identity distinction: service vs human.
// It is derived structurally from the SPIFFE ID, never asserted by the caller.
type RoleClass string

const (
	// RoleClassService is any workload SVID (K8s or Linux node-group path shape).
	RoleClassService RoleClass = "service"
	// RoleClassHuman is a Defakto Developer Identity (DevID) SVID or a
	// portal-issued OIDC token. Carries an on-call sub-state handled downstream.
	RoleClassHuman RoleClass = "human"
	// RoleClassUnknown is an identity that matched no known shape. The
	// authorizer must treat it as unauthorized (fail closed).
	RoleClassUnknown RoleClass = ""
)

// ClaimMapper implements authorization.ClaimMapper against Defakto SPIFFE.
type ClaimMapper struct {
	cfg    *spiffeconfig.Config
	logger log.Logger
}

var _ authorization.ClaimMapper = (*ClaimMapper)(nil)

// NewClaimMapper builds a ClaimMapper from the config contract.
func NewClaimMapper(cfg *spiffeconfig.Config, logger log.Logger) *ClaimMapper {
	return &ClaimMapper{cfg: cfg, logger: logger}
}

// GetClaims maps the request's auth info to Temporal Claims.
//
// It stashes the derived RoleClass in Claims.Extensions and leaves the Role
// bitmask empty: grants are the authorizer's job, not the claim mapper's. This
// is the seam FRY-1368 fills in — SVID parse + role_class derivation.
func (m *ClaimMapper) GetClaims(authInfo *authorization.AuthInfo) (*authorization.Claims, error) {
	subject, class := m.derive(authInfo)
	return &authorization.Claims{
		Subject:    subject,
		AuthType:   "spiffe",
		Extensions: class,
	}, nil
}

// derive resolves the subject SPIFFE ID and its role class.
//
// TODO(FRY-1368): parse the JWT-SVID from authInfo.AuthToken and the X.509-SVID
// URI SAN from authInfo.TLSConnection, validate against m.cfg.TrustDomain, and
// classify human vs service by the m.cfg.DevIDTemplate prefix. The current
// stub returns Unknown so the authorizer denies — fail closed until implemented.
func (m *ClaimMapper) derive(_ *authorization.AuthInfo) (subject string, class RoleClass) {
	return "", RoleClassUnknown
}
