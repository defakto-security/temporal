---
name: SPIFFE Native Support for Temporal
description: Design spec for x509 claim mapper and SpiffeCertProvider (issue #9152)
type: project
---

# SPIFFE Native Support — Design Spec

**Issue:** temporalio/temporal#9152  
**Branch:** `defakto/spiffe-support`  
**Date:** 2026-04-08

## Summary

Two independent, focused additions to Temporal's existing TLS and authorization infrastructure:

1. **`x509ClaimMapper`** (`common/authorization`) — a generic X.509 claim mapper that extracts URI SANs from peer certificates into `Claims.Subject`. No SPIFFE dependency. Purely programmatic (not config-registered).
2. **`SpiffeCertProvider`** (`common/rpc/encryption`) — a `CertProvider` implementation that fetches certificates and trust bundles directly from the SPIFFE Workload API via the go-spiffe SDK. No changes to existing TLS config structs.

Both are additive and backward-compatible. All existing configurations continue to work unchanged.

## Part 1: X.509 Claim Mapper

### File
`common/authorization/x509_claim_mapper.go`

### Interface
```go
// NewX509ClaimMapper returns a ClaimMapper that extracts identity from X.509
// peer certificates. It populates Claims.Subject with the first URI SAN if
// present, falling back to the certificate's Common Name. No roles are
// populated — role mapping is left to the caller's Authorizer implementation.
func NewX509ClaimMapper() ClaimMapper
```

### Behavior
- Implements `ClaimMapper` (and `ClaimMapperWithAuthInfoRequired` returning `false` so it is called even without a TLS connection).
- `GetClaims(authInfo)`:
  1. Call `PeerCert(authInfo.TLSConnection)` to get the leaf cert.
  2. If no cert: return `&Claims{AuthType: "x509"}` — not an error.
  3. If cert has `URIs`: set `Claims.Subject` to `cert.URIs[0].String()`.
  4. Otherwise: set `Claims.Subject` to `cert.Subject.CommonName`.
  5. Return `&Claims{Subject: ..., AuthType: "x509"}`.
- No SPIFFE package imports. Works for any mTLS peer cert.

### Wiring (custom main.go)
```go
temporal.WithClaimMapper(func(cfg *config.Config) authorization.ClaimMapper {
    return authorization.NewX509ClaimMapper()
})
```

## Part 2: SPIFFE Cert Provider

### File
`common/rpc/encryption/spiffe_cert_provider.go`

### Interface
```go
// NewSpiffeCertProvider creates a CertProvider backed by the SPIFFE Workload
// API. It blocks until the initial SVID is received. socketPath is the
// Workload API endpoint address; if empty, the SPIFFE_ENDPOINT_SOCKET
// environment variable is used. The caller must call Close() when done.
func NewSpiffeCertProvider(ctx context.Context, socketPath string) (*SpiffeCertProvider, error)

func (p *SpiffeCertProvider) Close() error
```

### Type
```go
type SpiffeCertProvider struct {
    source *workloadapi.X509Source
}
```

### Interface compliance
`SpiffeCertProvider` implements `CertProvider` and `CertExpirationChecker`.

### Method behavior

| Method | Behavior |
|---|---|
| `FetchServerCertificate()` | Calls `source.GetX509SVID()`, converts to `*tls.Certificate` (cert chain + private key). |
| `FetchClientCertificate(isWorker bool)` | Same as `FetchServerCertificate()` — SPIFFE identity is the same for server and client roles. `isWorker` is ignored. |
| `FetchClientCAs()` | Gets the trust bundle from the source for the SVID's trust domain; returns as `*x509.CertPool`. Used to verify inbound mTLS clients. |
| `FetchServerRootCAsForClient(isWorker bool)` | Same as `FetchClientCAs()`. Used to verify outbound TLS connections to servers. `isWorker` is ignored. |
| `GetExpiringCerts(timeWindow)` | Checks the SVID leaf certificate's `NotAfter` against `now + timeWindow`. Returns expiring/expired maps in the existing format. |

The `X509Source` handles rotation automatically — each call reads the current in-memory SVID. No background goroutines needed in our code.

### SVID → tls.Certificate conversion
```
SVID.Certificates  → tls.Certificate.Certificate (DER-encoded cert chain)
SVID.PrivateKey    → tls.Certificate.PrivateKey
SVID.Certificates[0] → tls.Certificate.Leaf (parsed leaf, avoids re-parse overhead)
```

### Trust bundle → x509.CertPool conversion
Iterate `bundle.X509Authorities()`, add each to a new `x509.CertPool` via `AddCert`.

### Wiring (custom main.go)
```go
provider, err := encryption.NewSpiffeCertProvider(ctx, "unix:///run/spire/sockets/agent.sock")
if err != nil { ... }
defer provider.Close()

tlsProvider, err := encryption.NewTLSConfigProviderFromConfig(
    cfg.Global.TLS,
    metricsHandler,
    logger,
    func(_, _, _ any, _ time.Duration, _ log.Logger) encryption.CertProvider {
        return provider
    },
)
```

## Error handling

- If the Workload API is unavailable at startup, `NewSpiffeCertProvider` returns an error (blocks until initial fetch or context cancellation).
- If the context is cancelled before the initial fetch, the error propagates to the caller.
- `FetchServerCertificate` and related methods return errors if the source is closed or the SVID is unavailable.

## Testing

### x509ClaimMapper
- No TLS connection → empty claims, no error
- Cert with URI SAN → `Claims.Subject` = URI SAN string
- Cert with no URI SAN, has CN → `Claims.Subject` = CN
- Cert with no URI SAN, no CN → empty subject, no error

### SpiffeCertProvider
- Uses go-spiffe's `workloadapi/fakeworkloadapi` test helper to mock the Workload API
- `FetchServerCertificate` returns valid `tls.Certificate` matching test SVID
- `FetchClientCAs` returns pool containing trust domain CA
- `GetExpiringCerts` correctly identifies certs expiring within window
- `Close` causes subsequent calls to return errors

## What is NOT in scope

- Modifying `RootTLS`, `GroupTLS`, `ServerTLS`, or `Authorization` config structs
- Registering claim mapper or cert provider in config-driven factory functions
- An `Authorizer` implementation (users implement this in their own `main.go`)
- Claim mapper chains or fallback logic
- Trust domain allowlisting (belongs in a custom `Authorizer`)
