# temporal

SPIFFE-authenticated, Cedar-authorized **custom build of the Temporal server**,
published as the `defakto-spiffe-temporal` container image.

Temporal is a **dependency, never a fork**: this repo imports
`go.temporal.io/server` and wires two plugins into its `authorization.ClaimMapper`
/ `authorization.Authorizer` hooks. A customer runs it on the **stock Temporal
Helm chart** by (1) swapping the `image:`, and (2) mounting a ConfigMap carrying
their trust-domain/issuer config and their Cedar policy. No chart fork.

See the design of record: [Defakto SPIFFE Temporal](https://linear.app/defakto/project/defakto-spiffe-temporal-cdd68326fc1f).

## Authorization model

```
decision = f(role_class, namespace, verb_class)
```

- **role_class** ∈ {`service`, `human`} — derived structurally from the SPIFFE
  identity by the claim mapper. Authentication only; no verb grants.
- **verb_class** — `read-only` · `start-signal` · `worker` · `break-glass` ·
  `forbidden-all`, mapped from `target.APIName` (`authz/verbmap.go`).
- **policy** — wholly customer-owned Cedar, loaded from the mounted ConfigMap.
  No compiled-in forbid set. The authorizer **fails closed** on an absent,
  unparseable, or invalid policy. The shipped `reference/policy.cedar` forbids
  the destruction verbs by default.

## Layout

```
cmd/server/main.go     custom Temporal server: registers ClaimMapper + Authorizer
authn/                 SPIFFE SVID / portal-OIDC -> Claims + role_class (no grants)
authz/                 Cedar authorizer, verb map, fail-closed policy source
config/                versioned config contract (trust domain, issuer, policy path)
reference/             shipped policy.cedar + example ConfigMap + stock-chart values
schema/                Cedar entity/action schema (CI/doc artifact)
```

## Develop

Toolchain is pinned in `mise.toml` ([mise](https://mise.jdx.dev)).

```sh
mise install        # Go, golangci-lint, goimports at pinned versions
mise run check      # vet + lint + test — the full PR gate
mise run fmt        # gofmt + goimports
```

CI (`.github/workflows/ci.yaml`) runs `vet`, `test`, and golangci-lint on
changed code. Merging to `main` builds and publishes the image
(`.github/workflows/publish.yaml`).
