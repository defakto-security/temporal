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
decision = f(identity, namespace, action)
```

- **role_class** ∈ {`service`, `human`} — derived structurally from the SPIFFE
  identity by the claim mapper. Authentication only; no verb grants.
- **action** — one RPC, named `<Service>/<Method>`, such as
  `Action::"WorkflowService/QueryWorkflow"`. The image ships groups of RPCs
  (`authz/verbmap.go`), and a permit can name a group, a list, or one RPC.
  Customers add groups with `actionGroups` in config.

| Shipped leaf group | Holds |
|---|---|
| `workflow-read` | Describe, List, Count, Scan, history |
| `workflow-query` | `QueryWorkflow` (runs workflow code) |
| `workflow-start` | Start, SignalWithStart, ExecuteMultiOperation |
| `workflow-signal` | Signal, Update, PollWorkflowExecutionUpdate |
| `workflow-admin` | Terminate, RequestCancel, Reset, Pause, Unpause, UpdateOptions, batch ops |
| `workflow-delete` | `DeleteWorkflowExecution` (both services) |
| `metadata-read` | System, cluster and search attribute info, namespaces, task queues, workers, batch and rule reads, and the OperatorService reads (`ListSearchAttributes`, `ListClusters`, `ListNexusEndpoints`, `GetNexusEndpoint`) |
| `schedule-read` · `schedule-write` · `schedule-delete` | Schedule RPCs |
| `activity-read` · `activity-write` · `activity-admin` · `activity-delete` | Standalone activity and Nexus operation RPCs |
| `worker-ops` | Poll, Respond, heartbeat, ShutdownWorker, sticky reset, worker config update |
| `deployment-read` · `deployment-admin` | Worker deployment, versioning and task queue config |
| `namespace-admin` | Register, Update, Deprecate namespace, workflow rules |
| `cluster-admin` | Every AdminService method and every OperatorService method except the four reads above and the workflow delete |

| Shipped aggregate | Holds |
|---|---|
| `workflow-interact` | `workflow-query`, `workflow-signal` |
| `workflow-client` | `workflow-read`, `metadata-read`, `workflow-start`, `workflow-interact` |
| `schedule-manage` | `schedule-read`, `schedule-write` |
| `activity-manage` | `activity-read`, `activity-write` |
| `read-all` | Every read group. It does not hold `workflow-query`. |
| `delete-all` | Every group that deletes data or its audit trail: workflow, schedule and activity deletes. The shipped policy forbids it. Cluster management deletes (worker deployments and versions, workflow rules, namespaces) are in the admin groups, which are granted by name. |

  No aggregate holds an admin leaf group. The only aggregate that holds delete
  leaf groups is `delete-all`, which the shipped policy forbids. An RPC the image does not
  know is in no group, so only a permit that names it, or a customer group
  that holds it, allows it. A new Temporal RPC therefore needs no new image:
  add `permit (..., action == Action::"WorkflowService/NewRpc", ...)`.
  A test fails when an API upgrade adds an RPC the table does not list.
- **actionGroups** — your own bundles. A member is an RPC such as
  `WorkflowService/QueryWorkflow`, or a shipped or customer group. A group
  cannot reuse a shipped name, name a group that does not exist, or form a
  cycle, and it cannot change what a shipped group holds. So a `forbid` on a
  shipped group keeps covering the same RPCs.

  ```yaml
  actionGroups:
    payments-ops: [workflow-read, WorkflowService/QueryWorkflow]
  ```

  ```cedar
  permit (principal == Workload::"spiffe://corp.example/ns/payments/sa/x",
          action in Action::"payments-ops", resource == Namespace::"payments")
    when { principal.trust_domain == "corp.example" };
  ```
- **policy** — wholly customer-owned Cedar, loaded from the mounted ConfigMap.
  No compiled-in forbid set. The authorizer **fails closed** on an absent,
  unparseable, or invalid policy. The shipped `reference/policy.cedar` forbids
  the destruction verbs by default.

## Trust boundaries to know

- Any trust domain the SPIFFE agent holds a bundle for (federated ones too) can
  authenticate. Every `permit` must scope `principal.trust_domain` (or name one
  exact Workload); the policy loader rejects one that does not.
  `trust_domain` is read from the SPIFFE ID and cannot be overridden.
- A JWT-SVID is a bearer token. Serve the frontend over TLS and give each
  cluster its own `workloadAPI.audience`. A token with more than one audience
  is refused.
- `identityMode: observe` lets callers without a valid identity through (the
  admin and delete groups, and RPCs with no shipped group, stay denied). It is a rollout aid.
- **Upgrade note: actions are RPCs.** The old classes (`read-only`,
  `start-signal`, `worker`, `break-glass`, `forbidden-all`) are gone. Rewrite
  `action` lists with the groups above: `start-signal` becomes
  `workflow-start` and `workflow-interact`, `worker` becomes `worker-ops`,
  `read-only` becomes `read-all`, `break-glass` becomes `workflow-admin`, and
  `forbidden-all` becomes `delete-all`. A permit that names no `action` (or
  uses an `action` wildcard) grants every RPC that has a shipped group, including
  the admin groups. It never grants an RPC with no group: only a permit that
  names that RPC, or a customer group holding it, does. The `delete-all` floor
  stops only data deletion. It does not stop deployment, version, rule or
  namespace deletes, which sit in the admin groups. Give every permit an
  `action in [...]` list. Or add a forbid that excepts the admin tooling
  workload, because a forbid beats every permit, including the admin one:
  `forbid (principal, action in [Action::"namespace-admin", Action::"deployment-admin", Action::"activity-admin", Action::"cluster-admin"], resource) unless { principal == Workload::"<admin tooling SPIFFE ID>" };`
  then permit that workload by exact ID. The shipped policy grants none of these
  groups. `DeleteWorkflowExecution` on both services is in `workflow-delete`,
  so it stays forbidden.
- Temporal's own services (worker, scheduler) carry no JWT-SVID. Set
  `clientCertAuth: true` to identify them by their X.509-SVID client cert
  (URI SAN = SPIFFE ID). Any `authorization` header, even blank, wins and is
  never rescued by a cert. Two checks must both pass, else the caller is unknown:
  1. Temporal's TLS verifies the chain (`requireClientAuth` + `clientCaFiles`).
  2. The mapper verifies the cert again against the Workload API X.509 roots
     of the trust domain in its own SAN. A merged CA file cannot bind a SAN
     to its domain, so without this step any root in it could mint an ID in
     any trust domain. It also checks: not a CA, one canonical URI SAN, in
     date, digitalSignature. No OCSP/CRL: rely on short-lived SVIDs.

```yaml
# Temporal server config (not config.yaml)
global:
  tls:
    refreshInterval: 1m              # reload cert and CA files as they rotate
    frontend:
      server:
        certFile: /spiffe/svid.pem
        keyFile: /spiffe/svid.key
        requireClientAuth: true
        clientCaFiles: [/spiffe/bundle.pem]   # the Defakto X.509 bundle
    systemWorker:                    # the worker and scheduler present this
      certFile: /spiffe/svid.pem
      keyFile: /spiffe/svid.key
      client:
        rootCaFiles: [/spiffe/bundle.pem]
```

  `requireClientAuth: true` refuses any client without a cert during the TLS
  handshake, before a header is read. JWT-only callers (people, CLI) then
  cannot connect to that listener. Keep them on a listener without
  `requireClientAuth`, and give the worker and scheduler the mTLS one
  (`internal-frontend`). A caller that reaches a listener with no
  `requireClientAuth` has no verified chain, so its cert is ignored. Keep the
  bundle file fresh (for example with spiffe-helper); a stale file rejects good
  callers. Check both listeners in observe mode before you enforce.

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
