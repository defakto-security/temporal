// Reference Cedar policy for defakto-spiffe-temporal.
//
// This is the SHIPPED DEFAULT a customer copies into their ConfigMap and edits.
// It is the entire policy — there is no compiled-in forbid set. The destruction
// verbs are forbidden here by default; a customer owns the decision to change that.
//
// Model: decision = f(identity, namespace, action)
//   Principal = Workload::"<spiffe id>", always a member of its role class:
//               `principal in RoleClass::"service"` | `principal in RoleClass::"human"`
//               Attributes: principal.trust_domain, principal.ns, principal.sa by default
//               (ns and sa are "" when the ID is not /ns/<ns>/sa/<sa>).
//               Add or override attributes with `attributes:` in config.yaml.
//               trust_domain is the ID's own trust domain; config cannot change it.
//               Any trust domain the SPIFFE agent holds a bundle for (including
//               federated ones) can authenticate, so EVERY PERMIT MUST SCOPE
//               principal.trust_domain, as below (or name one exact Workload).
//               A permit that does not is rejected at load. IDs not in
//               canonical form are denied.
//               A policy that still scopes the
//               principal with `== RoleClass::"x"` is rejected at load.
//               Write denies as allow-lists: `forbid ... when { principal.ns ==
//               "prod" }` does not fire when ns is "" (an ID of another shape).
//   Action    = one RPC, named "<Service>/<Method>", for example
//               Action::"WorkflowService/QueryWorkflow". The image ships groups of
//               RPCs, so a permit can say `action in Action::"workflow-interact"`.
//               Leaf groups: workflow-read, workflow-query, workflow-start,
//               workflow-signal, workflow-admin, workflow-delete, metadata-read,
//               schedule-read, schedule-write, schedule-delete, activity-read,
//               activity-write, activity-admin, activity-delete, worker-ops,
//               deployment-read, deployment-admin, namespace-admin, cluster-admin.
//               Aggregates: workflow-interact (query, signal), workflow-client
//               (read, start, query, signal), schedule-manage, activity-manage,
//               read-all, delete-all. No aggregate holds an admin leaf. Only delete-all holds delete leaves.
//               Add your own groups with `actionGroups:` in config.yaml, or name
//               one RPC. An RPC the image does not know is in no group: only a
//               permit that names it (or a customer group that holds it) allows it.
//   Resource  = Namespace::"<name>"

// --- service ---------------------------------------------------------------
// Workloads get start, query, signal and the worker loop in any namespace.
permit (
  principal in RoleClass::"service",
  action in [Action::"workflow-start", Action::"workflow-interact", Action::"worker-ops"],
  resource
) when { principal.trust_domain == "corp.defakto.security" };

// --- Temporal's own services (clientCertAuth) ------------------------------
// The internal worker and scheduler dial the frontend with an X.509-SVID client
// cert and no header. Needed when you narrow the broad service permit above.
permit (
  principal in RoleClass::"service",
  action in [Action::"workflow-client", Action::"schedule-manage", Action::"worker-ops"],
  resource
) when {
  principal.trust_domain == "corp.defakto.security" &&
  principal.ns == "temporal" && principal.sa == "temporal-worker"
};

// --- per-workload scoping (example) ---------------------------------------
// To confine a workload to its own namespace, replace the broad service permit
// above with permits like this one, one per workload family:
//
// permit (
//   principal in RoleClass::"service",
//   action in [Action::"workflow-start", Action::"workflow-interact", Action::"worker-ops"],
//   resource == Namespace::"payments"
// ) when { principal.trust_domain == "corp.defakto.security" && principal.ns == "payments" };
//
// Or name one exact identity (the ID includes its trust domain):
//   principal == Workload::"spiffe://corp.example/ns/payments/sa/worker"

// Mix groups and single RPCs when a bundle does not fit. This one reads and
// queries everywhere, but signals only in "payments":
//
// permit (principal == Workload::"spiffe://corp.example/ns/ops/sa/tool",
//   action in [Action::"workflow-read", Action::"workflow-query"], resource);
// permit (principal == Workload::"spiffe://corp.example/ns/ops/sa/tool",
//   action in Action::"workflow-signal", resource == Namespace::"payments");

// --- human -----------------------------------------------------------------
// Humans get read-all everywhere (secret-exfil safety is a CI check, not an
// authorization boundary — see the project design). read-all does not include
// workflow-query, which runs workflow code.
permit (
  principal in RoleClass::"human",
  action in Action::"read-all",
  resource
) when { principal.trust_domain == "corp.defakto.security" };

// workflow-admin (Terminate / RequestCancel / Reset / Pause / batch) for humans.
//
// SHIPPED DISABLED ON PURPOSE. The on-call-grant gate (FRY-1374) is not built
// yet: the authorizer does not check on-call status before consulting Cedar,
// so an active permit here grants destructive break-glass to EVERY human in
// EVERY namespace with no incident binding, expiry, or approval. The reference
// default must not do that. Uncomment this permit only once an on-call gate
// (or an equivalent scoping condition) is in place.
//
// permit (
//   principal in RoleClass::"human",
//   action in Action::"workflow-admin",
//   resource
// );

// namespace-admin (Register / Update / Deprecate namespace, workflow rules),
// deployment-admin, activity-admin and cluster-admin (every AdminService and
// OperatorService method) are granted to no one by default. Give them to the admin tooling workload only, by exact ID.
//
// permit (
//   principal == Workload::"spiffe://corp.defakto.security/ns/temporal/sa/temporal-admintools",
//   action in [Action::"namespace-admin", Action::"cluster-admin"],
//   resource
// );

// --- floor (customer-editable) ---------------------------------------------
// Data and audit-trail deletion (workflow, schedule and activity deletes) is
// forbidden to everyone by default. Cluster management deletes (deployments,
// rules, namespaces) are in the admin groups, not here, so internal management
// still works where an admin group is granted.
// deny-overrides means this wins over any permit above.
forbid (
  principal,
  action in Action::"delete-all",
  resource
);
