// Reference Cedar policy for defakto-spiffe-temporal.
//
// This is the SHIPPED DEFAULT a customer copies into their ConfigMap and edits.
// It is the entire policy — there is no compiled-in forbid set. The destruction
// verbs are forbidden here by default; a customer owns the decision to change that.
//
// Model: decision = f(role_class, namespace, verb_class)
//   Principal = RoleClass::"service" | RoleClass::"human"
//   Action    = Action::"read-only" | "start-signal" | "worker" | "break-glass" | "forbidden-all"
//   Resource  = Namespace::"<name>"

// --- service ---------------------------------------------------------------
// Workloads get start/signal and the worker loop in any namespace.
permit (
  principal == RoleClass::"service",
  action in [Action::"start-signal", Action::"worker"],
  resource
);

// --- human -----------------------------------------------------------------
// Humans get read-all everywhere (secret-exfil safety is a CI check, not an
// authorization boundary — see the project design).
permit (
  principal == RoleClass::"human",
  action == Action::"read-only",
  resource
);

// break-glass (Terminate / RequestCancel / Reset) for humans.
//
// SHIPPED DISABLED ON PURPOSE. The on-call-grant gate (FRY-1374) is not built
// yet: the authorizer does not check on-call status before consulting Cedar,
// so an active permit here grants destructive break-glass to EVERY human in
// EVERY namespace with no incident binding, expiry, or approval. The reference
// default must not do that. Uncomment this permit only once an on-call gate
// (or an equivalent scoping condition) is in place.
//
// permit (
//   principal == RoleClass::"human",
//   action == Action::"break-glass",
//   resource
// );

// --- floor (customer-editable) ---------------------------------------------
// Destruction / shard-admin verbs: forbidden to everyone by default.
// deny-overrides means this wins over any permit above.
forbid (
  principal,
  action == Action::"forbidden-all",
  resource
);
