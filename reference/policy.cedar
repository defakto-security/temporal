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

// break-glass (Terminate / RequestCancel / Reset) is granted to humans here,
// but the on-call-grant gate is enforced in the authorizer before Cedar is
// consulted (FRY-1374). Keeping the permit here documents the human capability.
permit (
  principal == RoleClass::"human",
  action == Action::"break-glass",
  resource
);

// --- floor (customer-editable) ---------------------------------------------
// Destruction / shard-admin verbs: forbidden to everyone by default.
// deny-overrides means this wins over any permit above.
forbid (
  principal,
  action == Action::"forbidden-all",
  resource
);
