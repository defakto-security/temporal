// Package authz decides f(role_class, namespace, verb_class) for a Temporal
// API call, keyed on the role class the claim mapper derived and the verb class
// of target.APIName. The policy is wholly customer-owned Cedar, loaded from the
// mounted ConfigMap; there is no compiled-in forbid set. The authorizer fails
// closed on an absent, unparseable, or schema-invalid policy.
package authz

import "strings"

// VerbClass groups Temporal frontend APIs by the capability they represent.
// The authorizer reasons in these classes, never in individual API names, so
// the Cedar policy stays small and stable as Temporal adds RPCs.
type VerbClass string

const (
	// VerbReadOnly is Describe*/List*/Count*/GetWorkflowExecutionHistory*.
	VerbReadOnly VerbClass = "read-only"
	// VerbStartSignal is StartWorkflow/SignalWorkflow/SignalWithStart/QueryWorkflow.
	VerbStartSignal VerbClass = "start-signal"
	// VerbWorker is the poll/respond/heartbeat worker loop.
	VerbWorker VerbClass = "worker"
	// VerbBreakGlass is Terminate/RequestCancel/Reset — on-call-on-demand only.
	VerbBreakGlass VerbClass = "break-glass"
	// VerbNamespaceAdmin is RegisterNamespace/UpdateNamespace/DeprecateNamespace.
	// The shipped policy grants it to no one; admin tooling gets a permit.
	VerbNamespaceAdmin VerbClass = "namespace-admin"
	// VerbClusterAdmin is every AdminService and OperatorService method, listed
	// or not (cluster, shard, search-attribute and namespace-delete operations).
	// The shipped policy grants it to no one; admin tooling gets a permit.
	VerbClusterAdmin VerbClass = "cluster-admin"
	// VerbForbiddenAll is DeleteWorkflowExecution — no legitimate caller;
	// forbidden by default in the shipped reference policy.
	VerbForbiddenAll VerbClass = "forbidden-all"
	// VerbUnknown is any API the map does not recognize. The authorizer treats
	// it as forbidden (fail closed) so a new upstream RPC is denied until classified.
	VerbUnknown VerbClass = "unknown"
)

// shortName strips the gRPC service prefix from a full APIName.
// "/temporal.api.workflowservice.v1.WorkflowService/StartWorkflowExecution"
// becomes "StartWorkflowExecution".
func shortName(apiName string) string {
	if _, after, found := strings.CutLast(apiName, "/"); found {
		return after
	}
	return apiName
}

// isAdminService reports whether a full APIName targets a low-level OPERATOR
// surface: AdminService (replication/shard internals) or OperatorService
// (namespace delete, cluster and search-attribute administration). Both carry
// method names that collide with WorkflowService's (Describe*/Get*/List*), so
// the service must be read off the full path before the bare-name rules run —
// otherwise, e.g., OperatorService/ListClusters is misclassified as a benign
// WorkflowService read-only and handed to every human. Methods on these
// services are classified ONLY by the explicit adminVerbClass table; anything
// else stays VerbUnknown (denied, fail closed) until classified.
func isAdminService(apiName string) bool {
	return strings.Contains(apiName, ".adminservice.") ||
		strings.Contains(apiName, ".operatorservice.")
}

// exactVerbClass maps the APIs whose classification is not a prefix rule.
// Kept small and explicit; prefix rules in VerbClassOf handle the long tail.
var exactVerbClass = map[string]VerbClass{
	"StartWorkflowExecution":           VerbStartSignal,
	"SignalWorkflowExecution":          VerbStartSignal,
	"SignalWithStartWorkflowExecution": VerbStartSignal,
	"QueryWorkflow":                    VerbStartSignal,
	"UpdateWorkflowExecution":          VerbStartSignal,
	"PollWorkflowExecutionUpdate":      VerbStartSignal,
	"ExecuteMultiOperation":            VerbStartSignal,

	// Client-side result reads that happen to start with "Poll". They are the
	// read side of a submission, NOT the worker task-dispatch loop, so they
	// must be classified explicitly and NOT fall through the Poll* prefix rule
	// to VerbWorker (which the reference policy grants broadly to services).
	"PollActivityExecution":       VerbStartSignal,
	"PollNexusOperationExecution": VerbStartSignal,

	// Worker lifecycle RPCs the Go SDK (v1.44+) sends from every worker,
	// including the Temporal server's own internal worker. Without these they
	// fall to VerbUnknown, which observe mode never forgives.
	"RecordWorkerHeartbeat": VerbWorker,
	"ShutdownWorker":        VerbWorker,

	"GetClusterInfo":      VerbReadOnly,
	"GetSystemInfo":       VerbReadOnly,
	"GetSearchAttributes": VerbReadOnly,

	"TerminateWorkflowExecution":     VerbBreakGlass,
	"RequestCancelWorkflowExecution": VerbBreakGlass,
	"ResetWorkflowExecution":         VerbBreakGlass,

	"DeleteWorkflowExecution": VerbForbiddenAll,

	"RegisterNamespace":  VerbNamespaceAdmin,
	"UpdateNamespace":    VerbNamespaceAdmin,
	"DeprecateNamespace": VerbNamespaceAdmin,
	// NOTE: AdminService and OperatorService methods are resolved by service
	// before this table is consulted (see adminVerbClass), so an entry here for
	// one of them would be dead.
}

// adminVerbClass holds the deliberate exceptions on AdminService and
// OperatorService. Keyed on the bare method name, so a name shared by both
// services must mean the same thing in both. Every method NOT listed here is
// VerbClusterAdmin, so a new upstream operator or admin RPC needs no entry and
// gets the same permit as the rest.
//
// DeleteWorkflowExecution is here because cluster-admin must never reach
// destruction: it stays VerbForbiddenAll, like the WorkflowService RPC of the
// same name, and the reference policy's forbid floor denies it to everyone.
//
// NOTE: renovate.json auto-bumps the pinned Temporal api version.
// TestOperatorAndAdminSurfaceClassified walks the generated descriptors and
// checks every method against this table plus the cluster-admin fallback.
var adminVerbClass = map[string]VerbClass{
	"DeleteWorkflowExecution": VerbForbiddenAll,
}

// VerbClassOf classifies a full APIName. It is the product-owned default; a
// customer overrides behavior through policy, not by editing this table.
func VerbClassOf(apiName string) VerbClass {
	name := shortName(apiName)
	// AdminService is the low-level operator surface. Its method names overlap
	// WorkflowService's (both have a GetSearchAttributes, a Describe*/Get*
	// surface), so it MUST be resolved by SERVICE before any bare-name rule —
	// the exact-name table and the prefix rules alike. Checking exactVerbClass
	// first would let AdminService/GetSearchAttributes inherit the benign
	// WorkflowService read-only class. Only explicitly listed admin methods are
	// classified; any other admin method stays VerbUnknown (denied, fail closed)
	// until someone classifies it.
	if isAdminService(apiName) {
		if c, ok := adminVerbClass[name]; ok {
			return c
		}
		return VerbClusterAdmin
	}
	if c, ok := exactVerbClass[name]; ok {
		return c
	}
	switch {
	case strings.HasPrefix(name, "Describe"),
		strings.HasPrefix(name, "List"),
		strings.HasPrefix(name, "Count"),
		strings.HasPrefix(name, "Get") && strings.Contains(name, "History"):
		return VerbReadOnly
	case strings.HasPrefix(name, "Poll"),
		strings.HasPrefix(name, "Respond"),
		strings.HasPrefix(name, "RecordActivityTaskHeartbeat"):
		return VerbWorker
	default:
		return VerbUnknown
	}
}
