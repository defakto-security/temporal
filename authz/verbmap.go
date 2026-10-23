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
	// VerbForbiddenAll is Delete/RemoveTask/shard-admin — no legitimate caller;
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
	if i := strings.LastIndex(apiName, "/"); i >= 0 {
		return apiName[i+1:]
	}
	return apiName
}

// exactVerbClass maps the APIs whose classification is not a prefix rule.
// Kept small and explicit; prefix rules in VerbClassOf handle the long tail.
var exactVerbClass = map[string]VerbClass{
	"StartWorkflowExecution":           VerbStartSignal,
	"SignalWorkflowExecution":          VerbStartSignal,
	"SignalWithStartWorkflowExecution": VerbStartSignal,
	"QueryWorkflow":                    VerbStartSignal,

	"TerminateWorkflowExecution":     VerbBreakGlass,
	"RequestCancelWorkflowExecution": VerbBreakGlass,
	"ResetWorkflowExecution":         VerbBreakGlass,

	"DeleteWorkflowExecution": VerbForbiddenAll,
	"RemoveTask":              VerbForbiddenAll,
	"DescribeHistoryHost":     VerbForbiddenAll,
}

// VerbClassOf classifies a full APIName. It is the product-owned default; a
// customer overrides behavior through policy, not by editing this table.
func VerbClassOf(apiName string) VerbClass {
	name := shortName(apiName)
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
