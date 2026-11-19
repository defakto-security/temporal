// Package authz decides whether a caller may run a Temporal API call in a
// namespace. The policy is wholly customer-owned Cedar, loaded from the mounted
// ConfigMap; there is no compiled-in forbid set. The authorizer fails closed on
// an absent, unparseable, or schema-invalid policy.
//
// Every RPC is a Cedar action, named "<Service>/<Method>", for example
// Action::"WorkflowService/QueryWorkflow". The image ships groups of RPCs, also
// Cedar actions, so a policy can say `action in Action::"workflow-interact"`.
// Customers add their own groups with config actionGroups and can always name
// single RPCs, so a new Temporal RPC never needs a new image to be permitted.
package authz

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/cedar-policy/cedar-go/types"
)

// Shipped leaf groups. Each RPC the image knows is a member of exactly one.
const (
	GroupWorkflowRead   = "workflow-read"
	GroupWorkflowQuery  = "workflow-query"
	GroupWorkflowStart  = "workflow-start"
	GroupWorkflowSignal = "workflow-signal"
	GroupWorkflowAdmin  = "workflow-admin"
	GroupWorkflowDelete = "workflow-delete"
	GroupMetadataRead   = "metadata-read"
	GroupScheduleRead   = "schedule-read"
	GroupScheduleWrite  = "schedule-write"
	GroupScheduleDelete = "schedule-delete"
	GroupActivityRead   = "activity-read"
	GroupActivityWrite  = "activity-write"
	GroupActivityAdmin  = "activity-admin"
	GroupActivityDelete = "activity-delete"
	GroupWorkerOps      = "worker-ops"
	GroupDeploymentRead = "deployment-read"
	GroupDeploymentAdm  = "deployment-admin"
	GroupNamespaceAdmin = "namespace-admin"
	GroupClusterAdmin   = "cluster-admin"
)

// The full gRPC service names the group table is written for. LeafGroup matches
// them exactly, so a service of another package or version with the same short
// name gets no group.
const (
	workflowServiceFull = "temporal.api.workflowservice.v1.WorkflowService"
	operatorServiceFull = "temporal.api.operatorservice.v1.OperatorService"
	adminServiceFull    = "temporal.server.api.adminservice.v1.AdminService"
)

// leafMembers lists the WorkflowService methods in each leaf group. It is
// explicit on purpose: a method not listed has no group, so only a permit that
// names it can allow it. TestWorkflowServiceClassified walks the generated
// descriptors and fails when a Temporal upgrade adds a method that is not here.
var leafMembers = map[string][]string{
	GroupWorkflowRead: {
		"DescribeWorkflowExecution", "ListWorkflowExecutions", "ListOpenWorkflowExecutions",
		"ListClosedWorkflowExecutions", "ListArchivedWorkflowExecutions", "ScanWorkflowExecutions",
		"CountWorkflowExecutions", "GetWorkflowExecutionHistory", "GetWorkflowExecutionHistoryReverse",
		// A long poll of the workflow's time-skipping state. It reads and is not a worker poll.
		"PollWorkflowExecutionTimeSkipping",
	},
	// Query runs the workflow's own code on a worker and returns what it returns.
	GroupWorkflowQuery: {"QueryWorkflow"},
	GroupWorkflowStart: {
		"StartWorkflowExecution", "SignalWithStartWorkflowExecution", "ExecuteMultiOperation",
	},
	// PollWorkflowExecutionUpdate is the result read of UpdateWorkflowExecution.
	// It is not a worker poll, so it must not be worker-ops.
	GroupWorkflowSignal: {
		"SignalWorkflowExecution", "UpdateWorkflowExecution", "PollWorkflowExecutionUpdate",
	},
	// Stop, kill, reset, pause and batch operations: on-call-on-demand only.
	GroupWorkflowAdmin: {
		"TerminateWorkflowExecution", "RequestCancelWorkflowExecution", "ResetWorkflowExecution",
		"PauseWorkflowExecution", "UnpauseWorkflowExecution", "UpdateWorkflowExecutionOptions",
		"StartBatchOperation", "StopBatchOperation",
	},
	GroupWorkflowDelete: {"DeleteWorkflowExecution"},
	GroupMetadataRead: {
		"GetSystemInfo", "GetClusterInfo", "GetSearchAttributes", "DescribeNamespace", "ListNamespaces",
		"DescribeTaskQueue", "ListTaskQueuePartitions", "DescribeBatchOperation", "ListBatchOperations",
		"DescribeWorkflowRule", "ListWorkflowRules", "DescribeWorker", "ListWorkers", "CountWorkers",
		"FetchWorkerConfig",
	},
	GroupScheduleRead: {
		"DescribeSchedule", "ListSchedules", "ListScheduleMatchingTimes", "CountSchedules",
	},
	GroupScheduleWrite:  {"CreateSchedule", "UpdateSchedule", "PatchSchedule"},
	GroupScheduleDelete: {"DeleteSchedule"},
	// Standalone activity and Nexus operation executions.
	GroupActivityRead: {
		"DescribeActivityExecution", "ListActivityExecutions", "CountActivityExecutions", "PollActivityExecution",
		"DescribeNexusOperationExecution", "ListNexusOperationExecutions", "CountNexusOperationExecutions",
		"PollNexusOperationExecution",
	},
	GroupActivityWrite: {
		"StartActivityExecution", "StartNexusOperationExecution", "PauseActivity", "PauseActivityExecution",
		"UnpauseActivity", "UnpauseActivityExecution", "ResetActivity", "ResetActivityExecution",
		"UpdateActivityOptions", "UpdateActivityExecutionOptions",
	},
	GroupActivityAdmin: {
		"TerminateActivityExecution", "TerminateNexusOperationExecution",
		"RequestCancelActivityExecution", "RequestCancelNexusOperationExecution",
	},
	GroupActivityDelete: {"DeleteActivityExecution", "DeleteNexusOperationExecution"},
	GroupWorkerOps: {
		"PollActivityTaskQueue", "PollWorkflowTaskQueue", "PollNexusTaskQueue",
		"RespondActivityTaskCompleted", "RespondActivityTaskCompletedById",
		"RespondActivityTaskFailed", "RespondActivityTaskFailedById",
		"RespondActivityTaskCanceled", "RespondActivityTaskCanceledById",
		"RespondWorkflowTaskCompleted", "RespondWorkflowTaskFailed", "RespondQueryTaskCompleted",
		"RespondNexusTaskCompleted", "RespondNexusTaskFailed",
		"RecordActivityTaskHeartbeat", "RecordActivityTaskHeartbeatById",
		// The Go SDK (v1.44+) sends these from every worker, including Temporal's own.
		"RecordWorkerHeartbeat", "ShutdownWorker", "ResetStickyTaskQueue", "UpdateWorkerConfig",
	},
	GroupDeploymentRead: {
		"DescribeDeployment", "DescribeWorkerDeployment", "DescribeWorkerDeploymentVersion",
		"ListDeployments", "ListWorkerDeployments", "GetCurrentDeployment", "GetDeploymentReachability",
		"GetWorkerBuildIdCompatibility", "GetWorkerTaskReachability", "GetWorkerVersioningRules",
	},
	// Routing, versioning and task queue config: it changes where work runs.
	GroupDeploymentAdm: {
		"CreateWorkerDeployment", "CreateWorkerDeploymentVersion", "DeleteWorkerDeployment",
		"DeleteWorkerDeploymentVersion", "SetCurrentDeployment", "SetWorkerDeploymentCurrentVersion",
		"SetWorkerDeploymentManager", "SetWorkerDeploymentRampingVersion", "UpdateTaskQueueConfig",
		"UpdateWorkerBuildIdCompatibility", "UpdateWorkerVersioningRules",
		"UpdateWorkerDeploymentVersionComputeConfig", "UpdateWorkerDeploymentVersionMetadata",
		"ValidateWorkerDeploymentVersionComputeConfig",
	},
	GroupNamespaceAdmin: {
		"RegisterNamespace", "UpdateNamespace", "DeprecateNamespace",
		"CreateWorkflowRule", "DeleteWorkflowRule", "TriggerWorkflowRule",
	},
}

// shippedAggregates are groups of groups. A policy can name an aggregate to
// grant a usual bundle in one line. None includes an admin or delete group, so
// no aggregate grants destruction.
var shippedAggregates = map[string][]string{
	// Run and use workflows: query and signal.
	"workflow-interact": {GroupWorkflowQuery, GroupWorkflowSignal},
	// A usual workflow client: read, start, query and signal.
	"workflow-client": {GroupWorkflowRead, GroupMetadataRead, GroupWorkflowStart, "workflow-interact"},
	"schedule-manage": {GroupScheduleRead, GroupScheduleWrite},
	"activity-manage": {GroupActivityRead, GroupActivityWrite},
	// Everything that only reads, and does not run workflow code (no query).
	"read-all": {
		GroupWorkflowRead, GroupMetadataRead, GroupScheduleRead, GroupActivityRead, GroupDeploymentRead,
	},
	// Everything that destroys data. The shipped policy forbids it for everyone.
	"delete-all": {GroupWorkflowDelete, GroupScheduleDelete, GroupActivityDelete},
}

// adminServiceLeaf holds the deliberate exceptions on AdminService and
// OperatorService. Every other method on those services is cluster-admin, so a
// new upstream operator or admin RPC needs no entry and joins the cluster-admin
// floor at once. Keyed on the bare method name.
//
// DeleteWorkflowExecution stays in workflow-delete so that cluster-admin never
// reaches destruction.
var adminServiceLeaf = map[string]string{
	"DeleteWorkflowExecution": GroupWorkflowDelete,
}

// neverForgiven are the leaf groups observe mode never forgives: a caller must
// not gain these by dropping its credential. An RPC with no shipped group is
// never forgiven either.
var neverForgiven = map[string]bool{
	GroupWorkflowAdmin: true, GroupWorkflowDelete: true, GroupScheduleDelete: true,
	GroupActivityAdmin: true, GroupActivityDelete: true, GroupDeploymentAdm: true,
	GroupNamespaceAdmin: true, GroupClusterAdmin: true,
}

// leafOf is the method to leaf group index for WorkflowService.
var leafOf = func() map[string]string {
	m := make(map[string]string)
	for leaf, methods := range leafMembers {
		for _, method := range methods {
			if prev, dup := m[method]; dup {
				panic(fmt.Sprintf("authz: %s is in both %s and %s", method, prev, leaf))
			}
			m[method] = leaf
		}
	}
	return m
}()

// shippedGroupParents maps each shipped group to the aggregates that hold it.
var shippedGroupParents = func() map[string][]string {
	m := make(map[string][]string)
	for agg, members := range shippedAggregates {
		for _, member := range members {
			m[member] = append(m[member], agg)
		}
	}
	for _, ps := range m {
		sort.Strings(ps)
	}
	return m
}()

// shippedGroupNames is every shipped group, leaf and aggregate.
func shippedGroupNames() []string {
	var out []string
	for g := range leafMembers {
		out = append(out, g)
	}
	for g := range shippedAggregates {
		out = append(out, g)
	}
	if _, ok := leafMembers[GroupClusterAdmin]; !ok {
		out = append(out, GroupClusterAdmin)
	}
	sort.Strings(out)
	return out
}

func isShippedGroup(name string) bool {
	_, leaf := leafMembers[name]
	_, agg := shippedAggregates[name]
	// cluster-admin has no member table: it is every Admin and Operator RPC.
	return leaf || agg || name == GroupClusterAdmin
}

// ActionName turns a full gRPC API name into its Cedar action name.
// "/temporal.api.workflowservice.v1.WorkflowService/QueryWorkflow" becomes
// "WorkflowService/QueryWorkflow".
func ActionName(apiName string) string {
	svc, method, ok := strings.Cut(strings.TrimPrefix(apiName, "/"), "/")
	if !ok {
		return apiName
	}
	if i := strings.LastIndex(svc, "."); i >= 0 {
		svc = svc[i+1:]
	}
	return svc + "/" + method
}

// LeafGroup returns the shipped leaf group of a full API name, or "" when the
// image does not know the RPC. An RPC with no group can still be permitted by
// naming it, or through a customer group. The full service name must match, so
// another package's "WorkflowService" gets no group.
func LeafGroup(apiName string) string {
	svc, method, ok := strings.Cut(strings.TrimPrefix(apiName, "/"), "/")
	if !ok {
		return ""
	}
	switch svc {
	case operatorServiceFull, adminServiceFull:
		// Every other method on these services is cluster-admin.
		if g, ok := adminServiceLeaf[method]; ok {
			return g
		}
		return GroupClusterAdmin
	case workflowServiceFull:
		return leafOf[method]
	}
	return ""
}

// actionGroups is the group hierarchy: the shipped groups plus the customer's.
// It is read-only after construction.
type actionGroups struct {
	// parents maps a group, or a customer-grouped RPC action, to its direct
	// parent groups. The shipped leaf of an RPC is added per request.
	parents map[string][]string
	// custom is the set of customer group names.
	custom map[string]bool
}

// knownGroup reports whether name is a shipped group or a customer group.
func (g *actionGroups) knownGroup(name string) bool {
	return isShippedGroup(name) || g.custom[name]
}

// newActionGroups builds the hierarchy. A customer group may not reuse a shipped
// name, may only name groups that exist, and may not form a cycle. A customer
// group never changes what a shipped group holds, so a forbid on a shipped group
// keeps covering the same RPCs.
func newActionGroups(custom map[string][]string) (*actionGroups, error) {
	g := &actionGroups{parents: make(map[string][]string), custom: make(map[string]bool)}
	for child, ps := range shippedGroupParents {
		g.parents[child] = slices.Clone(ps)
	}
	var errs []error
	for name := range custom {
		g.custom[name] = true
		if isShippedGroup(name) {
			errs = append(errs, fmt.Errorf("actionGroups: %q is a shipped group and cannot be redefined", name))
		}
	}
	for name, members := range custom {
		for _, m := range members {
			isRPC := strings.Contains(m, "/")
			if _, ok := custom[m]; !isRPC && !isShippedGroup(m) && !ok {
				errs = append(errs, fmt.Errorf("actionGroups[%s]: unknown group %q", name, m))
				continue
			}
			g.parents[m] = append(g.parents[m], name)
		}
	}
	if len(errs) == 0 {
		if err := g.checkCycles(); err != nil {
			errs = append(errs, err)
		}
	}
	return g, errors.Join(errs...)
}

// checkCycles refuses a group that is, through its members, its own ancestor.
func (g *actionGroups) checkCycles() error {
	const (
		visiting = 1
		done     = 2
	)
	state := make(map[string]int)
	var visit func(n string) error
	visit = func(n string) error {
		switch state[n] {
		case visiting:
			return fmt.Errorf("actionGroups: %q is its own ancestor", n)
		case done:
			return nil
		}
		state[n] = visiting
		for _, p := range g.parents[n] {
			if err := visit(p); err != nil {
				return err
			}
		}
		state[n] = done
		return nil
	}
	names := make([]string, 0, len(g.parents))
	for n := range g.parents {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if err := visit(n); err != nil {
			return err
		}
	}
	return nil
}

// addActionEntities adds the action for apiName, and every group above it, to
// the entity map so `action in Action::"<group>"` resolves.
func (g *actionGroups) addActionEntities(entities types.EntityMap, apiName string) types.EntityUID {
	name := ActionName(apiName)
	direct := slices.Clone(g.parents[name])
	if leaf := LeafGroup(apiName); leaf != "" {
		direct = append(direct, leaf)
	}
	uid := types.NewEntityUID(actionAccess, types.String(name))
	entities[uid] = types.Entity{UID: uid, Parents: parentSet(direct)}

	queue := slices.Clone(direct)
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		guid := types.NewEntityUID(actionAccess, types.String(n))
		if _, seen := entities[guid]; seen {
			continue
		}
		entities[guid] = types.Entity{UID: guid, Parents: parentSet(g.parents[n])}
		queue = append(queue, g.parents[n]...)
	}
	return uid
}

func parentSet(names []string) types.EntityUIDSet {
	uids := make([]types.EntityUID, len(names))
	for i, n := range names {
		uids[i] = types.NewEntityUID(actionAccess, types.String(n))
	}
	return types.NewEntityUIDSet(uids...)
}
