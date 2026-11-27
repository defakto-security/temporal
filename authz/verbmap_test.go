package authz

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	operatorservice "go.temporal.io/api/operatorservice/v1"
	workflowservice "go.temporal.io/api/workflowservice/v1"
	adminservice "go.temporal.io/server/api/adminservice/v1"
	"google.golang.org/grpc"
)

// shippedGroupNames is every shipped group, leaf and aggregate.
func shippedGroupNames() []string {
	var out []string
	for g := range leafGroups {
		out = append(out, g)
	}
	for g := range shippedAggregates {
		out = append(out, g)
	}
	sort.Strings(out)
	return out
}

func TestActionName(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "WorkflowService/QueryWorkflow", ActionName(svc+"QueryWorkflow"))
	assert.Equal(t, "AdminService/RemoveTask", ActionName(adminSvc+"RemoveTask"))
	assert.Equal(t, "OperatorService/DeleteNamespace",
		ActionName("/temporal.api.operatorservice.v1.OperatorService/DeleteNamespace"))
}

func TestLeafGroup(t *testing.T) {
	t.Parallel()

	const opsvc = "/temporal.api.operatorservice.v1.OperatorService/"
	cases := []struct {
		api  string
		want string
	}{
		{svc + "StartWorkflowExecution", GroupWorkflowStart},
		{svc + "SignalWithStartWorkflowExecution", GroupWorkflowStart},
		{svc + "SignalWorkflowExecution", GroupWorkflowSignal},
		{svc + "UpdateWorkflowExecution", GroupWorkflowSignal},
		// The read side of an update. It must not fall to worker-ops.
		{svc + "PollWorkflowExecutionUpdate", GroupWorkflowSignal},
		{svc + "QueryWorkflow", GroupWorkflowQuery},
		{svc + "PollActivityExecution", GroupActivityRead},
		{svc + "PollNexusOperationExecution", GroupActivityRead},

		{svc + "GetSystemInfo", GroupMetadataRead},
		{svc + "GetClusterInfo", GroupMetadataRead},
		{svc + "DescribeNamespace", GroupMetadataRead},
		{svc + "ListWorkflowExecutions", GroupWorkflowRead},
		{svc + "GetWorkflowExecutionHistory", GroupWorkflowRead},

		{svc + "PollActivityTaskQueue", GroupWorkerOps},
		{svc + "RespondActivityTaskCompleted", GroupWorkerOps},
		{svc + "RecordWorkerHeartbeat", GroupWorkerOps},
		{svc + "ShutdownWorker", GroupWorkerOps},

		{svc + "TerminateWorkflowExecution", GroupWorkflowAdmin},
		{svc + "StartBatchOperation", GroupWorkflowAdmin},
		{svc + "CreateSchedule", GroupScheduleWrite},
		{svc + "DescribeSchedule", GroupScheduleRead},
		{svc + "DeleteSchedule", GroupScheduleDelete},
		{svc + "SetCurrentDeployment", GroupDeploymentAdm},
		{svc + "GetWorkerTaskReachability", GroupDeploymentRead},
		{svc + "RegisterNamespace", GroupNamespaceAdmin},

		{svc + "DeleteWorkflowExecution", GroupWorkflowDelete},
		{adminSvc + "DeleteWorkflowExecution", GroupWorkflowDelete},
		{adminSvc + "RemoveTask", GroupClusterAdmin},
		// AdminService and OperatorService are resolved by service, so a name
		// they share with WorkflowService never inherits a WorkflowService group.
		{adminSvc + "GetSearchAttributes", GroupClusterAdmin},
		{adminSvc + "DescribeMutableState", GroupClusterAdmin},
		{opsvc + "ListClusters", GroupMetadataRead},
		{opsvc + "ListSearchAttributes", GroupMetadataRead},
		{opsvc + "ListNexusEndpoints", GroupMetadataRead},
		{opsvc + "GetNexusEndpoint", GroupMetadataRead},
		{opsvc + "CreateNexusEndpoint", GroupClusterAdmin},
		{opsvc + "AddSearchAttributes", GroupClusterAdmin},
		// The read list is OperatorService only. AdminService keeps every method.
		{adminSvc + "ListClusters", GroupClusterAdmin},
		{opsvc + "DeleteNamespace", GroupClusterAdmin},
		{opsvc + "SomeFutureOperatorRPC", GroupClusterAdmin},

		// Unknown RPCs have no group. Only a permit that names one allows it.
		{svc + "SomeBrandNewRPC", ""},
		// The Poll prefix no longer maps to worker-ops.
		{svc + "PollSomethingNew", ""},
		{"/other.Service/StartWorkflowExecution", ""},
	}
	for _, tc := range cases {
		t.Run(tc.api, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, LeafGroup(tc.api))
		})
	}
}

// TestWorkflowServiceClassified walks the generated WorkflowService descriptor
// for the pinned Temporal API version. Every method must be in exactly one leaf
// group, and every table entry must be a real method. This is the tripwire for
// a renovate bump that adds an RPC: it fails until the RPC is classified.
func TestWorkflowServiceClassified(t *testing.T) {
	t.Parallel()
	have := make(map[string]bool)
	d := workflowservice.WorkflowService_ServiceDesc
	for _, m := range d.Methods {
		have[m.MethodName] = true
	}
	for _, s := range d.Streams {
		have[s.StreamName] = true
	}
	for name := range have {
		require.NotEmpty(t, LeafGroup("/"+d.ServiceName+"/"+name), "%s has no shipped group; add it to leafMembers", name)
	}
	for leaf, members := range leafMembers {
		for _, m := range members {
			require.True(t, have[m], "%s lists %s, which WorkflowService does not have", leaf, m)
		}
	}
}

// TestOperatorAndAdminSurfaceClassified checks every OperatorService and
// AdminService method: its group is the adminServiceLeaf entry when there is
// one, else cluster-admin. A new operator or admin RPC joins the cluster-admin
// floor with no table change.
func TestOperatorAndAdminSurfaceClassified(t *testing.T) {
	t.Parallel()

	descs := []grpc.ServiceDesc{
		operatorservice.OperatorService_ServiceDesc,
		adminservice.AdminService_ServiceDesc,
	}
	seenReads := map[string]bool{}
	for _, d := range descs {
		names := make([]string, 0, len(d.Methods)+len(d.Streams))
		for _, m := range d.Methods {
			names = append(names, m.MethodName)
		}
		for _, s := range d.Streams {
			names = append(names, s.StreamName)
		}
		for _, name := range names {
			want := GroupClusterAdmin
			if g, ok := adminServiceLeaf[name]; ok {
				want = g
			}
			if d.ServiceName == operatorServiceFull && operatorServiceReads[name] {
				want = GroupMetadataRead
				seenReads[name] = true
			}
			require.Equal(t, want, LeafGroup("/"+d.ServiceName+"/"+name), "%s/%s", d.ServiceName, name)
		}
	}
	// A read listed in operatorServiceReads must exist upstream, so a rename
	// cannot leave a dead entry that quietly returns the read to cluster-admin.
	for name := range operatorServiceReads {
		require.True(t, seenReads[name], "operatorServiceReads names a method OperatorService lacks: %s", name)
	}
}

// Every aggregate member exists, no aggregate holds an admin or delete leaf,
// and the Cedar schema lists every shipped group.
func TestShippedGroupsConsistent(t *testing.T) {
	t.Parallel()
	for agg, members := range shippedAggregates {
		for _, m := range members {
			require.True(t, isShippedGroup(m), "%s holds unknown group %s", agg, m)
			if agg != "delete-all" {
				require.False(t, neverForgiven[m], "%s must not hold %s", agg, m)
			}
		}
	}
	schema, err := os.ReadFile("../schema/temporal.cedarschema")
	require.NoError(t, err)
	for _, g := range shippedGroupNames() {
		require.Contains(t, string(schema), `action "`+g+`"`, "schema is missing group %s", g)
	}
	_, err = newActionGroups(nil)
	require.NoError(t, err)
}

// TestDeleteRPCsAreReviewed is the guard for delete-all, which covers data and
// audit trail deletion only. Cluster management deletes (deployments, rules) sit
// in admin groups on purpose and are listed below. A WorkflowService RPC
// whose name starts with Delete must be in a delete leaf, or be listed in
// reviewedDeletes with the admin group it was put in on purpose. A new Delete*
// RPC fails here until someone decides which it is.
func TestDeleteRPCsAreReviewed(t *testing.T) {
	t.Parallel()
	reviewedDeletes := map[string]string{
		"DeleteWorkerDeployment":        GroupDeploymentAdm,
		"DeleteWorkerDeploymentVersion": GroupDeploymentAdm,
		"DeleteWorkflowRule":            "namespace-admin",
	}
	d := workflowservice.WorkflowService_ServiceDesc
	for _, m := range d.Methods {
		if !strings.HasPrefix(m.MethodName, "Delete") {
			continue
		}
		got := LeafGroup("/" + d.ServiceName + "/" + m.MethodName)
		if want, ok := reviewedDeletes[m.MethodName]; ok {
			require.Equal(t, want, got, "%s moved groups; review it against delete-all", m.MethodName)
			continue
		}
		require.Contains(t, []string{GroupWorkflowDelete, GroupScheduleDelete, GroupActivityDelete}, got,
			"%s is a new Delete RPC in %q; put it in a delete group, or list it in reviewedDeletes", m.MethodName, got)
	}
}

// A service of another package with a known short name gets no group.
func TestLeafGroupNeedsFullServiceName(t *testing.T) {
	t.Parallel()
	require.Equal(t, GroupWorkflowStart, LeafGroup("/temporal.api.workflowservice.v1.WorkflowService/StartWorkflowExecution"))
	for _, api := range []string{
		"/other.WorkflowService/StartWorkflowExecution",
		"/temporal.api.workflowservice.v2.WorkflowService/StartWorkflowExecution",
		"/evil.adminservice.AdminService/DeleteNamespace",
		"/x.operatorservice.Y/AddSearchAttributes",
	} {
		require.Empty(t, LeafGroup(api), api)
	}
	require.Equal(t, GroupClusterAdmin, LeafGroup("/temporal.api.operatorservice.v1.OperatorService/DeleteNamespace"))
}
