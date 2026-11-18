package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	operatorservice "go.temporal.io/api/operatorservice/v1"
	adminservice "go.temporal.io/server/api/adminservice/v1"
	"google.golang.org/grpc"
)

// TestVerbClassOf is a test helper or test case in this package.
func TestVerbClassOf(t *testing.T) {
	t.Parallel()

	const svc = "/temporal.api.workflowservice.v1.WorkflowService/"
	const opsvc = "/temporal.api.operatorservice.v1.OperatorService/"
	cases := []struct {
		api  string
		want VerbClass
	}{
		{svc + "StartWorkflowExecution", VerbStartSignal},
		{svc + "SignalWorkflowExecution", VerbStartSignal},
		{svc + "SignalWithStartWorkflowExecution", VerbStartSignal},
		{svc + "QueryWorkflow", VerbStartSignal},
		{svc + "UpdateWorkflowExecution", VerbStartSignal},
		// PollWorkflowExecutionUpdate polls for an update's result; it is the
		// read side of UpdateWorkflowExecution, so it must share VerbStartSignal
		// and NOT fall through the Poll* prefix rule to VerbWorker.
		{svc + "PollWorkflowExecutionUpdate", VerbStartSignal},
		// Same class of bug: these Poll* RPCs are client-side result reads, not
		// the worker task-dispatch loop, so they must not be VerbWorker.
		{svc + "PollActivityExecution", VerbStartSignal},
		{svc + "PollNexusOperationExecution", VerbStartSignal},
		{svc + "ExecuteMultiOperation", VerbStartSignal},
		{svc + "GetSystemInfo", VerbReadOnly},
		{svc + "GetSearchAttributes", VerbReadOnly},

		{svc + "DescribeNamespace", VerbReadOnly},
		{svc + "ListWorkflowExecutions", VerbReadOnly},
		{svc + "CountWorkflowExecutions", VerbReadOnly},
		{svc + "GetWorkflowExecutionHistory", VerbReadOnly},

		{svc + "PollActivityTaskQueue", VerbWorker},
		{svc + "PollWorkflowTaskQueue", VerbWorker},
		{svc + "RespondActivityTaskCompleted", VerbWorker},
		{svc + "RecordActivityTaskHeartbeat", VerbWorker},

		{svc + "TerminateWorkflowExecution", VerbBreakGlass},
		{svc + "RequestCancelWorkflowExecution", VerbBreakGlass},
		{svc + "ResetWorkflowExecution", VerbBreakGlass},

		{svc + "DeleteWorkflowExecution", VerbForbiddenAll},
		{"/temporal.server.api.adminservice.v1.AdminService/DeleteWorkflowExecution", VerbForbiddenAll},
		{"/temporal.server.api.adminservice.v1.AdminService/RemoveTask", VerbClusterAdmin},
		{"/temporal.server.api.adminservice.v1.AdminService/DescribeHistoryHost", VerbClusterAdmin},

		// AdminService RPCs are forbidden by service, NOT classified by the
		// bare-name prefix rules. DescribeMutableState shares a name shape with
		// WorkflowService reads but must never be treated as read-only.
		{"/temporal.server.api.adminservice.v1.AdminService/DescribeMutableState", VerbClusterAdmin},
		{"/temporal.server.api.adminservice.v1.AdminService/GetWorkflowExecutionRawHistory", VerbClusterAdmin},
		{"/temporal.server.api.adminservice.v1.AdminService/ListClusters", VerbClusterAdmin},
		{"/temporal.server.api.adminservice.v1.AdminService/AddSearchAttributes", VerbClusterAdmin},

		// Service is resolved BEFORE the exact-name table: an admin method that
		// shares a name with a WorkflowService entry (GetSearchAttributes) must
		// NOT inherit the benign read-only class.
		{"/temporal.server.api.adminservice.v1.AdminService/GetSearchAttributes", VerbClusterAdmin},

		// OperatorService is an operator surface too. Its List*/Describe* names
		// would otherwise hit the WorkflowService prefix rules and become
		// read-only (reachable by humans); classify by service instead.
		{opsvc + "ListClusters", VerbClusterAdmin},
		{opsvc + "ListSearchAttributes", VerbClusterAdmin},
		{opsvc + "DeleteNamespace", VerbClusterAdmin},
		{opsvc + "AddSearchAttributes", VerbClusterAdmin},
		{opsvc + "RemoveSearchAttributes", VerbClusterAdmin},
		// An unlisted operator method is cluster-admin, not read-only.
		{opsvc + "SomeFutureOperatorRPC", VerbClusterAdmin},

		// Namespace lifecycle is namespace-admin.
		{svc + "RegisterNamespace", VerbNamespaceAdmin},
		{svc + "UpdateNamespace", VerbNamespaceAdmin},
		{svc + "DeprecateNamespace", VerbNamespaceAdmin},

		// A GetXxx without History is not read-only by the prefix rule.
		{svc + "GetClusterInfo", VerbUnknown},
		{svc + "SomeBrandNewRPC", VerbUnknown},
	}

	for _, tc := range cases {
		t.Run(tc.api, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, VerbClassOf(tc.api))
		})
	}
}

// TestOperatorAndAdminSurfaceClassified walks the generated gRPC service
// descriptors for the pinned Temporal api/server versions and checks every
// OperatorService and AdminService method (unary and streaming): its class is
// the adminVerbClass entry when there is one, else VerbClusterAdmin. This is the
// tripwire against a newly added operator or admin RPC reaching a WorkflowService
// prefix rule (which would make a List* or Describe* RPC human-readable).
func TestOperatorAndAdminSurfaceClassified(t *testing.T) {
	t.Parallel()

	descs := []grpc.ServiceDesc{
		operatorservice.OperatorService_ServiceDesc,
		adminservice.AdminService_ServiceDesc,
	}

	for _, d := range descs {
		svc := d.ServiceName
		names := make([]string, 0, len(d.Methods)+len(d.Streams))
		for _, m := range d.Methods {
			names = append(names, m.MethodName)
		}
		for _, s := range d.Streams {
			names = append(names, s.StreamName)
		}
		for _, name := range names {
			want := VerbClusterAdmin
			if c, ok := adminVerbClass[name]; ok {
				want = c
			}
			require.Equal(t, want, VerbClassOf("/"+svc+"/"+name), "%s/%s", svc, name)
		}
	}
}
