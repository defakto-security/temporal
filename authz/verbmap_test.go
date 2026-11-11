package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
		{"/temporal.server.api.adminservice.v1.AdminService/RemoveTask", VerbForbiddenAll},
		{"/temporal.server.api.adminservice.v1.AdminService/DescribeHistoryHost", VerbForbiddenAll},

		// AdminService RPCs are forbidden by service, NOT classified by the
		// bare-name prefix rules. DescribeMutableState shares a name shape with
		// WorkflowService reads but must never be treated as read-only.
		{"/temporal.server.api.adminservice.v1.AdminService/DescribeMutableState", VerbForbiddenAll},
		{"/temporal.server.api.adminservice.v1.AdminService/GetWorkflowExecutionRawHistory", VerbForbiddenAll},
		{"/temporal.server.api.adminservice.v1.AdminService/ListClusters", VerbForbiddenAll},
		{"/temporal.server.api.adminservice.v1.AdminService/AddSearchAttributes", VerbForbiddenAll},

		// Service is resolved BEFORE the exact-name table: an admin method that
		// shares a name with a WorkflowService entry (GetSearchAttributes) must
		// NOT inherit the benign read-only class.
		{"/temporal.server.api.adminservice.v1.AdminService/GetSearchAttributes", VerbUnknown},

		// OperatorService is an operator surface too. Its List*/Describe* names
		// would otherwise hit the WorkflowService prefix rules and become
		// read-only (reachable by humans); classify by service instead.
		{opsvc + "ListClusters", VerbForbiddenAll},
		{opsvc + "ListSearchAttributes", VerbForbiddenAll},
		{opsvc + "DeleteNamespace", VerbForbiddenAll},
		{opsvc + "AddSearchAttributes", VerbForbiddenAll},
		{opsvc + "RemoveSearchAttributes", VerbForbiddenAll},
		// An unlisted operator method is denied (fail closed), not read-only.
		{opsvc + "SomeFutureOperatorRPC", VerbUnknown},

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
// descriptors for the pinned Temporal api/server versions and fails if any
// OperatorService or AdminService method (unary OR streaming) is not resolved
// as an operator surface. renovate.json auto-bumps these dependencies; this
// test is the tripwire that a newly-added operator/admin RPC is not silently
// left to the bare-name prefix rules (which would make a List*/Describe* RPC
// human-readable). "Resolved as operator surface" means either an explicit
// adminVerbClass classification or VerbUnknown (denied) — never a
// WorkflowService class reached by prefix matching.
func TestOperatorAndAdminSurfaceClassified(t *testing.T) {
	t.Parallel()

	descs := []grpc.ServiceDesc{
		operatorservice.OperatorService_ServiceDesc,
		adminservice.AdminService_ServiceDesc,
	}

	// Classes a WorkflowService prefix rule can produce. An operator/admin
	// method landing in one of these means the service check was bypassed.
	workflowPrefixClasses := map[VerbClass]bool{
		VerbReadOnly:    true,
		VerbStartSignal: true,
		VerbWorker:      true,
		VerbBreakGlass:  true,
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
			full := "/" + svc + "/" + name
			got := VerbClassOf(full)
			if workflowPrefixClasses[got] {
				t.Errorf("%s classified as %q via prefix rules; operator/admin "+
					"methods must be explicitly classified or VerbUnknown", full, got)
			}
		}
	}
}
