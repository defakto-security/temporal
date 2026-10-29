package authz

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVerbClassOf(t *testing.T) {
	t.Parallel()

	const svc = "/temporal.api.workflowservice.v1.WorkflowService/"
	cases := []struct {
		api  string
		want VerbClass
	}{
		{svc + "StartWorkflowExecution", VerbStartSignal},
		{svc + "SignalWorkflowExecution", VerbStartSignal},
		{svc + "SignalWithStartWorkflowExecution", VerbStartSignal},
		{svc + "QueryWorkflow", VerbStartSignal},

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
