package main

import (
	"go.temporal.io/server/tools/elasticsearch"
)

// CmdElasticsearchTool is the first argument that runs Temporal's own
// temporal-elasticsearch-tool instead of the server. The tool signs requests
// with the pod's IRSA role (--aws-credentials aws-sdk-default), so the image
// can set up the visibility index template with no stored credentials.
const CmdElasticsearchTool = "elasticsearch-tool"

// runTool runs the elasticsearch tool when args select it. It reports whether
// it ran, and any error from the CLI layer (bad flags). A failed command makes
// the upstream tool exit the process with status 1 itself, so it never
// returns here.
func runTool(args []string) (bool, error) {
	if len(args) < 2 || args[1] != CmdElasticsearchTool {
		return false, nil
	}
	rest := append([]string{"temporal-elasticsearch-tool"}, args[2:]...)
	return true, elasticsearch.RunTool(rest)
}
