package example_test

import (
	"testing"

	"github.com/exposureguard/exposureguard/integrations/example"
	"github.com/exposureguard/exposureguard/pkg/integration/integrationtest"
)

func TestExampleAdapterContract(t *testing.T) {
	adapter := example.NewAdapter()
	integrationtest.RunAdapterContract(t, adapter)
}
