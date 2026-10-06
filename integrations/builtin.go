package integrations

import (
	"github.com/exposureguard/exposureguard/integrations/httpx"
	"github.com/exposureguard/exposureguard/integrations/katana"
	"github.com/exposureguard/exposureguard/integrations/nuclei"
	"github.com/exposureguard/exposureguard/integrations/subfinder"
	"github.com/exposureguard/exposureguard/pkg/integration"
)

// BuiltinAdapters returns instances of all supported built-in integration adapters.
func BuiltinAdapters() []integration.Adapter {
	return []integration.Adapter{
		subfinder.NewAdapter(),
		httpx.NewAdapter(),
		katana.NewAdapter(),
		nuclei.NewAdapter(),
	}
}

// RegisterBuiltins registers all built-in adapters into the provided registry.
func RegisterBuiltins(reg *integration.Registry) error {
	if reg == nil {
		return nil
	}
	for _, a := range BuiltinAdapters() {
		if err := reg.Register(a); err != nil {
			return err
		}
	}
	return nil
}

// NewBuiltinRegistry creates and returns a clean, isolated Registry with all built-in adapters.
func NewBuiltinRegistry() *integration.Registry {
	reg := integration.NewRegistry()
	if err := RegisterBuiltins(reg); err != nil {
		return reg
	}
	return reg
}

// InitDefaultRegistry populates the global default registry with built-in adapters.
func InitDefaultRegistry() {
	if err := RegisterBuiltins(integration.DefaultRegistry()); err != nil {
		return
	}
}
