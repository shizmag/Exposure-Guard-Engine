package integrations_test

import (
	"slices"
	"testing"

	"github.com/exposureguard/exposureguard/integrations"
	"github.com/exposureguard/exposureguard/pkg/integration"
)

func TestBuiltinAdapters(t *testing.T) {
	adapters := integrations.BuiltinAdapters()
	if len(adapters) != 4 {
		t.Fatalf("expected 4 built-in adapters, got %d", len(adapters))
	}

	expectedIDs := []string{"subfinder", "httpx", "katana", "nuclei"}
	var foundIDs []string
	for _, a := range adapters {
		foundIDs = append(foundIDs, a.ID())
		if a.Metadata().ID != a.ID() {
			t.Errorf("adapter metadata ID %q != ID() %q", a.Metadata().ID, a.ID())
		}
		if a.Metadata().Binary == "" {
			t.Errorf("adapter %s has empty binary name", a.ID())
		}
	}

	for _, req := range expectedIDs {
		if !slices.Contains(foundIDs, req) {
			t.Errorf("missing expected built-in adapter: %s", req)
		}
	}
}

func TestNewBuiltinRegistry(t *testing.T) {
	reg := integrations.NewBuiltinRegistry()
	if reg == nil {
		t.Fatal("NewBuiltinRegistry returned nil")
	}

	list := reg.List()
	if len(list) != 4 {
		t.Fatalf("expected 4 adapters in registry, got %d", len(list))
	}

	for _, id := range []string{"subfinder", "httpx", "katana", "nuclei"} {
		a, ok := reg.Get(id)
		if !ok || a == nil {
			t.Errorf("expected adapter %s in registry", id)
		}
	}
}

func TestRegisterBuiltinsIdempotence(t *testing.T) {
	reg := integration.NewRegistry()
	if err := integrations.RegisterBuiltins(reg); err != nil {
		t.Fatalf("first registration failed: %v", err)
	}

	// Second registration of same IDs should return error (no duplicate registration)
	if err := integrations.RegisterBuiltins(reg); err == nil {
		t.Error("expected error on duplicate registration")
	}
}
