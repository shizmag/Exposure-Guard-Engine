package capabilities_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"slices"
	"strconv"
	"testing"

	"github.com/exposureguard/exposureguard/integrations"
	"github.com/exposureguard/exposureguard/pkg/capabilities"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/profile"
)

func TestCapabilityContractMatchesEngineRegistries(t *testing.T) {
	manifest, err := capabilities.Load()
	if err != nil {
		t.Fatal(err)
	}
	sourceManifest, err := capabilities.Parse(capabilitySource(t))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(manifest, sourceManifest) {
		t.Fatal("embedded capability contract differs from pkg/capabilities/manifest.json")
	}

	capabilityByID := make(map[string]capabilities.Capability, len(manifest.Capabilities))
	for _, capability := range manifest.Capabilities {
		capabilityByID[capability.ID] = capability
	}

	actualNativeStages := nativeStageIDs(t)
	var registeredNativeStages []string
	for _, capability := range manifest.Capabilities {
		if capability.Kind == "native" {
			registeredNativeStages = append(registeredNativeStages, capability.ID)
		}
	}
	sortStrings(actualNativeStages)
	sortStrings(registeredNativeStages)
	if !equalStrings(actualNativeStages, registeredNativeStages) {
		t.Fatalf("native stages in engine.go = %v, capability contract registers %v", actualNativeStages, registeredNativeStages)
	}

	actualProfiles := profile.List()
	if len(actualProfiles) != len(manifest.Profiles) {
		t.Fatalf("profile count mismatch: runtime=%d contract=%d", len(actualProfiles), len(manifest.Profiles))
	}
	profilesByID := make(map[string]capabilities.Profile, len(manifest.Profiles))
	for _, p := range manifest.Profiles {
		profilesByID[p.ID] = p
	}
	for _, actual := range actualProfiles {
		declared, ok := profilesByID[string(actual.ID)]
		if !ok {
			t.Fatalf("runtime profile %q is absent from capability contract", actual.ID)
		}
		mode := "any"
		if actual.RequiredMode == model.ScanModeOwned {
			mode = "owned"
		}
		if declared.RequiredMode != mode {
			t.Errorf("profile %q mode=%q, contract=%q", actual.ID, mode, declared.RequiredMode)
		}
		var want []string
		for _, module := range actual.NativeChecks {
			if module == "sourcemaps" {
				continue
			}
			want = append(want, module)
		}
		for _, integrationID := range actual.Integrations {
			want = append(want, "integration."+integrationID)
		}
		sortStrings(want)
		got := append([]string(nil), declared.Capabilities...)
		sortStrings(got)
		if !equalStrings(want, got) {
			t.Errorf("profile %q runtime capabilities=%v, contract=%v", actual.ID, want, got)
		}
		for _, id := range declared.Capabilities {
			capability, ok := capabilityByID[id]
			if !ok || !contains(capability.Profiles, string(actual.ID)) {
				t.Errorf("profile %q and capability %q are not registered bidirectionally", actual.ID, id)
			}
		}
	}

	registry := integrations.NewBuiltinRegistry()
	var actualIntegrations, registeredIntegrations []string
	for _, adapter := range registry.List() {
		actualIntegrations = append(actualIntegrations, adapter.ID())
		capability, ok := capabilityByID["integration."+adapter.ID()]
		if !ok {
			t.Errorf("registered integration %q has no capability contract", adapter.ID())
			continue
		}
		metadata := adapter.Metadata()
		needsOwned := !metadata.SupportsMode(model.ScanModePublic) && metadata.SupportsMode(model.ScanModeOwned)
		if capability.OwnershipRequired != needsOwned {
			t.Errorf("integration %q ownership requirement disagrees with adapter policy", adapter.ID())
		}
		registeredIntegrations = append(registeredIntegrations, capability.Integration)
	}
	for _, capability := range manifest.Capabilities {
		if capability.Kind == "integration" && !contains(registeredIntegrations, capability.Integration) {
			registeredIntegrations = append(registeredIntegrations, capability.Integration)
		}
	}
	sortStrings(actualIntegrations)
	sortStrings(registeredIntegrations)
	if !equalStrings(actualIntegrations, registeredIntegrations) {
		t.Fatalf("registered integrations=%v, capability contract=%v", actualIntegrations, registeredIntegrations)
	}
}

func TestCapabilityContractRejectsUnregisteredSyntheticStage(t *testing.T) {
	manifest, err := capabilities.Load()
	if err != nil {
		t.Fatal(err)
	}
	manifest.Capabilities = append(manifest.Capabilities, capabilities.Capability{ID: "integration.synthetic_stage", Kind: "integration"})
	if err := manifest.Validate(); err == nil {
		t.Fatal("incomplete test-only capability unexpectedly passed contract validation")
	}
}

func nativeStageIDs(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "../../pkg/engine/engine.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok || len(call.Args) != 2 {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "emit" {
			return true
		}
		event, ok := call.Args[0].(*ast.SelectorExpr)
		if !ok || event.Sel.Name != "EventStageStarted" {
			return true
		}
		literal, ok := call.Args[1].(*ast.CompositeLit)
		if !ok {
			return true
		}
		for _, element := range literal.Elts {
			pair, ok := element.(*ast.KeyValueExpr)
			if !ok {
				continue
			}
			key, ok := pair.Key.(*ast.BasicLit)
			if !ok || key.Value != `"stage"` {
				continue
			}
			value, ok := pair.Value.(*ast.BasicLit)
			if !ok || value.Kind != token.STRING {
				continue
			}
			stage, err := strconv.Unquote(value.Value)
			if err == nil {
				seen[stage] = true
			}
		}
		return true
	})
	var stages []string
	for stage := range seen {
		stages = append(stages, stage)
	}
	return stages
}

func capabilitySource(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile("../../pkg/capabilities/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
func sortStrings(values []string) { slices.Sort(values) }
