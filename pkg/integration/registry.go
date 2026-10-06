package integration

import (
	"fmt"
	"sort"
	"sync"
)

// Registry manages the set of available integration adapters.
type Registry struct {
	mu       sync.RWMutex
	adapters map[string]Adapter
}

// NewRegistry initializes an empty Registry.
func NewRegistry() *Registry {
	return &Registry{
		adapters: make(map[string]Adapter),
	}
}

// Register registers an adapter into the registry.
// Returns an error if an adapter with the same ID is already registered or metadata is invalid.
func (r *Registry) Register(a Adapter) error {
	if a == nil {
		return fmt.Errorf("cannot register nil adapter")
	}
	id := a.ID()
	if id == "" {
		return fmt.Errorf("adapter has empty ID")
	}
	meta := a.Metadata()
	if meta.ID == "" {
		return fmt.Errorf("adapter %q has empty metadata ID", id)
	}
	if meta.Binary == "" {
		return fmt.Errorf("adapter %q has empty binary name", id)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.adapters[id]; exists {
		return fmt.Errorf("adapter %q is already registered", id)
	}
	r.adapters[id] = a
	return nil
}

// Get returns the adapter registered with the specified ID.
func (r *Registry) Get(id string) (Adapter, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	a, ok := r.adapters[id]
	return a, ok
}

// List returns all registered adapters sorted alphabetically by ID.
func (r *Registry) List() []Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make([]Adapter, 0, len(r.adapters))
	for _, a := range r.adapters {
		list = append(list, a)
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID() < list[j].ID()
	})
	return list
}

// ByCapability filters registered adapters that provide the given capability.
func (r *Registry) ByCapability(cap Capability) []Adapter {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var matched []Adapter
	for _, a := range r.adapters {
		if a.Metadata().HasCapability(cap) {
			matched = append(matched, a)
		}
	}
	sort.Slice(matched, func(i, j int) bool {
		return matched[i].ID() < matched[j].ID()
	})
	return matched
}

var (
	defaultRegistry     = NewRegistry()
	defaultRegistryLock sync.RWMutex
)

// DefaultRegistry returns the global default integration registry.
func DefaultRegistry() *Registry {
	defaultRegistryLock.RLock()
	defer defaultRegistryLock.RUnlock()
	return defaultRegistry
}

// ResetDefaultRegistry resets the global registry (useful for test isolation).
func ResetDefaultRegistry() {
	defaultRegistryLock.Lock()
	defer defaultRegistryLock.Unlock()
	defaultRegistry = NewRegistry()
}

// Register adds an adapter to the default global registry.
func Register(a Adapter) error {
	return DefaultRegistry().Register(a)
}
