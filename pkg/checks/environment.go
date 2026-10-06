package checks

import (
	"net/http"
	"time"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/exposureguard/exposureguard/pkg/protocol"
)

// Environment provides strictly controlled, safe network and reporting capabilities to checks.
// Checks MUST NOT construct their own raw HTTP clients or DNS resolvers.
type Environment struct {
	HTTP   *http.Client
	DNS    netguard.DNSResolver
	Policy netguard.NetworkPolicy
	Limits model.Limits
	Events *protocol.Encoder
}

// NewDialer constructs a SafeDialer respecting the environment's resolver and network policy.
func (e *Environment) NewDialer(timeout time.Duration) *netguard.SafeDialer {
	policy := e.Policy
	if policy == nil {
		policy = netguard.DefaultNetworkPolicy{}
	}
	return netguard.NewSafeDialerWithPolicy(e.DNS, policy, timeout)
}

// NewEnvironment creates an isolated execution environment for checks using DefaultNetworkPolicy.
func NewEnvironment(client *http.Client, resolver netguard.DNSResolver, limits model.Limits, events *protocol.Encoder) *Environment {
	return NewEnvironmentWithPolicy(client, resolver, netguard.DefaultNetworkPolicy{}, limits, events)
}

// NewEnvironmentWithPolicy creates an isolated execution environment with a specific network policy.
func NewEnvironmentWithPolicy(client *http.Client, resolver netguard.DNSResolver, policy netguard.NetworkPolicy, limits model.Limits, events *protocol.Encoder) *Environment {
	limits.Clamp()
	if policy == nil {
		policy = netguard.DefaultNetworkPolicy{}
	}
	if resolver == nil {
		resolver = netguard.NewSafeResolverWithPolicy(nil, policy)
	}
	if client == nil {
		client = netguard.NewSafeHTTPClientWithPolicy(resolver, policy, limits)
	}

	return &Environment{
		HTTP:   client,
		DNS:    resolver,
		Policy: policy,
		Limits: limits,
		Events: events,
	}
}
