package netguard

import (
	"context"
	"fmt"
	"net"
	"net/netip"
)

// DNSResolver resolves hostnames to IP addresses.
type DNSResolver interface {
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// SafeResolver enforces network policy on all DNS resolutions.
type SafeResolver struct {
	base   DNSResolver
	policy NetworkPolicy
}

// NewSafeResolver creates a SafeResolver wrapping base using DefaultNetworkPolicy.
func NewSafeResolver(base DNSResolver) *SafeResolver {
	return NewSafeResolverWithPolicy(base, DefaultNetworkPolicy{})
}

// NewSafeResolverWithPolicy creates a SafeResolver with a custom network policy.
func NewSafeResolverWithPolicy(base DNSResolver, policy NetworkPolicy) *SafeResolver {
	if base == nil {
		base = net.DefaultResolver
	}
	if policy == nil {
		policy = DefaultNetworkPolicy{}
	}
	return &SafeResolver{base: base, policy: policy}
}

// LookupNetIP resolves host and asserts that NO resolved IP is blocked.
func (r *SafeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if r.policy.IsBlockedHostname(host) {
		return nil, fmt.Errorf("%w: %s", ErrBlockedHostname, host)
	}

	// If host is an IP literal, validate directly
	if addr, err := netip.ParseAddr(host); err == nil {
		if r.policy.IsBlockedIP(addr) {
			return nil, fmt.Errorf("%w: %s", ErrBlockedIP, addr)
		}
		return []netip.Addr{addr}, nil
	}

	addrs, err := r.base.LookupNetIP(ctx, network, host)
	if err != nil {
		return nil, err
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no IP addresses found for host: %s", host)
	}

	validAddrs := make([]netip.Addr, 0, len(addrs))
	for _, addr := range addrs {
		if r.policy.IsBlockedIP(addr) {
			return nil, fmt.Errorf("%w: %s resolved to blocked IP %s", ErrBlockedIP, host, addr)
		}
		validAddrs = append(validAddrs, addr)
	}

	return validAddrs, nil
}
