package netguard

import (
	"context"
	"fmt"
	"net"
	"time"
)

// SafeDialer establishes network connections while strictly enforcing network safety policies.
type SafeDialer struct {
	resolver DNSResolver
	policy   NetworkPolicy
	dialer   *net.Dialer
}

// NewSafeDialer returns a SafeDialer with the provided resolver and connection timeout.
func NewSafeDialer(resolver DNSResolver, timeout time.Duration) *SafeDialer {
	return NewSafeDialerWithPolicy(resolver, DefaultNetworkPolicy{}, timeout)
}

// NewSafeDialerWithPolicy returns a SafeDialer with custom network policy.
func NewSafeDialerWithPolicy(resolver DNSResolver, policy NetworkPolicy, timeout time.Duration) *SafeDialer {
	if resolver == nil {
		resolver = NewSafeResolverWithPolicy(nil, policy)
	}
	if policy == nil {
		policy = DefaultNetworkPolicy{}
	}
	return &SafeDialer{
		resolver: resolver,
		policy:   policy,
		dialer: &net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		},
	}
}

// DialContext resolves addr safely and dials only validated non-private IPs.
func (d *SafeDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid address %q: %w", addr, err)
	}

	addrs, err := d.resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}

	if len(addrs) == 0 {
		return nil, fmt.Errorf("no IP addresses resolved for %s", host)
	}

	var lastErr error
	for _, ip := range addrs {
		if d.policy.IsBlockedIP(ip) {
			return nil, fmt.Errorf("%w: %s (%s)", ErrBlockedIP, host, ip)
		}

		targetAddr := net.JoinHostPort(ip.String(), port)
		conn, err := d.dialer.DialContext(ctx, network, targetAddr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	return nil, fmt.Errorf("failed to connect to %s (tried %d IPs): %w", addr, len(addrs), lastErr)
}
