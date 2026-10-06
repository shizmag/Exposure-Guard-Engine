package netguard

import (
	"fmt"
	"net/http"
	"strings"
)

// NewSafeCheckRedirect returns a redirect policy function using DefaultNetworkPolicy.
func NewSafeCheckRedirect(maxRedirects int, resolver DNSResolver) func(req *http.Request, via []*http.Request) error {
	return NewSafeCheckRedirectWithPolicy(maxRedirects, resolver, DefaultNetworkPolicy{})
}

// NewSafeCheckRedirectWithPolicy returns a redirect policy function with custom policy.
func NewSafeCheckRedirectWithPolicy(maxRedirects int, resolver DNSResolver, policy NetworkPolicy) func(req *http.Request, via []*http.Request) error {
	if policy == nil {
		policy = DefaultNetworkPolicy{}
	}
	if resolver == nil {
		resolver = NewSafeResolverWithPolicy(nil, policy)
	} else if _, ok := resolver.(*SafeResolver); !ok {
		resolver = NewSafeResolverWithPolicy(resolver, policy)
	}

	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= maxRedirects {
			return fmt.Errorf("%w: limit of %d hops reached", ErrTooManyRedirects, maxRedirects)
		}

		scheme := strings.ToLower(req.URL.Scheme)
		if scheme != "http" && scheme != "https" {
			return fmt.Errorf("%w: invalid redirect scheme %q", ErrBlockedScheme, scheme)
		}

		host := req.URL.Hostname()
		if policy.IsBlockedHostname(host) {
			return fmt.Errorf("%w: redirect target %q", ErrBlockedHostname, host)
		}

		// Re-resolve hostname at redirect boundary to prevent redirect-based SSRF/rebinding
		ctx := req.Context()
		addrs, err := resolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return fmt.Errorf("redirect target resolution failed: %w", err)
		}
		for _, addr := range addrs {
			if policy.IsBlockedIP(addr) {
				return fmt.Errorf("%w: redirect target %s resolved to %s", ErrBlockedIP, host, addr)
			}
		}

		return nil
	}
}
