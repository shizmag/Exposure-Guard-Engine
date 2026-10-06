package netguard

import (
	"crypto/tls"
	"net/http"
	"time"

	"github.com/exposureguard/exposureguard/pkg/model"
)

// NewSafeTransport creates an http.Transport guarded by SafeDialer using DefaultNetworkPolicy.
func NewSafeTransport(resolver DNSResolver, limits model.Limits) *http.Transport {
	return NewSafeTransportWithPolicy(resolver, DefaultNetworkPolicy{}, limits)
}

// NewSafeTransportWithPolicy creates an http.Transport with custom policy.
func NewSafeTransportWithPolicy(resolver DNSResolver, policy NetworkPolicy, limits model.Limits) *http.Transport {
	limits.Clamp()

	dialer := NewSafeDialerWithPolicy(resolver, policy, time.Duration(limits.RequestTimeoutSeconds)*time.Second)

	return &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   time.Duration(limits.TLSHandshakeTimeoutSeconds) * time.Second,
		ResponseHeaderTimeout: time.Duration(limits.RequestTimeoutSeconds) * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          limits.MaxConcurrency * 4,
		MaxIdleConnsPerHost:   limits.MaxPerHostConcurrency,
		MaxResponseHeaderBytes: 256 * 1024,
		DisableCompression:   false,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
}

// NewSafeHTTPClient creates a production-hardened http.Client using DefaultNetworkPolicy.
func NewSafeHTTPClient(resolver DNSResolver, limits model.Limits) *http.Client {
	return NewSafeHTTPClientWithPolicy(resolver, DefaultNetworkPolicy{}, limits)
}

// NewSafeHTTPClientWithPolicy creates a production-hardened http.Client with custom policy.
func NewSafeHTTPClientWithPolicy(resolver DNSResolver, policy NetworkPolicy, limits model.Limits) *http.Client {
	limits.Clamp()

	transport := NewSafeTransportWithPolicy(resolver, policy, limits)
	redirectFn := NewSafeCheckRedirectWithPolicy(limits.MaxRedirects, resolver, policy)

	return &http.Client{
		Transport:     transport,
		CheckRedirect: redirectFn,
		Timeout:       time.Duration(limits.RequestTimeoutSeconds) * time.Second,
	}
}
