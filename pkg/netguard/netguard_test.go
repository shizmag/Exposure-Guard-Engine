package netguard

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBlockedIPs(t *testing.T) {
	blockedCases := []string{
		"127.0.0.1",
		"127.255.255.254",
		"0.0.0.0",
		"10.0.0.1",
		"10.255.0.1",
		"172.16.0.1",
		"172.31.255.255",
		"192.168.0.1",
		"192.168.1.100",
		"169.254.169.254", // Cloud metadata
		"169.254.1.1",     // Link local
		"100.64.0.1",      // CGNAT
		"100.127.255.255", // CGNAT
		"224.0.0.1",       // Multicast
		"240.0.0.1",       // Reserved
		"255.255.255.255", // Broadcast
		"::1",             // IPv6 loopback
		"::",              // IPv6 unspecified
		"fc00::1",         // IPv6 ULA
		"fd12:3456::1",    // IPv6 ULA
		"fe80::1",         // IPv6 link local
		"ff02::1",         // IPv6 multicast
		"::ffff:127.0.0.1",
		"::ffff:10.0.0.1",
		"::ffff:169.254.169.254",
	}

	for _, ipStr := range blockedCases {
		addr, err := netip.ParseAddr(ipStr)
		require.NoError(t, err, "failed to parse %s", ipStr)
		assert.True(t, IsBlockedIP(addr), "expected %s to be blocked", ipStr)
	}

	allowedCases := []string{
		"8.8.8.8",
		"1.1.1.1",
		"93.184.216.34",
		"2606:4700:4700::1111",
		"2001:4860:4860::8888",
	}

	for _, ipStr := range allowedCases {
		addr, err := netip.ParseAddr(ipStr)
		require.NoError(t, err, "failed to parse %s", ipStr)
		assert.False(t, IsBlockedIP(addr), "expected %s to be allowed", ipStr)
	}
}

func TestBlockedHostnames(t *testing.T) {
	blocked := []string{
		"localhost",
		"LOCALHOST",
		"foo.localhost",
		"sub.app.localhost.",
		"metadata.google.internal",
		"metadata",
		"instance-data",
		"127.0.0.1",
		"10.0.0.1",
		"169.254.169.254",
		"::1",
	}

	for _, h := range blocked {
		assert.True(t, IsBlockedHostname(h), "expected hostname %q to be blocked", h)
	}

	allowed := []string{
		"example.com",
		"sub.example.com",
		"github.com",
		"8.8.8.8",
	}

	for _, h := range allowed {
		assert.False(t, IsBlockedHostname(h), "expected hostname %q to be allowed", h)
	}
}

type mockResolver struct {
	fn func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

func (m *mockResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return m.fn(ctx, network, host)
}

func TestSafeResolverBlockedHostAndIP(t *testing.T) {
	ctx := context.Background()

	// 1. Blocked hostname rejected before lookup
	r := NewSafeResolver(nil)
	_, err := r.LookupNetIP(ctx, "ip", "localhost")
	require.ErrorIs(t, err, ErrBlockedHostname)

	// 2. Host resolving to private IP rejected
	mock := &mockResolver{
		fn: func(_ context.Context, _, _ string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("10.0.0.5")}, nil
		},
	}
	r = NewSafeResolver(mock)
	_, err = r.LookupNetIP(ctx, "ip", "attacker.com")
	require.ErrorIs(t, err, ErrBlockedIP)

	// 3. Host resolving to public IP allowed
	mock = &mockResolver{
		fn: func(_ context.Context, _, _ string) ([]netip.Addr, error) {
			return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
		},
	}
	r = NewSafeResolver(mock)
	addrs, err := r.LookupNetIP(ctx, "ip", "example.com")
	require.NoError(t, err)
	assert.Len(t, addrs, 1)
	assert.Equal(t, "93.184.216.34", addrs[0].String())
}

func TestDNSRebindingProtection(t *testing.T) {
	ctx := context.Background()

	// Simulate DNS rebinding:
	// First lookup returns public IP (93.184.216.34)
	// Second lookup (during DialContext) returns loopback (127.0.0.1)
	var callCount atomic.Int32
	mock := &mockResolver{
		fn: func(_ context.Context, _, _ string) ([]netip.Addr, error) {
			c := callCount.Add(1)
			if c == 1 {
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("127.0.0.1")}, nil
		},
	}

	safeRes := NewSafeResolver(mock)
	// First lookup passes
	addrs, err := safeRes.LookupNetIP(ctx, "ip", "rebind.attacker.com")
	require.NoError(t, err)
	assert.Equal(t, "93.184.216.34", addrs[0].String())

	// Dialer dials: resolver is queried again and returns 127.0.0.1 -> blocked!
	dialer := NewSafeDialer(safeRes, 2*time.Second)
	_, err = dialer.DialContext(ctx, "tcp", "rebind.attacker.com:80")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBlockedIP)
}

func TestRedirectPolicySecurity(t *testing.T) {
	ctx := context.Background()

	mock := &mockResolver{
		fn: func(_ context.Context, _, host string) ([]netip.Addr, error) {
			if host == "safe.com" {
				return []netip.Addr{netip.MustParseAddr("93.184.216.34")}, nil
			}
			return []netip.Addr{netip.MustParseAddr("169.254.169.254")}, nil
		},
	}
	checkRedirect := NewSafeCheckRedirect(3, mock)

	// 1. Max redirects exceeded
	req, _ := http.NewRequestWithContext(ctx, "GET", "http://safe.com/step4", nil)
	via := []*http.Request{
		req, req, req,
	}
	err := checkRedirect(req, via)
	require.ErrorIs(t, err, ErrTooManyRedirects)

	// 2. Redirect to unsafe scheme
	req, _ = http.NewRequestWithContext(ctx, "GET", "file:///etc/passwd", nil)
	err = checkRedirect(req, nil)
	require.ErrorIs(t, err, ErrBlockedScheme)

	// 3. Redirect to private IP host
	req, _ = http.NewRequestWithContext(ctx, "GET", "http://127.0.0.1/admin", nil)
	err = checkRedirect(req, nil)
	require.ErrorIs(t, err, ErrBlockedHostname)

	// 4. Redirect to host that resolves to metadata IP
	req, _ = http.NewRequestWithContext(ctx, "GET", "http://metadata-trick.com/", nil)
	err = checkRedirect(req, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBlockedIP)

	// 5. Valid redirect
	req, _ = http.NewRequestWithContext(ctx, "GET", "http://safe.com/page2", nil)
	err = checkRedirect(req, nil)
	require.NoError(t, err)
}

func TestSafeDialerRejectsRealLocalhostServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprintln(w, "secret local data")
	}))
	defer ts.Close()

	limits := model.DefaultLimits()
	client := NewSafeHTTPClient(nil, limits)

	// Attempting to query the real local test server with production safe client MUST fail (SSRF guard)
	_, err := client.Get(ts.URL)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "connection blocked")
}

// permissiveTestPolicy allows loopback for testing internal HTTP pipelines against httptest
type permissiveTestPolicy struct{}

func (permissiveTestPolicy) IsBlockedIP(_ netip.Addr) bool {
	return false
}

func (permissiveTestPolicy) IsBlockedHostname(_ string) bool {
	return false
}

func TestSafeHTTPClientWithPermissivePolicy(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Custom", "ok")
		fmt.Fprintln(w, "hello world")
	}))
	defer ts.Close()

	limits := model.DefaultLimits()
	client := NewSafeHTTPClientWithPolicy(nil, permissiveTestPolicy{}, limits)

	resp, err := client.Get(ts.URL)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, "ok", resp.Header.Get("X-Custom"))
}
