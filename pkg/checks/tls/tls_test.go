package tls

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type loopbackPermissivePolicy struct{}

func (loopbackPermissivePolicy) IsBlockedIP(_ netip.Addr) bool { return false }
func (loopbackPermissivePolicy) IsBlockedHostname(_ string) bool { return false }

func TestTLSCheckWithTestServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer ts.Close()

	host, portStr, err := net.SplitHostPort(ts.Listener.Addr().String())
	require.NoError(t, err)
	port, err := strconv.ParseUint(portStr, 10, 16)
	require.NoError(t, err)

	limits := model.DefaultLimits()
	limits.TLSHandshakeTimeoutSeconds = 5

	resolver := netguard.NewSafeResolverWithPolicy(nil, loopbackPermissivePolicy{})
	transport := netguard.NewSafeTransportWithPolicy(resolver, loopbackPermissivePolicy{}, limits)
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	client := &http.Client{Transport: transport, Timeout: 5 * time.Second}

	env := checks.NewEnvironmentWithPolicy(client, resolver, loopbackPermissivePolicy{}, limits, nil)
	target := model.Target{
		Raw:    ts.URL,
		URL:    ts.URL,
		Host:   host,
		Scheme: "https",
		Port:   uint16(port),
	}

	check := NewCheck()
	res, err := check.Run(t.Context(), env, target)
	require.NoError(t, err)

	require.NotEmpty(t, res.Observations)
	obs := res.Observations[0]
	assert.Equal(t, "tls_certificate", obs.Kind)
	assert.NotEmpty(t, obs.Data["fingerprint_sha256"])
	assert.NotEmpty(t, obs.Data["version"])
	assert.NotEmpty(t, obs.Data["cipher_suite"])
}
