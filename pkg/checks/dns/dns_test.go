package dns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockDNSResolver struct {
	fn func(ctx context.Context, network, host string) ([]netip.Addr, error)
}

func (m *mockDNSResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	return m.fn(ctx, network, host)
}

func TestDNSCheck(t *testing.T) {
	mock := &mockDNSResolver{
		fn: func(_ context.Context, _, _ string) ([]netip.Addr, error) {
			return []netip.Addr{
				netip.MustParseAddr("93.184.216.34"),
				netip.MustParseAddr("2606:2800:220:1:248:1893:25c8:1946"),
			}, nil
		},
	}

	env := checks.NewEnvironment(nil, mock, model.DefaultLimits(), nil)
	target := model.Target{
		Raw:    "example.com",
		URL:    "https://example.com/",
		Host:   "example.com",
		Scheme: "https",
		Port:   443,
	}

	check := NewCheck()
	assert.Equal(t, "dns.records", check.ID())
	assert.Equal(t, "dns", check.Stage())

	res, err := check.Run(context.Background(), env, target)
	require.NoError(t, err)

	assert.NotEmpty(t, res.Observations)
	foundA := false
	foundAAAA := false
	for _, obs := range res.Observations {
		if obs.Kind == "dns_record" {
			if obs.Data["record_type"] == "A" && obs.Data["value"] == "93.184.216.34" {
				foundA = true
			}
			if obs.Data["record_type"] == "AAAA" {
				foundAAAA = true
			}
		}
	}
	assert.True(t, foundA, "A record must be found in observations")
	assert.True(t, foundAAAA, "AAAA record must be found in observations")
}
