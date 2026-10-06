package netguard_test

import (
	"net/netip"
	"testing"

	"github.com/exposureguard/exposureguard/pkg/netguard"
	"github.com/stretchr/testify/assert"
)

func TestDefaultNetworkPolicyBlocksDestinations(t *testing.T) {
	policy := netguard.DefaultNetworkPolicy{}

	blockedIPs := []string{
		"169.254.169.254",        // AWS/GCP/Azure Cloud Metadata
		"169.254.1.1",            // Link-Local IPv4
		"127.0.0.1",              // Loopback IPv4
		"127.0.0.2",              // Loopback IPv4
		"10.0.0.1",               // RFC 1918 Class A
		"172.16.0.1",             // RFC 1918 Class B
		"192.168.1.1",            // RFC 1918 Class C
		"100.64.0.1",             // CGNAT Shared Address Space
		"0.0.0.0",                // Current network
		"::1",                    // Loopback IPv6
		"fe80::1",                // Link-Local IPv6
		"fc00::1",                // Unique Local IPv6 (ULA)
		"::ffff:169.254.169.254", // IPv4-mapped IPv6 Metadata
		"::ffff:127.0.0.1",       // IPv4-mapped IPv6 Loopback
		"::ffff:10.0.0.1",        // IPv4-mapped IPv6 RFC 1918
	}

	for _, ipStr := range blockedIPs {
		addr, err := netip.ParseAddr(ipStr)
		if !assert.NoError(t, err, "failed to parse test IP %s", ipStr) {
			continue
		}
		assert.True(t, policy.IsBlockedIP(addr), "DefaultNetworkPolicy must block %s", ipStr)
		assert.True(t, policy.IsBlockedHostname(ipStr), "DefaultNetworkPolicy must block hostname %s", ipStr)
	}

	blockedHostnames := []string{
		"localhost",
		"sub.localhost",
		"metadata.google.internal",
		"metadata",
		"instance-data",
	}

	for _, host := range blockedHostnames {
		assert.True(t, policy.IsBlockedHostname(host), "DefaultNetworkPolicy must block hostname %s", host)
	}

	allowedIPs := []string{
		"93.184.216.34",   // example.com
		"1.1.1.1",         // Cloudflare DNS
		"8.8.8.8",         // Google DNS
		"2606:4700::6810", // Public IPv6
	}

	for _, ipStr := range allowedIPs {
		addr, err := netip.ParseAddr(ipStr)
		if !assert.NoError(t, err, "failed to parse test IP %s", ipStr) {
			continue
		}
		assert.False(t, policy.IsBlockedIP(addr), "DefaultNetworkPolicy must allow public IP %s", ipStr)
		assert.False(t, policy.IsBlockedHostname(ipStr), "DefaultNetworkPolicy must allow public hostname %s", ipStr)
	}
}

func TestAllowPrivatePolicyDefenseAgainstMetadata(t *testing.T) {
	policy := netguard.AllowPrivateNetworkPolicy{}

	// Must ALLOW loopback and RFC1918 for local synthetic tests
	allowedForTesting := []string{
		"127.0.0.1",
		"localhost",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
	}

	for _, host := range allowedForTesting {
		if addr, err := netip.ParseAddr(host); err == nil {
			assert.False(t, policy.IsBlockedIP(addr), "AllowPrivateNetworkPolicy should allow test IP %s", host)
		}
		assert.False(t, policy.IsBlockedHostname(host), "AllowPrivateNetworkPolicy should allow test host %s", host)
	}

	// Must STRICTLY CONTINUE BLOCKING Cloud Metadata and Unspecified
	strictlyBlockedMetadata := []string{
		"169.254.169.254",
		"169.254.0.1",
		"0.0.0.0",
		"::ffff:169.254.169.254",
	}

	for _, ipStr := range strictlyBlockedMetadata {
		addr, err := netip.ParseAddr(ipStr)
		if !assert.NoError(t, err, "failed to parse test IP %s", ipStr) {
			continue
		}
		assert.True(t, policy.IsBlockedIP(addr), "AllowPrivateNetworkPolicy must CONTINUE blocking metadata IP %s", ipStr)
		assert.True(t, policy.IsBlockedHostname(ipStr), "AllowPrivateNetworkPolicy must CONTINUE blocking metadata host %s", ipStr)
	}

	strictlyBlockedHostnames := []string{
		"metadata.google.internal",
		"metadata",
		"instance-data",
	}

	for _, host := range strictlyBlockedHostnames {
		assert.True(t, policy.IsBlockedHostname(host), "AllowPrivateNetworkPolicy must CONTINUE blocking hostname %s", host)
	}
}
