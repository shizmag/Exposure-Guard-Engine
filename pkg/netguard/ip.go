package netguard

import (
	"errors"
	"net/netip"
	"strings"
)

var (
	// ErrBlockedIP indicates an IP address violates the public network policy (SSRF protection).
	ErrBlockedIP = errors.New("connection blocked: destination IP is private, loopback, or reserved")
	// ErrBlockedHostname indicates the hostname is known to target private/cloud infrastructure.
	ErrBlockedHostname = errors.New("connection blocked: destination hostname is restricted")
	// ErrBlockedScheme indicates an unsupported or unsafe protocol scheme.
	ErrBlockedScheme = errors.New("connection blocked: scheme is not http or https")
	// ErrTooManyRedirects indicates redirect limit exceeded.
	ErrTooManyRedirects = errors.New("connection blocked: maximum redirects exceeded")
)

var blockedPrefixes = []netip.Prefix{
	// IPv4 loopback & current network
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("0.0.0.0/8"),
	// IPv4 private (RFC 1918)
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	// IPv4 link-local & cloud metadata
	netip.MustParsePrefix("169.254.0.0/16"),
	// CGNAT (RFC 6598)
	netip.MustParsePrefix("100.64.0.0/10"),
	// IPv4 multicast & reserved
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	// IPv4 broadcast
	netip.MustParsePrefix("255.255.255.255/32"),
	// IPv6 loopback & unspecified
	netip.MustParsePrefix("::1/128"),
	netip.MustParsePrefix("::/128"),
	// IPv6 unique local (RFC 4193)
	netip.MustParsePrefix("fc00::/7"),
	// IPv6 link-local
	netip.MustParsePrefix("fe80::/10"),
	// IPv6 multicast
	netip.MustParsePrefix("ff00::/8"),
}

// NetworkPolicy defines network access rules for hostnames and IP addresses.
type NetworkPolicy interface {
	IsBlockedIP(addr netip.Addr) bool
	IsBlockedHostname(host string) bool
}

// DefaultNetworkPolicy implements strict public Internet enforcement.
type DefaultNetworkPolicy struct{}

// IsBlockedIP implements NetworkPolicy.
func (DefaultNetworkPolicy) IsBlockedIP(addr netip.Addr) bool {
	return IsBlockedIP(addr)
}

// IsBlockedHostname implements NetworkPolicy.
func (DefaultNetworkPolicy) IsBlockedHostname(host string) bool {
	return IsBlockedHostname(host)
}

// AllowPrivateNetworkPolicy permits private and loopback destinations for controlled local testing,
// while strictly maintaining blocks against cloud metadata and unspecified destinations.
type AllowPrivateNetworkPolicy struct{}

var cloudMetadataPrefix = netip.MustParsePrefix("169.254.0.0/16")

// IsBlockedIP implements NetworkPolicy for AllowPrivateNetworkPolicy.
func (AllowPrivateNetworkPolicy) IsBlockedIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}
	unmapped := addr.Unmap()
	if unmapped.IsUnspecified() || unmapped.IsLinkLocalUnicast() || unmapped.IsLinkLocalMulticast() {
		return true
	}
	return cloudMetadataPrefix.Contains(unmapped)
}

// IsBlockedHostname implements NetworkPolicy for AllowPrivateNetworkPolicy.
func (AllowPrivateNetworkPolicy) IsBlockedHostname(hostname string) bool {
	h := strings.ToLower(strings.TrimSpace(hostname))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return true
	}
	if h == "metadata.google.internal" || h == "metadata" || h == "instance-data" {
		return true
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		return (AllowPrivateNetworkPolicy{}).IsBlockedIP(addr)
	}
	return false
}

// IsBlockedIP tests if addr is in a private, loopback, link-local, or reserved range.
// It unmaps IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1) before evaluation.
func IsBlockedIP(addr netip.Addr) bool {
	if !addr.IsValid() {
		return true
	}

	// Canonicalize IPv4-in-IPv6 to pure IPv4
	unmapped := addr.Unmap()

	if unmapped.IsLoopback() ||
		unmapped.IsPrivate() ||
		unmapped.IsLinkLocalUnicast() ||
		unmapped.IsLinkLocalMulticast() ||
		unmapped.IsMulticast() ||
		unmapped.IsUnspecified() {
		return true
	}

	for _, prefix := range blockedPrefixes {
		if prefix.Contains(unmapped) {
			return true
		}
	}

	return false
}

// IsBlockedHostname tests if a hostname should be blocked immediately without DNS lookup.
func IsBlockedHostname(hostname string) bool {
	h := strings.ToLower(strings.TrimSpace(hostname))
	h = strings.TrimSuffix(h, ".")

	if h == "" {
		return true
	}

	if h == "localhost" || strings.HasSuffix(h, ".localhost") {
		return true
	}

	// Cloud metadata hostnames
	if h == "metadata.google.internal" ||
		h == "metadata" ||
		h == "instance-data" {
		return true
	}

	// If hostname is directly an IP literal, validate it
	if addr, err := netip.ParseAddr(h); err == nil {
		return IsBlockedIP(addr)
	}

	return false
}
