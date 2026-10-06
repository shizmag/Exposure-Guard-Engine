package target

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/model"
	"golang.org/x/net/publicsuffix"
)

// Parse normalizes a user or machine target string into a canonical model.Target.
// It handles raw hostnames, scheme-less inputs, default ports, and domain extraction.
func Parse(input string) (model.Target, error) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return model.Target{}, fmt.Errorf("target input cannot be empty")
	}

	// If scheme is missing, default to https://
	toParse := raw
	if !strings.Contains(toParse, "://") {
		toParse = "https://" + toParse
	}

	u, err := url.Parse(toParse)
	if err != nil {
		return model.Target{}, fmt.Errorf("invalid target URL: %w", err)
	}

	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return model.Target{}, fmt.Errorf("unsupported target scheme: %s (only http and https are allowed)", scheme)
	}

	host := strings.ToLower(u.Hostname())
	// Strip trailing dot if present (FQDN)
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return model.Target{}, fmt.Errorf("target host cannot be empty")
	}

	var port uint16
	portStr := u.Port()
	if portStr != "" {
		p, err := strconv.ParseUint(portStr, 10, 16)
		if err != nil || p == 0 {
			return model.Target{}, fmt.Errorf("invalid target port: %s", portStr)
		}
		port = uint16(p)
	} else {
		if scheme == "http" {
			port = 80
		} else {
			port = 443
		}
	}

	// Registrable domain extraction
	domain, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		// Fallback for IP addresses or special local domains
		domain = host
	}

	// Build canonical URL
	var hostPort string
	if (scheme == "http" && port == 80) || (scheme == "https" && port == 443) {
		hostPort = host
	} else {
		hostPort = net.JoinHostPort(host, strconv.Itoa(int(port)))
	}

	canonicalURL := fmt.Sprintf("%s://%s", scheme, hostPort)
	if u.Path != "" && u.Path != "/" {
		canonicalURL += u.Path
	} else {
		canonicalURL += "/"
	}

	return model.Target{
		Raw:    raw,
		URL:    canonicalURL,
		Scheme: scheme,
		Host:   host,
		Port:   port,
		Domain: domain,
	}, nil
}
