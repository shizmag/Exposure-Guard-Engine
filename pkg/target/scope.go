package target

import (
	"net/url"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/model"
	"golang.org/x/net/publicsuffix"
)

// Scope classifies relation of arbitrary URLs or hostnames to the scan target.
type Scope struct {
	Target model.Target
}

// Relation classifies how an asset relates to the primary target.
type Relation string

const (
	RelationSameHost   Relation = "same_host"
	RelationSameDomain Relation = "same_domain"
	RelationThirdParty Relation = "third_party"
)

// NewScope returns a Scope checker for target.
func NewScope(t model.Target) Scope {
	return Scope{Target: t}
}

// CheckHostname determines relation of a hostname to the target.
func (s Scope) CheckHostname(hostname string) Relation {
	h := strings.ToLower(strings.TrimSpace(hostname))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return RelationThirdParty
	}

	if h == s.Target.Host {
		return RelationSameHost
	}

	d, err := publicsuffix.EffectiveTLDPlusOne(h)
	if err == nil && d == s.Target.Domain {
		return RelationSameDomain
	}

	return RelationThirdParty
}

// CheckURL parses and determines relation of a URL string to the target.
func (s Scope) CheckURL(rawURL string) (Relation, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return RelationThirdParty, err
	}
	return s.CheckHostname(u.Hostname()), nil
}

// IsAllowedCrawl returns true only for exact same-host targets.
func (s Scope) IsAllowedCrawl(rawURL string) bool {
	rel, err := s.CheckURL(rawURL)
	if err != nil {
		return false
	}
	return rel == RelationSameHost
}
