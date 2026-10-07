package dns

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"sort"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/checks"
	"github.com/exposureguard/exposureguard/pkg/model"
)

// Check implements the DNS records inspection module.
type Check struct{}

// NewCheck returns an instantiated DNS check.
func NewCheck() *Check {
	return &Check{}
}

func (c *Check) ID() string    { return "dns.records" }
func (c *Check) Name() string  { return "DNS Records Inspection" }
func (c *Check) Stage() string { return "dns" }

// Record holds normalized representation of a DNS entry.
type Record struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	Value string `json:"value"`
	TTL   uint32 `json:"ttl,omitempty"`
}

func (c *Check) Run(ctx context.Context, env *checks.Environment, target model.Target) (checks.Result, error) {
	var result checks.Result
	host := target.Host

	resolver := net.DefaultResolver

	var records []Record
	discoveredHosts := make(map[string]bool)

	// 1. A & AAAA records via safe env resolver
	if addrs, err := env.DNS.LookupNetIP(ctx, "ip", host); err == nil {
		for _, addr := range addrs {
			recType := "A"
			if addr.Is6() {
				recType = "AAAA"
			}
			records = append(records, Record{
				Type:  recType,
				Name:  host,
				Value: addr.String(),
			})
		}
	}

	// 2. CNAME
	if cname, err := resolver.LookupCNAME(ctx, host); err == nil {
		cnameClean := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(cname)), ".")
		if cnameClean != "" && cnameClean != host {
			records = append(records, Record{
				Type:  "CNAME",
				Name:  host,
				Value: cnameClean,
			})
			discoveredHosts[cnameClean] = true
		}
	}

	// 3. MX
	if mxRecords, err := resolver.LookupMX(ctx, host); err == nil {
		for _, mx := range mxRecords {
			mxHost := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(mx.Host)), ".")
			records = append(records, Record{
				Type:  "MX",
				Name:  host,
				Value: fmt.Sprintf("%d %s", mx.Pref, mxHost),
			})
			if mxHost != "" {
				discoveredHosts[mxHost] = true
			}
		}
	}

	// 4. TXT
	if txtRecords, err := resolver.LookupTXT(ctx, host); err == nil {
		for _, txt := range txtRecords {
			records = append(records, Record{
				Type:  "TXT",
				Name:  host,
				Value: txt,
			})
		}
	}

	// 5. NS
	if nsRecords, err := resolver.LookupNS(ctx, host); err == nil {
		for _, ns := range nsRecords {
			nsHost := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(ns.Host)), ".")
			records = append(records, Record{
				Type:  "NS",
				Name:  host,
				Value: nsHost,
			})
			if nsHost != "" {
				discoveredHosts[nsHost] = true
			}
		}
	}

	// Sort records deterministically by Type then Value
	sort.Slice(records, func(i, j int) bool {
		if records[i].Type != records[j].Type {
			return records[i].Type < records[j].Type
		}
		return records[i].Value < records[j].Value
	})

	// Build Observations
	for _, rec := range records {
		obsID := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("dns:%s:%s:%s", rec.Type, rec.Name, rec.Value))))
		result.Observations = append(result.Observations, model.Observation{
			ID:      obsID,
			Kind:    "dns_record",
			Scope:   "dns",
			Subject: rec.Name,
			Data: map[string]any{
				"record_type": rec.Type,
				"name":        rec.Name,
				"value":       rec.Value,
			},
		})
	}

	// Build Assets for discovered hosts
	for h := range discoveredHosts {
		assetID := fmt.Sprintf("%x", sha256.Sum256([]byte("hostname:"+h)))
		result.Assets = append(result.Assets, model.Asset{
			ID:            assetID,
			Kind:          model.AssetKindHostname,
			Value:         h,
			Source:        "dns",
			DiscoveredVia: "dns_record",
		})
	}

	// Sort assets deterministically
	sort.Slice(result.Assets, func(i, j int) bool {
		return result.Assets[i].Value < result.Assets[j].Value
	})

	return result, nil
}
