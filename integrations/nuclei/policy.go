package nuclei

import "strings"

const (
	CuratedProfileVersion = "v1.0-defensive"
)

// CuratedPolicy defines the defensive boundary for outside-in Nuclei checks.
type CuratedPolicy struct {
	AllowedTags       []string
	ExcludedTags      []string
	AllowedProtocols  []string
	ExcludedProtocols []string
	DisableInteractsh bool
	MaxRateLimit      int
}

// DefaultCuratedPolicy returns the defensive policy for ExposureGuard monitoring.
func DefaultCuratedPolicy() CuratedPolicy {
	return CuratedPolicy{
		AllowedTags: []string{
			"exposure",
			"misconfig",
			"misconfiguration",
			"config",
			"token",
			"artifact",
			"disclosure",
			"dev",
		},
		ExcludedTags: []string{
			"fuzz",
			"dos",
			"bruteforce",
			"brute-force",
			"intrusive",
			"oast",
			"interactsh",
			"rce",
			"code-execution",
			"headless",
			"active",
			"sqli",
			"xss",
			"lfi",
			"ssrf",
			"cve",
		},
		AllowedProtocols: []string{
			"http",
			"ssl",
			"dns",
		},
		ExcludedProtocols: []string{
			"headless",
			"tcp",
			"code",
			"workflow",
			"websocket",
		},
		DisableInteractsh: true,
		MaxRateLimit:      15,
	}
}

// BuildCLIArgs builds the command line filtering flags enforcing the curated policy.
func (p CuratedPolicy) BuildCLIArgs() []string {
	var args []string

	if len(p.AllowedTags) > 0 {
		args = append(args, "-tags", strings.Join(p.AllowedTags, ","))
	}
	if len(p.ExcludedTags) > 0 {
		args = append(args, "-etags", strings.Join(p.ExcludedTags, ","))
	}
	if len(p.AllowedProtocols) > 0 {
		args = append(args, "-pt", strings.Join(p.AllowedProtocols, ","))
	}
	if len(p.ExcludedProtocols) > 0 {
		args = append(args, "-ept", strings.Join(p.ExcludedProtocols, ","))
	}
	if p.DisableInteractsh {
		args = append(args, "-ni") // -no-interactsh
	}

	return args
}
