package nuclei

import "strings"

const (
	CuratedProfileVersion   = "v1.0-defensive"
	CuratedTemplatesVersion = "10.5.0"
	CuratedRulesetSHA256    = "9d9645adf0d134ecd593489cdbff384460e143761878c488ff415bdede7164b0"
	CuratedRulesetPath      = "profiles/nuclei/v1/manifest.json"
)

// CuratedTemplateIDs defines the deterministic, safety-audited set of Nuclei template IDs
// permitted for outside-in defensive reconnaissance against pinned nuclei-templates 10.5.0.
var CuratedTemplateIDs = []string{
	"git-config",
	"env-file",
	"git-head",
	"ds-store",
	"backup-files",
	"docker-compose-exposure",
	"phpinfo-files",
	"security-txt",
	"robots-txt-disclosure",
	"sitemap-xml-disclosure",
	"svn-entries",
	"aws-credentials-exposure",
	"tls-version",
	"ssl-dns-names",
	"certificate-expiry",
}

// CuratedPolicy defines the defensive boundary for outside-in Nuclei checks.
type CuratedPolicy struct {
	AllowedTemplateIDs []string
	AllowedTags        []string
	ExcludedTags       []string
	AllowedProtocols   []string
	ExcludedProtocols  []string
	DisableInteractsh  bool
	MaxRateLimit       int
}

// DefaultCuratedPolicy returns the defensive policy for ExposureGuard monitoring.
func DefaultCuratedPolicy() CuratedPolicy {
	return CuratedPolicy{
		AllowedTemplateIDs: CuratedTemplateIDs,
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

	if len(p.AllowedTemplateIDs) > 0 {
		args = append(args, "-id", strings.Join(p.AllowedTemplateIDs, ","))
	}
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
