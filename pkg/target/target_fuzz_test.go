package target

import (
	"testing"
)

func FuzzParseTarget(f *testing.F) {
	seeds := []string{
		"example.com",
		"https://example.com",
		"http://sub.domain.co.uk:8080/path?query=1#frag",
		"https://[::1]:8443",
		"http://127.0.0.1:80",
		"ftp://malformed",
		"javascript:alert(1)",
		"http://user:pass@host:80/path",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, input string) {
		res, err := Parse(input)
		if err != nil {
			return
		}

		if res.URL == "" || res.Host == "" || res.Port == 0 || res.Scheme == "" {
			t.Fatalf("Parse produced invalid non-empty target without error for %q: %+v", input, res)
		}
	})
}
