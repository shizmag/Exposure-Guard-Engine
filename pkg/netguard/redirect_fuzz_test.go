package netguard

import (
	"context"
	"net/http"
	"testing"
)

func FuzzRedirectValidation(f *testing.F) {
	seeds := []string{
		"http://example.com/login",
		"https://example.com/path",
		"http://127.0.0.1/admin",
		"http://localhost:8080/",
		"http://169.254.169.254/latest/meta-data",
		"file:///etc/passwd",
		"gopher://evil.com",
		"https://[::1]/",
		"ftp://anonymous@ftp.com",
	}

	for _, s := range seeds {
		f.Add(s)
	}

	checkFn := NewSafeCheckRedirect(8, nil)

	f.Fuzz(func(t *testing.T, redirectURL string) {
		req, err := http.NewRequestWithContext(context.Background(), "GET", redirectURL, nil)
		if err != nil {
			return
		}

		_ = checkFn(req, nil)
	})
}
