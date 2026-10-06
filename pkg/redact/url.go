package redact

import (
	"net/url"
	"strings"
)

var sensitiveQueryParams = map[string]bool{
	"token":         true,
	"access_token":  true,
	"id_token":      true,
	"refresh_token": true,
	"api_key":       true,
	"apikey":        true,
	"secret":        true,
	"secret_key":    true,
	"password":      true,
	"passwd":        true,
	"auth":          true,
	"key":           true,
}

// RedactURL strips userinfo passwords and masks sensitive query parameters in raw URLs.
func RedactURL(raw string) string {
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u = CleanURL(u)
	return u.String()
}

// CleanURL sanitizes userinfo and sensitive query params in-place on a parsed URL.
func CleanURL(u *url.URL) *url.URL {
	if u == nil {
		return nil
	}

	// Redact user info credentials
	if u.User != nil {
		if _, hasPass := u.User.Password(); hasPass {
			u.User = url.UserPassword(u.User.Username(), "REDACTED")
		} else if u.User.Username() != "" && strings.Contains(strings.ToLower(u.User.Username()), "token") {
			u.User = url.User("REDACTED")
		}
	}

	// Redact sensitive query parameters
	if u.RawQuery != "" {
		q := u.Query()
		modified := false
		for k := range q {
			if sensitiveQueryParams[strings.ToLower(k)] {
				q.Set(k, "REDACTED")
				modified = true
			}
		}
		if modified {
			u.RawQuery = q.Encode()
		}
	}

	return u
}
