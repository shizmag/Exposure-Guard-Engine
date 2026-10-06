package e2e

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
)

// ServerState defines the state of the synthetic website fixture.
type ServerState int32

const (
	StateA ServerState = 0
	StateB ServerState = 1
)

// SyntheticServer provides a controlled outside-in inspection target with two deterministic states.
type SyntheticServer struct {
	state  atomic.Int32
	server *httptest.Server
}

// NewSyntheticServer starts an in-process HTTP server simulating a real-world web application.
func NewSyntheticServer() *SyntheticServer {
	s := &SyntheticServer{}
	s.state.Store(int32(StateA))

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			// Subpath routing
			switch r.URL.Path {
			case "/about":
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `<!DOCTYPE html><html><body><h1>About Synthetic Corp</h1><a href="/">Home</a></body></html>`)
				return
			case "/new-portal":
				if s.CurrentState() == StateB {
					w.Header().Set("Content-Type", "text/html; charset=utf-8")
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `<!DOCTYPE html><html><body><h1>New Portal Exposed</h1></body></html>`)
					return
				}
				http.NotFound(w, r)
				return
			case "/api/v1/health":
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `{"status":"ok","version":"1.0.0"}`)
				return
			case "/robots.txt":
				w.Header().Set("Content-Type", "text/plain")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "User-agent: *\nDisallow: /admin/\nSitemap: /sitemap.xml\n")
				return
			case "/sitemap.xml":
				w.Header().Set("Content-Type", "application/xml")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, `<?xml version="1.0" encoding="UTF-8"?><urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>/about</loc></url></urlset>`)
				return
			case "/static/app.js":
				w.Header().Set("Content-Type", "application/javascript")
				w.WriteHeader(http.StatusOK)
				if s.CurrentState() == StateA {
					fmt.Fprint(w, `console.log("synthetic app initialized");
const apiEndpoint = "/api/v1/auth";
`)
				} else {
					fmt.Fprint(w, `console.log("synthetic app initialized");
const apiEndpoint = "/api/v1/auth";
//# sourceMappingURL=/static/app.js.map
`)
				}
				return
			case "/static/app.js.map":
				if s.CurrentState() == StateB {
					w.Header().Set("Content-Type", "application/json")
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `{
  "version": 3,
  "sources": ["src/index.ts", "src/auth.ts"],
  "sourcesContent": ["export const start = () => console.log('hello');", "export const auth = () => true;"],
  "mappings": "AAAA;"
}`)
					return
				}
				http.NotFound(w, r)
				return
			case "/.git/config":
				if s.CurrentState() == StateB {
					w.Header().Set("Content-Type", "text/plain")
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `[core]
repositoryformatversion = 0
filemode = true
bare = false
logallrefupdates = true
[remote "origin"]
url = git@github.com:example/repo.git
`)
					return
				}
				http.NotFound(w, r)
				return
			default:
				http.NotFound(w, r)
				return
			}
		}

		// Root page
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("X-Content-Type-Options", "nosniff")

		if s.CurrentState() == StateA {
			w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
    <title>Synthetic Test Website</title>
    <script src="/static/app.js"></script>
</head>
<body>
    <h1>Synthetic Test Corp</h1>
    <nav>
        <a href="/about">About</a>
        <a href="/api/v1/health">API Health</a>
    </nav>
</body>
</html>`)
		} else {
			// State B: CSP removed, new-portal link added
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<!DOCTYPE html>
<html>
<head>
    <title>Synthetic Test Website</title>
    <script src="/static/app.js"></script>
</head>
<body>
    <h1>Synthetic Test Corp</h1>
    <nav>
        <a href="/about">About</a>
        <a href="/new-portal">New Portal</a>
        <a href="/api/v1/health">API Health</a>
    </nav>
</body>
</html>`)
		}
	})

	s.server = httptest.NewServer(mux)
	return s
}

// URL returns the base URL of the synthetic server.
func (s *SyntheticServer) URL() string {
	return s.server.URL
}

// Close stops the synthetic server.
func (s *SyntheticServer) Close() {
	s.server.Close()
}

// SetState switches the synthetic server state.
func (s *SyntheticServer) SetState(st ServerState) {
	s.state.Store(int32(st))
}

// CurrentState returns the active state.
func (s *SyntheticServer) CurrentState() ServerState {
	return ServerState(s.state.Load())
}
