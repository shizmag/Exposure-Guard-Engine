package model

// Limits defines execution and resource bounds for a scan.
type Limits struct {
	TotalTimeoutSeconds        int     `json:"total_timeout_seconds" koanf:"total_timeout_seconds"`
	RequestTimeoutSeconds      int     `json:"request_timeout_seconds" koanf:"request_timeout_seconds"`
	DNSTimeoutSeconds          int     `json:"dns_timeout_seconds" koanf:"dns_timeout_seconds"`
	TLSHandshakeTimeoutSeconds int     `json:"tls_handshake_timeout_seconds" koanf:"tls_handshake_timeout_seconds"`
	MaxRedirects               int     `json:"max_redirects" koanf:"max_redirects"`
	MaxDepth                   int     `json:"max_depth" koanf:"max_depth"`
	MaxPages                   int     `json:"max_pages" koanf:"max_pages"`
	MaxAssets                  int     `json:"max_assets" koanf:"max_assets"`
	MaxResponseBytes           int64   `json:"max_response_bytes" koanf:"max_response_bytes"`
	MaxTotalDownloadBytes      int64   `json:"max_total_download_bytes" koanf:"max_total_download_bytes"`
	MaxConcurrency             int     `json:"max_concurrency" koanf:"max_concurrency"`
	MaxPerHostConcurrency      int     `json:"max_per_host_concurrency" koanf:"max_per_host_concurrency"`
	RequestsPerSecondPerHost   float64 `json:"requests_per_second_per_host" koanf:"requests_per_second_per_host"`
}

// DefaultLimits provides production-safe defaults.
func DefaultLimits() Limits {
	return Limits{
		TotalTimeoutSeconds:        120,
		RequestTimeoutSeconds:      10,
		DNSTimeoutSeconds:          5,
		TLSHandshakeTimeoutSeconds: 7,
		MaxRedirects:               8,
		MaxDepth:                   2,
		MaxPages:                   100,
		MaxAssets:                  500,
		MaxResponseBytes:           4 * 1024 * 1024,  // 4 MiB
		MaxTotalDownloadBytes:      50 * 1024 * 1024, // 50 MiB
		MaxConcurrency:             8,
		MaxPerHostConcurrency:      4,
		RequestsPerSecondPerHost:   2.0,
	}
}

// HardLimits defines upper bounds that cannot be exceeded by client config.
func HardLimits() Limits {
	return Limits{
		TotalTimeoutSeconds:        300,
		RequestTimeoutSeconds:      30,
		DNSTimeoutSeconds:          15,
		TLSHandshakeTimeoutSeconds: 15,
		MaxRedirects:               15,
		MaxDepth:                   5,
		MaxPages:                   500,
		MaxAssets:                  2000,
		MaxResponseBytes:           16 * 1024 * 1024,  // 16 MiB
		MaxTotalDownloadBytes:      200 * 1024 * 1024, // 200 MiB
		MaxConcurrency:             32,
		MaxPerHostConcurrency:      8,
		RequestsPerSecondPerHost:   10.0,
	}
}

// Clamp ensures user-supplied limits do not violate hard safety bounds.
func (l *Limits) Clamp() {
	def := DefaultLimits()
	hard := HardLimits()

	if l.TotalTimeoutSeconds <= 0 {
		l.TotalTimeoutSeconds = def.TotalTimeoutSeconds
	} else if l.TotalTimeoutSeconds > hard.TotalTimeoutSeconds {
		l.TotalTimeoutSeconds = hard.TotalTimeoutSeconds
	}

	if l.RequestTimeoutSeconds <= 0 {
		l.RequestTimeoutSeconds = def.RequestTimeoutSeconds
	} else if l.RequestTimeoutSeconds > hard.RequestTimeoutSeconds {
		l.RequestTimeoutSeconds = hard.RequestTimeoutSeconds
	}

	if l.DNSTimeoutSeconds <= 0 {
		l.DNSTimeoutSeconds = def.DNSTimeoutSeconds
	} else if l.DNSTimeoutSeconds > hard.DNSTimeoutSeconds {
		l.DNSTimeoutSeconds = hard.DNSTimeoutSeconds
	}

	if l.TLSHandshakeTimeoutSeconds <= 0 {
		l.TLSHandshakeTimeoutSeconds = def.TLSHandshakeTimeoutSeconds
	} else if l.TLSHandshakeTimeoutSeconds > hard.TLSHandshakeTimeoutSeconds {
		l.TLSHandshakeTimeoutSeconds = hard.TLSHandshakeTimeoutSeconds
	}

	if l.MaxRedirects <= 0 {
		l.MaxRedirects = def.MaxRedirects
	} else if l.MaxRedirects > hard.MaxRedirects {
		l.MaxRedirects = hard.MaxRedirects
	}

	if l.MaxDepth < 0 {
		l.MaxDepth = def.MaxDepth
	} else if l.MaxDepth > hard.MaxDepth {
		l.MaxDepth = hard.MaxDepth
	}

	if l.MaxPages <= 0 {
		l.MaxPages = def.MaxPages
	} else if l.MaxPages > hard.MaxPages {
		l.MaxPages = hard.MaxPages
	}

	if l.MaxAssets <= 0 {
		l.MaxAssets = def.MaxAssets
	} else if l.MaxAssets > hard.MaxAssets {
		l.MaxAssets = hard.MaxAssets
	}

	if l.MaxResponseBytes <= 0 {
		l.MaxResponseBytes = def.MaxResponseBytes
	} else if l.MaxResponseBytes > hard.MaxResponseBytes {
		l.MaxResponseBytes = hard.MaxResponseBytes
	}

	if l.MaxTotalDownloadBytes <= 0 {
		l.MaxTotalDownloadBytes = def.MaxTotalDownloadBytes
	} else if l.MaxTotalDownloadBytes > hard.MaxTotalDownloadBytes {
		l.MaxTotalDownloadBytes = hard.MaxTotalDownloadBytes
	}

	if l.MaxConcurrency <= 0 {
		l.MaxConcurrency = def.MaxConcurrency
	} else if l.MaxConcurrency > hard.MaxConcurrency {
		l.MaxConcurrency = hard.MaxConcurrency
	}

	if l.MaxPerHostConcurrency <= 0 {
		l.MaxPerHostConcurrency = def.MaxPerHostConcurrency
	} else if l.MaxPerHostConcurrency > hard.MaxPerHostConcurrency {
		l.MaxPerHostConcurrency = hard.MaxPerHostConcurrency
	}

	if l.RequestsPerSecondPerHost <= 0 {
		l.RequestsPerSecondPerHost = def.RequestsPerSecondPerHost
	} else if l.RequestsPerSecondPerHost > hard.RequestsPerSecondPerHost {
		l.RequestsPerSecondPerHost = hard.RequestsPerSecondPerHost
	}
}
