package httpx

import (
	"strconv"
	"strings"

	"github.com/exposureguard/exposureguard/pkg/integration"
	"github.com/exposureguard/exposureguard/pkg/model"
)

// Record represents a single JSONL event from httpx.
type Record struct {
	Timestamp     string   `json:"timestamp,omitempty"`
	URL           string   `json:"url"`
	Input         string   `json:"input"`
	Scheme        string   `json:"scheme"`
	Port          string   `json:"port"`
	Host          string   `json:"host"`
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title,omitempty"`
	ContentType   string   `json:"content_type,omitempty"`
	ContentLength int64    `json:"content_length,omitempty"`
	WebServer     string   `json:"webserver,omitempty"`
	Tech          []string `json:"tech,omitempty"`
	Location      string   `json:"location,omitempty"`
	Failed        bool     `json:"failed,omitempty"`
}

// MapRecord normalizes an httpx event into canonical Asset and Observation representations.
func MapRecord(rec Record, emit integration.Emitter) {
	if rec.Failed || rec.URL == "" {
		return
	}

	rawURL := strings.TrimSpace(rec.URL)
	canonicalURL := strings.ToLower(rawURL)

	attrs := map[string]string{
		"status_code": strconv.Itoa(rec.StatusCode),
		"source":      "httpx",
	}
	if rec.WebServer != "" {
		attrs["server"] = rec.WebServer
	}
	if rec.Title != "" {
		attrs["title"] = rec.Title
	}
	if rec.ContentType != "" {
		attrs["content_type"] = rec.ContentType
	}
	if len(rec.Tech) > 0 {
		attrs["technologies"] = strings.Join(rec.Tech, ",")
	}

	asset := model.Asset{
		Kind:          model.AssetKindURL,
		Value:         canonicalURL,
		URL:           canonicalURL,
		Source:        "httpx",
		DiscoveredVia: "probe",
		Attributes:    attrs,
	}
	emit.EmitAsset(asset)

	obsData := map[string]any{
		"url":            canonicalURL,
		"input":          rec.Input,
		"status_code":    rec.StatusCode,
		"title":          rec.Title,
		"content_type":   rec.ContentType,
		"content_length": rec.ContentLength,
		"webserver":      rec.WebServer,
		"technologies":   rec.Tech,
		"location":       rec.Location,
		"source":         "httpx",
	}

	obs := model.Observation{
		Kind:    "http.service_probe",
		Subject: canonicalURL,
		Data:    obsData,
	}
	emit.EmitObservation(obs)
}
