package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVirusTotalCheckParsesStats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "test-key" {
			t.Fatalf("missing api key")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"data":{"id":"abc","attributes":{"reputation":12,"last_analysis_stats":{"harmless":65,"malicious":1,"suspicious":2}}}}`))
	}))
	defer srv.Close()

	vt := &VirusTotal{APIKey: "test-key", Client: srv.Client(), BaseURL: srv.URL}
	got := vt.Check(context.Background(), "abc")
	if got.Status != "found" {
		t.Fatalf("status=%q", got.Status)
	}
	if got.DetectionCount == nil || *got.DetectionCount != 3 {
		t.Fatalf("detection count=%v", got.DetectionCount)
	}
	if got.MaliciousCount == nil || *got.MaliciousCount != 1 {
		t.Fatalf("malicious=%v", got.MaliciousCount)
	}
}

func TestVirusTotalCheckNotFoundIsNotMalicious(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	vt := &VirusTotal{APIKey: "test-key", Client: srv.Client(), BaseURL: srv.URL}
	got := vt.Check(context.Background(), "unknown")
	if got.Status != "not_found" {
		t.Fatalf("status=%q", got.Status)
	}
	if got.Reputation != "unknown" {
		t.Fatalf("reputation=%q", got.Reputation)
	}
}
