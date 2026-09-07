package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/example/ddg/internal/models"
)

type VirusTotal struct {
	APIKey  string
	Client  *http.Client
	BaseURL string
}

func NewVirusTotal() *VirusTotal {
	return &VirusTotal{
		APIKey:  os.Getenv("DDG_VT_API_KEY"),
		Client:  &http.Client{Timeout: 10 * time.Second},
		BaseURL: "https://www.virustotal.com/api/v3",
	}
}

func (v *VirusTotal) Enabled() bool { return strings.TrimSpace(v.APIKey) != "" }

func (v *VirusTotal) Check(ctx context.Context, sha256 string) models.OnlineCheck {
	result := models.OnlineCheck{Provider: "virustotal", Status: "skipped"}
	if !v.Enabled() {
		result.Details = "DDG_VT_API_KEY is missing. No secret is sent."
		return result
	}
	if sha256 == "" {
		result.Status = "unavailable"
		result.Details = "SHA-256 is unavailable for this process."
		return result
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, v.BaseURL+"/files/"+sha256, nil)
	if err != nil {
		result.Status = "error"
		result.Details = err.Error()
		return result
	}
	req.Header.Set("x-apikey", v.APIKey)
	resp, err := v.Client.Do(req)
	if err != nil {
		result.Status = "error"
		result.Details = err.Error()
		return result
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		result.Status = "not_found"
		result.Reputation = "unknown"
		result.URL = "https://www.virustotal.com/gui/file/" + sha256
		return result
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		result.Status = "error"
		result.Details = fmt.Sprintf("VirusTotal HTTP %d", resp.StatusCode)
		return result
	}

	var payload struct {
		Data struct {
			ID         string `json:"id"`
			Attributes struct {
				LastAnalysisStats struct {
					Harmless   int `json:"harmless"`
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
				} `json:"last_analysis_stats"`
				Reputation int `json:"reputation"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		result.Status = "error"
		result.Details = err.Error()
		return result
	}

	result.Status = "found"
	result.Reputation = fmt.Sprintf("%d", payload.Data.Attributes.Reputation)
	result.HarmlessCount = &payload.Data.Attributes.LastAnalysisStats.Harmless
	result.MaliciousCount = &payload.Data.Attributes.LastAnalysisStats.Malicious
	result.SuspiciousCount = &payload.Data.Attributes.LastAnalysisStats.Suspicious
	detection := payload.Data.Attributes.LastAnalysisStats.Malicious + payload.Data.Attributes.LastAnalysisStats.Suspicious
	result.DetectionCount = &detection
	result.URL = "https://www.virustotal.com/gui/file/" + sha256
	return result
}
