package models

import "time"

type ProcessInfo struct {
	PID                uint32          `json:"pid"`
	PPID               *uint32         `json:"ppid,omitempty"`
	Name               string          `json:"name"`
	Description        string          `json:"description"`
	Executable         *string         `json:"executable,omitempty"`
	CommandLine        []string        `json:"command_line,omitempty"`
	CWD                *string         `json:"cwd,omitempty"`
	User               *string         `json:"user,omitempty"`
	MemoryBytes        uint64          `json:"memory_bytes"`
	VirtualMemoryBytes uint64          `json:"virtual_memory_bytes"`
	CPUPercent         float64         `json:"cpu_percent"`
	StartTimeUnix      uint64          `json:"start_time_unix"`
	SHA256             *string         `json:"sha256,omitempty"`
	Application        ApplicationInfo `json:"application"`
	Legitimacy         Legitimacy      `json:"legitimacy"`
	OnlineChecks       []OnlineCheck   `json:"online_checks,omitempty"`
	CheckedAt          *time.Time      `json:"checked_at,omitempty"`
}

type ApplicationInfo struct {
	Name      *string `json:"name,omitempty"`
	Publisher *string `json:"publisher,omitempty"`
	Category  *string `json:"category,omitempty"`
}

type Legitimacy struct {
	Status          string   `json:"status"`
	Confidence      string   `json:"confidence"`
	Reasons         []string `json:"reasons"`
	SignatureStatus string   `json:"signature_status"`
}

type OnlineCheck struct {
	Provider        string `json:"provider"`
	Status          string `json:"status"`
	Reputation      string `json:"reputation,omitempty"`
	DetectionCount  *int   `json:"detection_count,omitempty"`
	HarmlessCount   *int   `json:"harmless_count,omitempty"`
	MaliciousCount  *int   `json:"malicious_count,omitempty"`
	SuspiciousCount *int   `json:"suspicious_count,omitempty"`
	URL             string `json:"url,omitempty"`
	Details         string `json:"details,omitempty"`
}

type Report struct {
	ToolVersion string        `json:"tool_version"`
	GeneratedAt time.Time     `json:"generated_at"`
	Target      string        `json:"target"`
	Processes   []ProcessInfo `json:"processes"`
	Warnings    []string      `json:"warnings,omitempty"`
}
