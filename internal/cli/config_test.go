package cli

import (
	"io"
	"strings"
	"testing"
)

func TestParseArgsDefaultsToTextOutput(t *testing.T) {
	cfg, err := ParseArgs([]string{"--pid", "42"}, io.Discard, io.Discard)
	if err != nil {
		t.Fatalf("ParseArgs returned error: %v", err)
	}
	if !cfg.TextOut {
		t.Fatalf("expected default text output to be enabled")
	}
	if cfg.JSONOut {
		t.Fatalf("json output should be disabled by default")
	}
}

func TestParseArgsRejectsMultipleTargets(t *testing.T) {
	_, err := ParseArgs([]string{"--pid", "42", "--name", "firefox"}, io.Discard, io.Discard)
	if err == nil {
		t.Fatal("expected error when multiple targets are passed")
	}
	if !strings.Contains(err.Error(), "exactly one target") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestTargetLabel(t *testing.T) {
	cases := []struct {
		name   string
		cfg    Config
		wanted string
	}{
		{name: "pid", cfg: Config{PID: 12}, wanted: "pid:12"},
		{name: "name", cfg: Config{Name: "firefox"}, wanted: "name:firefox"},
		{name: "all", cfg: Config{All: true}, wanted: "all"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.cfg.TargetLabel(); got != tc.wanted {
				t.Fatalf("TargetLabel() = %q, want %q", got, tc.wanted)
			}
		})
	}
}
