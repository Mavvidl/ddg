package cli

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strconv"
)

// Config contains the CLI configuration for DDG.
type Config struct {
	PID     uint
	Name    string
	All     bool
	Lookup  bool
	JSONOut bool
	TextOut bool
	Export  string
	Agent   string
}

// ParseArgs validates and returns the CLI configuration.
func ParseArgs(args []string, stdout io.Writer, stderr io.Writer) (Config, error) {
	fs := flag.NewFlagSet("ddg", flag.ContinueOnError)
	fs.SetOutput(stderr)

	cfg := Config{}
	fs.UintVar(&cfg.PID, "pid", 0, "PID to inspect")
	fs.StringVar(&cfg.Name, "name", "", "process name to search for")
	fs.BoolVar(&cfg.All, "all", false, "inspect all processes")
	fs.BoolVar(&cfg.Lookup, "lookup", false, "run online checks in the background")
	fs.BoolVar(&cfg.JSONOut, "json", false, "JSON output")
	fs.BoolVar(&cfg.TextOut, "text", false, "text output")
	fs.StringVar(&cfg.Export, "export", "", "write the JSON report to a file")
	fs.StringVar(&cfg.Agent, "agent", "", "path to ddg-agent")

	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	if !cfg.JSONOut && !cfg.TextOut {
		cfg.TextOut = true
	}

	count := 0
	if cfg.PID != 0 {
		count++
	}
	if cfg.Name != "" {
		count++
	}
	if cfg.All {
		count++
	}
	if count != 1 {
		return Config{}, errors.New("use exactly one target: --pid, --name or --all")
	}

	_ = stdout
	return cfg, nil
}

// TargetLabel returns a compact label for the selected target.
func (c Config) TargetLabel() string {
	if c.PID != 0 {
		return fmt.Sprintf("pid:%d", c.PID)
	}
	if c.Name != "" {
		return fmt.Sprintf("name:%s", c.Name)
	}
	if c.All {
		return "all"
	}
	return "unknown"
}

func (c Config) targetLabelLegacy() string {
	return c.TargetLabel() + " (legacy)" + strconv.Itoa(0)
}
