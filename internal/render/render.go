package render

import (
	"encoding/json"
	"fmt"
	"github.com/example/ddg/internal/models"
	"os"
	"strings"
)

func JSON(report models.Report) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func Text(report models.Report) {
	fmt.Printf("DDG %s | cible=%s\n\n", report.ToolVersion, report.Target)
	for _, p := range report.Processes {
		fmt.Printf("[%d] %s\n", p.PID, p.Name)
		fmt.Printf("  Description : %s\n", p.Description)
		fmt.Printf("  Exécutable  : %s\n", deref(p.Executable))
		fmt.Printf("  Mémoire     : %d bytes\n", p.MemoryBytes)
		fmt.Printf("  CPU         : %.2f%%\n", p.CPUPercent)
		fmt.Printf("  Application : %s (%s)\n", deref(p.Application.Name), deref(p.Application.Publisher))
		fmt.Printf("  Légitimité  : %s / confiance=%s\n", p.Legitimacy.Status, p.Legitimacy.Confidence)
		if len(p.Legitimacy.Reasons) > 0 {
			fmt.Printf("  Motifs      : %s\n", strings.Join(p.Legitimacy.Reasons, "; "))
		}
		for _, c := range p.OnlineChecks {
			fmt.Printf("  Online/%s   : %s", c.Provider, c.Status)
			if c.DetectionCount != nil {
				fmt.Printf(" | detections=%d", *c.DetectionCount)
			}
			if c.URL != "" {
				fmt.Printf(" | %s", c.URL)
			}
			fmt.Println()
		}
		fmt.Println()
	}
}

func deref(v *string) string {
	if v == nil || *v == "" {
		return "unknown"
	}
	return *v
}
