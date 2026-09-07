package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/example/ddg/internal/api"
	"github.com/example/ddg/internal/models"
	"github.com/example/ddg/internal/render"
)

const version = "0.1.0"

func main() {
	pid := flag.Uint("pid", 0, "PID à inspecter")
	name := flag.String("name", "", "nom du processus à rechercher")
	all := flag.Bool("all", false, "inspecter tous les processus")
	lookup := flag.Bool("lookup", false, "faire les vérifications en ligne en arrière-plan")
	jsonOut := flag.Bool("json", false, "sortie JSON")
	textOut := flag.Bool("text", false, "sortie texte")
	export := flag.String("export", "", "écrire le rapport JSON dans un fichier")
	agent := flag.String("agent", "", "chemin vers ddg-agent")
	flag.Parse()

	if !*jsonOut && !*textOut {
		*textOut = true
	}
	count := 0
	if *pid != 0 {
		count++
	}
	if *name != "" {
		count++
	}
	if *all {
		count++
	}
	if count != 1 {
		fatal("utilise exactement une cible: --pid, --name ou --all")
	}

	target, err := queryAgent(*agent, *pid, *name, *all)
	if err != nil {
		fatal(err.Error())
	}

	if *lookup {
		var wg sync.WaitGroup
		vt := api.NewVirusTotal()
		if len(target) > 0 {
			for i := range target {
				if !vt.Enabled() && i == 0 && !*jsonOut {
					fmt.Fprintln(os.Stderr, "[DDG] lookup VirusTotal désactivé: DDG_VT_API_KEY absent")
				}
				wg.Add(1)
				go func(idx int) {
					defer wg.Done()
					ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
					defer cancel()
					sha := ""
					if target[idx].SHA256 != nil {
						sha = *target[idx].SHA256
					}
					target[idx].OnlineChecks = append(target[idx].OnlineChecks, vt.Check(ctx, sha))
				}(i)
			}
		}
		wg.Wait()
	}

	now := time.Now().UTC()
	report := models.Report{ToolVersion: version, GeneratedAt: now, Target: targetLabel(*pid, *name, *all), Processes: target}
	if *export != "" {
		data, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			fatal(err.Error())
		}
		if err := os.WriteFile(*export, append(data, '\n'), 0600); err != nil {
			fatal(err.Error())
		}
	}
	if *jsonOut {
		if err := render.JSON(report); err != nil {
			fatal(err.Error())
		}
	}
	if *textOut {
		render.Text(report)
	}
}

func queryAgent(agentPath string, pid uint, name string, all bool) ([]models.ProcessInfo, error) {
	if agentPath == "" {
		agentPath = defaultAgentPath()
	}
	if _, err := os.Stat(agentPath); err != nil {
		return nil, fmt.Errorf("ddg-agent introuvable: %s (utilise --agent ou compile scripts/build.sh)", agentPath)
	}
	var req map[string]any
	switch {
	case pid != 0:
		req = map[string]any{"op": "process_by_pid", "pid": pid}
	case name != "":
		req = map[string]any{"op": "process_by_name", "name": name}
	default:
		req = map[string]any{"op": "all"}
	}
	payload, _ := json.Marshal(req)
	cmd := exec.Command(agentPath)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	if _, err := stdin.Write(append(payload, '\n')); err != nil {
		return nil, err
	}
	stdin.Close()
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		errText, _ := bufio.NewReader(stderr).ReadString('\n')
		_ = cmd.Wait()
		return nil, errors.New("ddg-agent: " + strings.TrimSpace(errText))
	}
	line := scanner.Text()
	if err := cmd.Wait(); err != nil {
		return nil, err
	}
	var resp struct {
		OK    bool            `json:"ok"`
		Data  json.RawMessage `json:"data"`
		Error string          `json:"error"`
	}
	if err := json.Unmarshal([]byte(line), &resp); err != nil {
		return nil, err
	}
	if !resp.OK {
		return nil, errors.New(resp.Error)
	}
	if pid != 0 {
		var one models.ProcessInfo
		if err := json.Unmarshal(resp.Data, &one); err != nil {
			return nil, err
		}
		return []models.ProcessInfo{one}, nil
	}
	var many []models.ProcessInfo
	if err := json.Unmarshal(resp.Data, &many); err != nil {
		return nil, err
	}
	return many, nil
}

func defaultAgentPath() string {
	exe, _ := os.Executable()
	base := filepath.Dir(exe)
	for _, p := range []string{filepath.Join(base, "ddg-agent"), filepath.Join(base, "ddg-agent.exe"), "./ddg-agent", "./ddg-agent.exe"} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "ddg-agent"
}
func targetLabel(pid uint, name string, all bool) string {
	if pid != 0 {
		return "pid:" + strconv.Itoa(int(pid))
	}
	if name != "" {
		return "name:" + name
	}
	if all {
		return "all"
	}
	return "unknown"
}
func fatal(msg string) { fmt.Fprintln(os.Stderr, "ddg:", msg); os.Exit(2) }
