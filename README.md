<p align="center">
  <img src="assets/ddg-lion.svg" alt="DDG lion" width="96">
</p>
<h1 align="center">DDG</h1>
<p align="center"><b>Rust pour la collecte locale et la sécurité · Go pour l'orchestration, la réactivité et le réseau</b></p>




[Français](README.fr.md) · [Architecture](docs/README.md)

## What DDG does

DDG inspects a process by PID, name or globally. The MVP returns the process name, what it appears to do, executable path, CPU, memory, parent PID, user, SHA-256, local application association and a deliberately conservative legitimacy assessment.

With `--lookup`, Go launches concurrent online reputation checks. The first integration is VirusTotal's file-report API, queried by the binary hash. DDG does not upload the file in this MVP: only its hash is sent to the provider.

## Architecture

```text
                +-----------------------+
                |       ddg (Go)        |
                | CLI + rendering + API |
                +-----------+-----------+
                            |
                     JSON-lines IPC
                            |
                +-----------v-----------+
                |   ddg-agent (Rust)    |
                | process + hash + trust |
                +-----------+-----------+
                            |
                    local OS process
                            |
                +-----------v-----------+
                |  Online reputation    |
                | VirusTotal (optional) |
                +-----------------------+
```

Rust is deliberately responsible for the low-level boundary: process inspection, path handling and streaming SHA-256. Go owns the user-facing flow, concurrent lookups and report formatting.

## Quick start

Requirements: Go 1.23+, Rust stable, Cargo and Git. DDG must be compiled on the
same operating system as the processes it inspects.

### Kali Linux

Install the toolchain, clone the repository and build both DDG binaries:

```bash
sudo apt update
sudo apt install -y git golang rustc cargo
git clone https://github.com/Mavvidl/ddg.git
cd ddg
make build
```

Run a first local test without any network access. The target can be a known
process name or a PID from the current machine:

```bash
# Find a process and keep one PID for the test.
pgrep -n systemd

# Replace 1 with a PID returned by pgrep, ps or top.
./scripts/run.sh --pid 1 --text
./scripts/run.sh --name systemd --json
./scripts/run.sh --all --export report.json
```

The same commands work with a desktop process such as `firefox` or
`google-chrome`. If a process is not visible, retry from a shell with the
necessary privileges, for example `sudo ./scripts/run.sh --all --text`.

### Windows PowerShell

Install Git, Go and Rust with their official installers, open PowerShell, then
build the native Windows binaries:

```powershell
git clone https://github.com/Mavvidl/ddg.git
Set-Location ddg
.\scripts\build.ps1
```

Get a PID and run a first local test. PowerShell uses `\` in paths and the
generated files have the `.exe` extension:

```powershell
# Pick a process that is present on the machine.
$pid = (Get-Process explorer | Select-Object -First 1).Id
.\dist\ddg.exe --agent .\dist\ddg-agent.exe --pid $pid --text
.\dist\ddg.exe --agent .\dist\ddg-agent.exe --name explorer --json
.\dist\ddg.exe --agent .\dist\ddg-agent.exe --all --export report.json
```

Replace `explorer` with `Code`, `firefox` or another process returned by
`Get-Process`. Start PowerShell as Administrator if Windows denies access to
some processes. Native Windows builds should be tested from Windows itself;
Kali/WSL binaries do not inspect native Windows processes.

### Optional VirusTotal lookup

`--lookup` sends only the SHA-256 hash to VirusTotal. Set the key in the shell
before running the command; DDG does not load `.env` files automatically:

```bash
# Kali/Linux
export DDG_VT_API_KEY="your_key_here"
./scripts/run.sh --name firefox --lookup --json
```

```powershell
# Windows PowerShell (current session only)
$env:DDG_VT_API_KEY = "your_key_here"
.\dist\ddg.exe --agent .\dist\ddg-agent.exe --name explorer --lookup --json
```

Without a VirusTotal key, use the local commands above. Never commit the key
or include it in an exported report.

To run the automated tests after building:

```bash
go test ./...
cargo test --manifest-path rust/ddg-agent/Cargo.toml
```

For the CLI syntax, use:

```bash
./scripts/run.sh --help
```

## Example JSON

```json
{
  "pid": 1234,
  "name": "firefox.exe",
  "description": "Navigateur web Firefox : accès aux sites et applications internet.",
  "executable": "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
  "memory_bytes": 257638400,
  "cpu_percent": 2.31,
  "sha256": "...",
  "application": {
    "name": "Mozilla Firefox",
    "publisher": "Mozilla",
    "category": "browser"
  },
  "legitimacy": {
    "status": "likely_legitimate",
    "confidence": "medium",
    "signature_status": "not_checked"
  },
  "online_checks": [
    {
      "provider": "virustotal",
      "status": "found",
      "detection_count": 0
    }
  ]
}
```

## Important security behavior

`likely_legitimate` is a heuristic, not a cryptographic guarantee. Unknown processes remain `unknown`. The MVP also reports `signature_status=not_checked`; native Windows/macOS/Linux signature verification belongs to the next security phase.

Do not put API keys in source code or reports. Prefer environment variables or a platform secret store.

## Roadmap

Phase 1: local process details + SHA-256.

Phase 2: online reputation providers and cached background enrichment.

Phase 3: native signature/PKI verification, CSV/SIEM output, policy engine.

Phase 4: richer application database, YARA/IOC integrations, long-running daemon mode, signed releases.

## License

MIT. See [LICENSE](LICENSE).
