$ErrorActionPreference = 'Stop'
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
New-Item -ItemType Directory -Force dist | Out-Null
cargo build --release --manifest-path rust/ddg-agent/Cargo.toml
Copy-Item rust/ddg-agent/target/release/ddg-agent.exe dist/ddg-agent.exe -Force
$env:CGO_ENABLED='0'
go build -trimpath -ldflags '-s -w' -o dist/ddg.exe ./cmd/ddg
Write-Host 'Built dist/ddg.exe and dist/ddg-agent.exe'
