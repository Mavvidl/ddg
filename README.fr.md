<p align="center">
  <img src="assets/ddg-lion.svg" alt="Lion DDG" width="96">
</p>
<h1 align="center">DDG — Détecteur-De-G</h1>
<p align="center"><b>Rust pour la collecte locale et la sécurité · Go pour la réactivité et le réseau</b></p>

<p align="center">
  <img src="assets/ddg-readme-banner.png" alt="Bannière du projet DDG" width="100%">
</p>

[English](README.md) · [Architecture](docs/README.md)

## Objectif

DDG analyse un processus à partir de son PID, de son nom ou de tous les processus. Le MVP fournit le nom, une petite description de son rôle, le chemin du binaire, CPU, mémoire, PID parent, utilisateur, SHA-256, application associée et une évaluation prudente de sa légitimité.

Avec `--lookup`, Go lance les vérifications en parallèle. La première intégration est VirusTotal via l'API v3 et la recherche du rapport du fichier à partir du hash. Le fichier n'est pas téléversé par ce MVP : seul son hash est envoyé au fournisseur.

## Architecture

```text
                     DDG (Go)
            CLI · réseau · rapports JSON/Texte
                        |
                   JSON-lines IPC
                        |
                  ddg-agent (Rust)
          processus · chemin · hash · heuristiques
                        |
                    OS local
                        |
                 VirusTotal (optionnel)
```

Rust protège la frontière bas niveau : collecte de processus, manipulation des chemins et calcul SHA-256 en streaming. Go gère la CLI, les requêtes concurrentes, les timeouts et les rapports.

## Quick start

Pré-requis : Go 1.23+, Rust stable, Cargo et Git. DDG doit être compilé sur
le même système d'exploitation que les processus à inspecter.

### Kali Linux

Installer les outils, cloner le dépôt et compiler les deux binaires :

```bash
sudo apt update
sudo apt install -y git golang rustc cargo
git clone https://github.com/Mavvidl/ddg.git
cd ddg
make build
```

Premier test local, sans accès réseau :

```bash
# Trouver un processus et récupérer un PID pour le test.
pgrep -n systemd

# Remplacer 1 par un PID renvoyé par pgrep, ps ou top.
./scripts/run.sh --pid 1 --text
./scripts/run.sh --name systemd --json
./scripts/run.sh --all --export report.json
```

Les noms `firefox` et `google-chrome` conviennent aussi si ces applications
sont installées. Si un processus n'est pas visible, relancer avec les droits
nécessaires, par exemple `sudo ./scripts/run.sh --all --text`.

### Windows PowerShell

Installer Git, Go et Rust avec leurs installateurs officiels, ouvrir PowerShell,
puis compiler les binaires Windows natifs :

```powershell
git clone https://github.com/Mavvidl/ddg.git
Set-Location ddg
.\scripts\build.ps1
```

Récupérer un PID et effectuer un premier test. Les binaires Windows portent
l'extension `.exe` :

```powershell
# Choisir un processus présent sur la machine.
$pid = (Get-Process explorer | Select-Object -First 1).Id
.\dist\ddg.exe --agent .\dist\ddg-agent.exe --pid $pid --text
.\dist\ddg.exe --agent .\dist\ddg-agent.exe --name explorer --json
.\dist\ddg.exe --agent .\dist\ddg-agent.exe --all --export report.json
```

Remplacer `explorer` par `Code`, `firefox` ou un nom renvoyé par
`Get-Process`. Ouvrir PowerShell en tant qu'administrateur si Windows refuse
l'accès à certains processus. Les binaires Kali/WSL ne permettent pas
d'inspecter les processus Windows natifs.

### Lookup VirusTotal optionnel

`--lookup` envoie uniquement le hash SHA-256 à VirusTotal. Définir la clé dans
le shell avant le lancement ; DDG ne charge pas automatiquement les fichiers
`.env` :

```bash
# Kali/Linux
export DDG_VT_API_KEY="votre_cle_ici"
./scripts/run.sh --name firefox --lookup --json
```

```powershell
# Windows PowerShell, pour la session courante uniquement
$env:DDG_VT_API_KEY = "votre_cle_ici"
.\dist\ddg.exe --agent .\dist\ddg-agent.exe --name explorer --lookup --json
```

Sans clé VirusTotal, utiliser les commandes locales ci-dessus. Ne jamais
committer la clé ni l'inclure dans un rapport exporté.

Pour lancer les tests automatisés après la compilation :

```bash
go test ./...
cargo test --manifest-path rust/ddg-agent/Cargo.toml
```

Pour afficher la syntaxe CLI :

```bash
./scripts/run.sh --help
```

## Signification du verdict

DDG ne doit pas transformer une hypothèse en certitude. `likely_legitimate` signifie seulement que plusieurs indices locaux sont cohérents. `unknown` est utilisé dès que les preuves sont insuffisantes. Le champ `signature_status` reste `not_checked` dans le MVP.

La prochaine étape de sécurité est une vraie vérification native des signatures numériques/PKI selon la plateforme.

## Commandes

```bash
ddg --pid 1234 --lookup --json
ddg --name firefox --text
ddg --all --lookup --export report.json
```

## Licence

MIT. Voir [LICENSE](LICENSE).
