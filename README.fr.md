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

## Installation

Pré-requis : Go 1.23+, Rust stable et Cargo.

```bash
./scripts/build.sh
./dist/ddg --pid 1234 --text
./dist/ddg --pid 1234 --lookup --json
./dist/ddg --name firefox --text
./dist/ddg --all --lookup --export report.json
```

Pour VirusTotal, définir au préalable `DDG_VT_API_KEY`. Sans cette variable, le lookup reste désactivé proprement.

Sous Windows : `scripts/build.ps1`.

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
