# DDG threat model

## Assets

- process metadata
- executable path
- executable hash
- local account information
- online reputation result
- VirusTotal API key

## Threats

- malicious process names mimicking legitimate applications
- path spoofing and unusual Unicode paths
- permission-related blind spots
- stale or absent reputation data
- accidental API-key disclosure
- treating a reputation result as proof of legitimacy

## Design responses

- Rust computes SHA-256 from the executable file itself rather than trusting the name.
- Unknown processes remain unknown.
- Online errors and not-found responses are represented separately.
- API keys are read from environment variables and are never printed.
- The MVP never uploads executable bytes.
