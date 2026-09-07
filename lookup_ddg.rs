use serde::{Deserialize, Serialize};

/// Résultat d'une recherche de réputation externe pour un binaire donné.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct LookupResult {
    pub source: String,
    pub queried_hash: Option<String>,
    pub known: bool,
    pub malicious_votes: Option<u32>,
    pub harmless_votes: Option<u32>,
    pub reputation_label: String,
    pub vendor_names: Vec<String>,
    pub notes: Option<String>,
}

impl LookupResult {
    fn unavailable(reason: &str) -> Self {
        LookupResult {
            source: "none".to_string(),
            queried_hash: None,
            known: false,
            malicious_votes: None,
            harmless_votes: None,
            reputation_label: "unknown".to_string(),
            vendor_names: vec![],
            notes: Some(reason.to_string()),
        }
    }
}

/// Point d'entrée du lookup. Pour l'instant branché sur VirusTotal (API v3, endpoint /files/{hash}).
/// Nécessite la variable d'environnement DDG_VT_API_KEY.
/// Conçu pour être remplacé/étendu par une base interne ou NVD dans une itération suivante.
pub fn lookup_hash(sha256: &str) -> LookupResult {
    let api_key = match std::env::var("DDG_VT_API_KEY") {
        Ok(k) if !k.trim().is_empty() => k,
        _ => {
            return LookupResult::unavailable(
                "Aucune clé API configurée (variable d'environnement DDG_VT_API_KEY manquante).",
            )
        }
    };

    let url = format!("https://www.virustotal.com/api/v3/files/{sha256}");
    let resp = ureq::get(&url)
        .set("x-apikey", &api_key)
        .timeout(std::time::Duration::from_secs(10))
        .call();

    let resp = match resp {
        Ok(r) => r,
        Err(ureq::Error::Status(404, _)) => {
            return LookupResult {
                source: "virustotal".to_string(),
                queried_hash: Some(sha256.to_string()),
                known: false,
                malicious_votes: None,
                harmless_votes: None,
                reputation_label: "not_found".to_string(),
                vendor_names: vec![],
                notes: Some("Hash inconnu de VirusTotal.".to_string()),
            }
        }
        Err(ureq::Error::Status(code, _)) => {
            return LookupResult::unavailable(&format!("Réponse API : {code}"))
        }
        Err(e) => return LookupResult::unavailable(&format!("Requête échouée : {e}")),
    };

    let json: serde_json::Value = match resp.into_json() {
        Ok(v) => v,
        Err(e) => return LookupResult::unavailable(&format!("Réponse illisible : {e}")),
    };

    let stats = &json["data"]["attributes"]["last_analysis_stats"];
    let malicious = stats["malicious"].as_u64().unwrap_or(0) as u32;
    let harmless = stats["harmless"].as_u64().unwrap_or(0) as u32;

    let label = if malicious > 5 {
        "malicious"
    } else if malicious > 0 {
        "suspicious"
    } else {
        "clean"
    };

    let vendor_names: Vec<String> = json["data"]["attributes"]["last_analysis_results"]
        .as_object()
        .map(|results| {
            results
                .iter()
                .filter(|(_, v)| v["category"] == "malicious")
                .map(|(vendor, _)| vendor.clone())
                .take(10)
                .collect()
        })
        .unwrap_or_default();

    LookupResult {
        source: "virustotal".to_string(),
        queried_hash: Some(sha256.to_string()),
        known: true,
        malicious_votes: Some(malicious),
        harmless_votes: Some(harmless),
        reputation_label: label.to_string(),
        vendor_names,
        notes: None,
    }
}
