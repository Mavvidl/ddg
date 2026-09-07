use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{fs::File, io::{self, BufRead, BufReader, Read}, path::Path};
use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

#[derive(Debug, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
enum Request {
    ProcessByPid { pid: u32 },
    ProcessByName { name: String },
    All,
}

#[derive(Debug, Serialize)]
struct ProcessInfo {
    pid: u32,
    ppid: Option<u32>,
    name: String,
    description: String,
    executable: Option<String>,
    command_line: Vec<String>,
    cwd: Option<String>,
    user: Option<String>,
    memory_bytes: u64,
    virtual_memory_bytes: u64,
    cpu_percent: f32,
    start_time_unix: u64,
    sha256: Option<String>,
    application: ApplicationInfo,
    legitimacy: Legitimacy,
}

#[derive(Debug, Serialize)]
struct ApplicationInfo {
    name: Option<String>,
    publisher: Option<String>,
    category: Option<String>,
}

#[derive(Debug, Serialize)]
struct Legitimacy {
    status: String,
    confidence: String,
    reasons: Vec<String>,
    signature_status: String,
}

fn main() -> anyhowless::Result<()> {
    let stdin = io::stdin();
    let reader = BufReader::new(stdin.lock());
    for line in reader.lines() {
        let line = line?;
        if line.trim().is_empty() { continue; }
        let request: Request = serde_json::from_str(&line)
            .map_err(|e| anyhowless::Error::Message(format!("invalid request: {e}")))?;
        match handle(request) {
            Ok(value) => println!("{}", serde_json::to_string(&json!({"ok": true, "data": value}))?),
            Err(err) => println!("{}", serde_json::to_string(&json!({"ok": false, "error": err.to_string()}))?),
        }
    }
    Ok(())
}

fn handle(request: Request) -> anyhowless::Result<Value> {
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::All,
        true,
        ProcessRefreshKind::nothing()
            .with_cpu()
            .with_memory()
            .with_cmd(sysinfo::ProcessRefreshKind::nothing().cmd()),
    );

    match request {
        Request::ProcessByPid { pid } => {
            let process = system.process(Pid::from_u32(pid)).ok_or_else(|| anyhowless::Error::Message(format!("process {pid} not found")))?;
            Ok(serde_json::to_value(inspect_process(process))?)
        }
        Request::ProcessByName { name } => {
            let needle = name.to_lowercase();
            let matches: Vec<ProcessInfo> = system.processes().values()
                .filter(|p| p.name().to_string_lossy().to_lowercase().contains(&needle))
                .map(inspect_process)
                .collect();
            Ok(serde_json::to_value(matches)?)
        }
        Request::All => {
            let matches: Vec<ProcessInfo> = system.processes().values().map(inspect_process).collect();
            Ok(serde_json::to_value(matches)?)
        }
    }
}

fn inspect_process(process: &sysinfo::Process) -> ProcessInfo {
    let name = process.name().to_string_lossy().to_string();
    let executable = process.exe().map(path_to_string);
    let sha256 = executable.as_deref().and_then(hash_file);
    let application = identify_application(&name, executable.as_deref());
    let legitimacy = assess_legitimacy(executable.as_deref(), &application);
    ProcessInfo {
        pid: process.pid().as_u32(),
        ppid: process.parent().map(|p| p.as_u32()),
        name: name.clone(),
        description: describe_process(&name, application.category.as_deref()),
        executable,
        command_line: process.cmd().iter().map(|v| v.to_string_lossy().to_string()).collect(),
        cwd: process.cwd().map(path_to_string),
        user: process.user_id().map(|u| u.to_string_lossy().to_string()),
        memory_bytes: process.memory(),
        virtual_memory_bytes: process.virtual_memory(),
        cpu_percent: process.cpu_usage(),
        start_time_unix: process.start_time(),
        sha256,
        application,
        legitimacy,
    }
}

fn describe_process(name: &str, category: Option<&str>) -> String {
    let n = name.to_lowercase();
    let known = match n.as_str() {
        "firefox" | "firefox.exe" => Some("Navigateur web Firefox : accès aux sites et applications internet."),
        "chrome" | "chrome.exe" | "google-chrome" => Some("Navigateur web Chromium/Chrome : affichage de pages, extensions et applications web."),
        "code" | "code.exe" => Some("Visual Studio Code : éditeur de code et extensions de développement."),
        "explorer.exe" => Some("Explorateur Windows : gestion des fichiers, dossiers et interface du bureau."),
        "systemd" => Some("Gestionnaire de démarrage et de services du système Linux."),
        "sshd" => Some("Serveur SSH : accepte et gère des connexions distantes sécurisées."),
        "dockerd" => Some("Moteur Docker : exécute et gère des conteneurs."),
        _ => None,
    };
    known.map(str::to_owned).unwrap_or_else(|| match category {
        Some("browser") => "Processus associé à un navigateur web.".to_owned(),
        Some("development") => "Processus associé à un outil de développement.".to_owned(),
        Some("system") => "Processus lié aux fonctions du système d'exploitation.".to_owned(),
        _ => "Fonction non déterminée automatiquement ; DDG recommande de vérifier l'éditeur, le chemin et la réputation du fichier.".to_owned(),
    })
}

fn identify_application(name: &str, executable: Option<&str>) -> ApplicationInfo {
    let n = name.to_lowercase();
    let lower_path = executable.unwrap_or_default().to_lowercase();
    if n.contains("firefox") { return ApplicationInfo { name: Some("Mozilla Firefox".into()), publisher: Some("Mozilla".into()), category: Some("browser".into()) }; }
    if n.contains("chrome") { return ApplicationInfo { name: Some("Google Chrome / Chromium".into()), publisher: Some("Google / Chromium".into()), category: Some("browser".into()) }; }
    if n == "code" || n == "code.exe" || lower_path.contains("visual studio code") { return ApplicationInfo { name: Some("Visual Studio Code".into()), publisher: Some("Microsoft".into()), category: Some("development".into()) }; }
    if n == "explorer.exe" { return ApplicationInfo { name: Some("Windows Explorer".into()), publisher: Some("Microsoft".into()), category: Some("system".into()) }; }
    if lower_path.starts_with("/usr/bin/") || lower_path.starts_with("/bin/") || lower_path.contains("\\windows\\system32\\") {
        return ApplicationInfo { name: Some("OS component / system binary".into()), publisher: None, category: Some("system".into()) };
    }
    ApplicationInfo { name: None, publisher: None, category: None }
}

fn assess_legitimacy(executable: Option<&str>, app: &ApplicationInfo) -> Legitimacy {
    let mut reasons = Vec::new();
    let Some(path) = executable else {
        return Legitimacy { status: "unknown".into(), confidence: "low".into(), reasons: vec!["Chemin du binaire inaccessible.".into()], signature_status: "not_checked".into() };
    };
    let p = path.to_lowercase();
    let trusted_path = p.starts_with("/usr/bin/") || p.starts_with("/usr/sbin/") || p.starts_with("/system/library/") || p.starts_with("/applications/") || p.contains("\\windows\\system32\\") || p.contains("\\program files\\");
    if trusted_path { reasons.push("Chemin correspondant à un répertoire système ou programme courant.".into()); }
    if app.name.is_some() { reasons.push("Application reconnue par la base heuristique locale.".into()); }
    if trusted_path && app.name.is_some() {
        Legitimacy { status: "likely_legitimate".into(), confidence: "medium".into(), reasons, signature_status: "not_checked".into() }
    } else {
        reasons.push("Aucune preuve cryptographique de confiance n'est évaluée par ce MVP.".into());
        Legitimacy { status: "unknown".into(), confidence: "low".into(), reasons, signature_status: "not_checked".into() }
    }
}

fn hash_file(path: &str) -> Option<String> {
    let metadata = std::fs::metadata(path).ok()?;
    if !metadata.is_file() { return None; }
    // Limite volontaire : le hash est calculé en streaming pour ne pas charger le binaire en RAM.
    let mut file = File::open(Path::new(path)).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 1024 * 128];
    loop {
        let n = file.read(&mut buffer).ok()?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }
    Some(hex::encode(hasher.finalize()))
}

fn path_to_string(path: &Path) -> String { path.to_string_lossy().into_owned() }

// Tiny local replacement to keep the agent's error surface explicit without a heavier runtime.
mod anyhowless {
    use std::{error::Error as StdError, fmt};
    #[derive(Debug)] pub enum Error { Message(String), Io(std::io::Error), Json(serde_json::Error) }
    impl fmt::Display for Error { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { match self { Self::Message(s) => write!(f, "{s}"), Self::Io(e) => write!(f, "{e}"), Self::Json(e) => write!(f, "{e}") } } }
    impl StdError for Error {}
    impl From<std::io::Error> for Error { fn from(e: std::io::Error) -> Self { Self::Io(e) } }
    impl From<serde_json::Error> for Error { fn from(e: serde_json::Error) -> Self { Self::Json(e) } }
    pub type Result<T> = std::result::Result<T, Error>;
}
