// crypto.rs — Couche cryptographique de l'agent Mythos
//
// Miroir exact du module crypto du serveur Go.
// Les deux implémentent le même protocole :
//   ECDH P-256 → HKDF-SHA256 → AES-256-GCM
//
// L'agent génère sa paire ECDH au démarrage.
// La clé privée ne quitte JAMAIS la mémoire de l'agent.

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use hkdf::Hkdf;
use p256::{
    ecdh::EphemeralSecret,
    PublicKey, EncodedPoint
};
use rand::RngCore;
use sha2::Sha256;
use serde::{Deserialize, Serialize};

// ─────────────────────────────────────────────────────────────
// ECDH Key Exchange
// ─────────────────────────────────────────────────────────────

/// Paire de clés ECDH P-256 de l'agent
pub struct AgentKeyPair {
    secret: EphemeralSecret,
    pub public_key_bytes: Vec<u8>,
}

impl AgentKeyPair {
    /// Génère une nouvelle paire de clés ECDH
    /// Appelé UNE FOIS au démarrage de l'agent
    pub fn generate() -> Self {
        let secret = EphemeralSecret::random(&mut OsRng);
        let public_key = EncodedPoint::from(secret.public_key());
        let public_key_bytes = public_key.as_bytes().to_vec();

        AgentKeyPair {
            secret,
            public_key_bytes,
        }
    }

    /// Retourne la clé publique encodée en base64
    /// C'est ce qui est envoyé au serveur lors du register
    pub fn public_key_b64(&self) -> String {
        BASE64.encode(&self.public_key_bytes)
    }

    /// Dérive la clé de session à partir de la clé publique du serveur
    ///
    /// Processus :
    ///   1. ECDH : agent_private × server_public → shared_secret
    ///   2. HKDF-SHA256(shared_secret) → session_key (32 bytes)
    ///
    /// Le résultat est identique à ce que le serveur Go calcule de son côté.
    pub fn derive_session_key(self, server_pub_key_b64: &str) -> Result<Vec<u8>, String> {
        // Décoder la clé publique du serveur
        let server_pub_bytes = BASE64
            .decode(server_pub_key_b64)
            .map_err(|e| format!("base64 decode: {}", e))?;

        let server_pub_key = PublicKey::from_sec1_bytes(&server_pub_bytes)
            .map_err(|e| format!("public key decode: {}", e))?;

        // Calcul ECDH → shared secret
        let shared_secret = self.secret.diffie_hellman(&server_pub_key);

        // HKDF-SHA256 pour dériver la clé AES — DOIT correspondre au Go
        let hkdf = Hkdf::<Sha256>::new(
            Some(b"mythos-c2-salt-v1"),   // salt — identique au serveur Go
            shared_secret.raw_secret_bytes(),
        );

        let mut session_key = vec![0u8; 32];
        hkdf.expand(b"mythos-session-key", &mut session_key) // info — identique au Go
            .map_err(|e| format!("HKDF expand: {}", e))?;

        Ok(session_key)
    }
}

// ─────────────────────────────────────────────────────────────
// AES-256-GCM
// ─────────────────────────────────────────────────────────────

/// Chiffre des données avec AES-256-GCM
///
/// Format de sortie : [ nonce (12 bytes) | ciphertext + tag ]
/// Identique au format du serveur Go → déchiffrement transparent
pub fn encrypt(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("AES key error: {}", e))?;

    // Nonce aléatoire de 12 bytes
    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from(nonce_bytes);

    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|e| format!("AES-GCM encrypt: {}", e))?;

    // Préfixer avec le nonce
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    Ok(result)
}

/// Déchiffre et vérifie l'intégrité d'un message AES-256-GCM
pub fn decrypt(key: &[u8], ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    if ciphertext.len() < 12 {
        return Err("ciphertext too short".into());
    }

    let cipher = Aes256Gcm::new_from_slice(key)
        .map_err(|e| format!("AES key error: {}", e))?;

    let nonce_arr: [u8; 12] = ciphertext[..12].try_into()
        .map_err(|_| "invalid nonce length")?;
    let nonce = Nonce::from(nonce_arr);
    let data = &ciphertext[12..];

    cipher
        .decrypt(&nonce, data)
        .map_err(|e| format!("AES-GCM decrypt (bad key or tampered): {}", e))
}

/// Chiffre une struct sérialisable en JSON puis encode en base64
pub fn encrypt_json_b64<T: Serialize>(key: &[u8], value: &T) -> Result<String, String> {
    let json = serde_json::to_vec(value)
        .map_err(|e| format!("JSON serialize: {}", e))?;
    let encrypted = encrypt(key, &json)?;
    Ok(BASE64.encode(&encrypted))
}

/// Décode base64, déchiffre, puis désérialise depuis JSON
pub fn decrypt_json_b64<T: for<'de> Deserialize<'de>>(
    key: &[u8],
    encoded: &str,
) -> Result<T, String> {
    let ciphertext = BASE64
        .decode(encoded)
        .map_err(|e| format!("base64 decode: {}", e))?;
    let plaintext = decrypt(key, &ciphertext)?;
    serde_json::from_slice(&plaintext)
        .map_err(|e| format!("JSON deserialize: {}", e))
}
