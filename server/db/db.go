// Package db — Couche persistance de Mythos C2
//
// Utilise SQLite via mattn/go-sqlite3 pour la portabilité.
// Tout est stocké localement sur le team server.
// Les données sensibles (clés de session) ne sont JAMAIS persistées sur disque.

package db

import (
	"database/sql"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
	"github.com/sherko/mythos-c2/server/models"
)

// Database — wrapper autour de la connexion SQLite
type Database struct {
	conn *sql.DB
}

// New — ouvre ou crée la base de données Mythos
func New(path string) (*Database, error) {
	conn, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_foreign_keys=on")
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	db := &Database{conn: conn}
	if err := db.migrate(); err != nil {
		return nil, fmt.Errorf("migration failed: %w", err)
	}

	return db, nil
}

// migrate — crée les tables si elles n'existent pas encore
func (db *Database) migrate() error {
	schema := `
	-- Agents enregistrés
	CREATE TABLE IF NOT EXISTS agents (
		id           TEXT PRIMARY KEY,
		hostname     TEXT NOT NULL,
		username     TEXT NOT NULL,
		os           TEXT,
		arch         TEXT,
		pid          INTEGER,
		process_name TEXT,
		internal_ip  TEXT,
		external_ip  TEXT,
		is_admin     INTEGER DEFAULT 0,
		integrity    TEXT,
		domain       TEXT,
		first_seen   DATETIME NOT NULL,
		last_seen    DATETIME NOT NULL,
		beacon_int   INTEGER DEFAULT 60,
		jitter       INTEGER DEFAULT 20,
		status       TEXT DEFAULT 'active',
		listener_id  TEXT,
		tags         TEXT DEFAULT '[]'
	);

	-- Tâches envoyées aux agents
	CREATE TABLE IF NOT EXISTS tasks (
		id          TEXT PRIMARY KEY,
		agent_id    TEXT NOT NULL REFERENCES agents(id),
		type        TEXT NOT NULL,
		payload     TEXT,
		status      TEXT DEFAULT 'pending',
		created_at  DATETIME NOT NULL,
		sent_at     DATETIME,
		done_at     DATETIME,
		result      TEXT,
		operator_id TEXT,
		error       TEXT
	);

	-- Opérateurs (membres de l'équipe Red Team)
	CREATE TABLE IF NOT EXISTS operators (
		id            TEXT PRIMARY KEY,
		username      TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role          TEXT DEFAULT 'operator',
		last_login    DATETIME,
		created_at    DATETIME NOT NULL
	);

	-- Listeners actifs
	CREATE TABLE IF NOT EXISTS listeners (
		id         TEXT PRIMARY KEY,
		name       TEXT NOT NULL,
		type       TEXT NOT NULL,
		host       TEXT NOT NULL,
		port       INTEGER NOT NULL,
		profile    TEXT,
		tls_cert   TEXT,
		tls_key    TEXT,
		active     INTEGER DEFAULT 1,
		created_at DATETIME NOT NULL
	);

	-- Log d'événements (audit trail)
	CREATE TABLE IF NOT EXISTS events (
		id          TEXT PRIMARY KEY,
		type        TEXT NOT NULL,
		agent_id    TEXT,
		operator_id TEXT,
		message     TEXT NOT NULL,
		timestamp   DATETIME NOT NULL
	);

	-- Index pour les requêtes fréquentes
	CREATE INDEX IF NOT EXISTS idx_tasks_agent    ON tasks(agent_id, status);
	CREATE INDEX IF NOT EXISTS idx_tasks_status   ON tasks(status);
	CREATE INDEX IF NOT EXISTS idx_events_agent   ON events(agent_id);
	CREATE INDEX IF NOT EXISTS idx_events_time    ON events(timestamp);
	`

	_, err := db.conn.Exec(schema)
	return err
}

// ─────────────────────────────────────────────────────────────
// AGENTS
// ─────────────────────────────────────────────────────────────

// SaveAgent — insère ou met à jour un agent
func (db *Database) SaveAgent(a *models.Agent) error {
	_, err := db.conn.Exec(`
		INSERT INTO agents (
			id, hostname, username, os, arch, pid, process_name,
			internal_ip, external_ip, is_admin, integrity, domain,
			first_seen, last_seen, beacon_int, jitter, status, listener_id
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO UPDATE SET
			hostname=excluded.hostname, username=excluded.username,
			pid=excluded.pid, process_name=excluded.process_name,
			internal_ip=excluded.internal_ip, external_ip=excluded.external_ip,
			is_admin=excluded.is_admin, integrity=excluded.integrity,
			last_seen=excluded.last_seen, beacon_int=excluded.beacon_int,
			jitter=excluded.jitter, status=excluded.status`,
		a.ID, a.Hostname, a.Username, a.OS, a.Arch, a.PID, a.ProcessName,
		a.InternalIP, a.ExternalIP, boolToInt(a.IsAdmin), a.Integrity, a.Domain,
		a.FirstSeen, a.LastSeen, a.BeaconInt, a.Jitter, a.Status, a.ListenerID,
	)
	return err
}

// GetAgent — récupère un agent par son ID
func (db *Database) GetAgent(id string) (*models.Agent, error) {
	a := &models.Agent{}
	var isAdmin int
	err := db.conn.QueryRow(`
		SELECT id, hostname, username, os, arch, pid, process_name,
		       internal_ip, external_ip, is_admin, integrity, domain,
		       first_seen, last_seen, beacon_int, jitter, status, listener_id
		FROM agents WHERE id = ?`, id,
	).Scan(
		&a.ID, &a.Hostname, &a.Username, &a.OS, &a.Arch, &a.PID, &a.ProcessName,
		&a.InternalIP, &a.ExternalIP, &isAdmin, &a.Integrity, &a.Domain,
		&a.FirstSeen, &a.LastSeen, &a.BeaconInt, &a.Jitter, &a.Status, &a.ListenerID,
	)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	a.IsAdmin = isAdmin == 1
	return a, nil
}

// ListAgents — liste tous les agents (actifs en premier)
func (db *Database) ListAgents() ([]*models.Agent, error) {
	rows, err := db.conn.Query(`
		SELECT id, hostname, username, os, arch, pid, process_name,
		       internal_ip, external_ip, is_admin, integrity, domain,
		       first_seen, last_seen, beacon_int, jitter, status, listener_id
		FROM agents ORDER BY last_seen DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var agents []*models.Agent
	for rows.Next() {
		a := &models.Agent{}
		var isAdmin int
		if err := rows.Scan(
			&a.ID, &a.Hostname, &a.Username, &a.OS, &a.Arch, &a.PID, &a.ProcessName,
			&a.InternalIP, &a.ExternalIP, &isAdmin, &a.Integrity, &a.Domain,
			&a.FirstSeen, &a.LastSeen, &a.BeaconInt, &a.Jitter, &a.Status, &a.ListenerID,
		); err != nil {
			return nil, err
		}
		a.IsAdmin = isAdmin == 1
		agents = append(agents, a)
	}
	return agents, nil
}

// UpdateAgentLastSeen — met à jour le timestamp de dernier check-in
func (db *Database) UpdateAgentLastSeen(agentID string) error {
	_, err := db.conn.Exec(
		`UPDATE agents SET last_seen = ?, status = 'active' WHERE id = ?`,
		time.Now(), agentID,
	)
	return err
}

// UpdateAgentSleep — met à jour l'intervalle beacon d'un agent
func (db *Database) UpdateAgentSleep(agentID string, sleep int) error {
	_, err := db.conn.Exec(
		`UPDATE agents SET beacon_int = ? WHERE id = ?`,
		sleep, agentID,
	)
	return err
}

// MarkDeadAgents — marque comme "dead" les agents inactifs depuis trop longtemps
func (db *Database) MarkDeadAgents(threshold time.Duration) error {
	cutoff := time.Now().Add(-threshold)
	_, err := db.conn.Exec(
		`UPDATE agents SET status = 'dead' WHERE last_seen < ? AND status != 'dead'`,
		cutoff,
	)
	return err
}

// ─────────────────────────────────────────────────────────────
// TASKS
// ─────────────────────────────────────────────────────────────

// CreateTask — enregistre une nouvelle tâche
func (db *Database) CreateTask(t *models.Task) error {
	_, err := db.conn.Exec(`
		INSERT INTO tasks (id, agent_id, type, payload, status, created_at, operator_id)
		VALUES (?, ?, ?, ?, 'pending', ?, ?)`,
		t.ID, t.AgentID, t.Type, t.Payload, time.Now(), t.OperatorID,
	)
	return err
}

// GetPendingTasks — récupère les tâches en attente pour un agent
// Appelé à chaque beacon check-in
func (db *Database) GetPendingTasks(agentID string) ([]*models.Task, error) {
	rows, err := db.conn.Query(`
		SELECT id, agent_id, type, payload, status, created_at, operator_id
		FROM tasks
		WHERE agent_id = ? AND status = 'pending'
		ORDER BY created_at ASC`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*models.Task
	for rows.Next() {
		t := &models.Task{}
		if err := rows.Scan(
			&t.ID, &t.AgentID, &t.Type, &t.Payload,
			&t.Status, &t.CreatedAt, &t.OperatorID,
		); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, nil
}

// UpdateTaskResult — met à jour une tâche avec son résultat
func (db *Database) UpdateTaskResult(taskID, result, errMsg string, success bool) error {
	status := "done"
	if !success {
		status = "error"
	}
	_, err := db.conn.Exec(`
		UPDATE tasks SET status = ?, result = ?, error = ?, done_at = ?
		WHERE id = ?`,
		status, result, errMsg, time.Now(), taskID,
	)
	return err
}

// MarkTasksSent — marque les tâches comme envoyées
func (db *Database) MarkTasksSent(taskIDs []string) error {
	for _, id := range taskIDs {
		if _, err := db.conn.Exec(
			`UPDATE tasks SET status = 'sent', sent_at = ? WHERE id = ?`,
			time.Now(), id,
		); err != nil {
			return err
		}
	}
	return nil
}

// GetTaskHistory — historique des tâches pour un agent
func (db *Database) GetTaskHistory(agentID string, limit int) ([]*models.Task, error) {
	rows, err := db.conn.Query(`
		SELECT id, agent_id, type, payload, status, created_at, operator_id,
		       COALESCE(result, ''), COALESCE(done_at, '')
		FROM tasks WHERE agent_id = ?
		ORDER BY created_at DESC LIMIT ?`, agentID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var tasks []*models.Task
	for rows.Next() {
		t := &models.Task{}
		var doneAt string
		if err := rows.Scan(
			&t.ID, &t.AgentID, &t.Type, &t.Payload,
			&t.Status, &t.CreatedAt, &t.OperatorID, &t.Result, &doneAt,
		); err != nil {
			return nil, err
		}
		tasks = append(tasks, t)
	}
	return tasks, nil
}

// ─────────────────────────────────────────────────────────────
// EVENTS
// ─────────────────────────────────────────────────────────────

// LogEvent — enregistre un événement dans l'audit trail
func (db *Database) LogEvent(eventType, agentID, operatorID, message string) error {
	id := fmt.Sprintf("%d", time.Now().UnixNano())
	_, err := db.conn.Exec(`
		INSERT INTO events (id, type, agent_id, operator_id, message, timestamp)
		VALUES (?, ?, ?, ?, ?, ?)`,
		id, eventType, agentID, operatorID, message, time.Now(),
	)
	return err
}

// GetRecentEvents — récupère les N derniers événements
func (db *Database) GetRecentEvents(limit int) ([]*models.Event, error) {
	rows, err := db.conn.Query(`
		SELECT id, type, COALESCE(agent_id,''), COALESCE(operator_id,''), message, timestamp
		FROM events ORDER BY timestamp DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []*models.Event
	for rows.Next() {
		e := &models.Event{}
		if err := rows.Scan(&e.ID, &e.Type, &e.AgentID, &e.OperatorID, &e.Message, &e.Timestamp); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, nil
}

// ─────────────────────────────────────────────────────────────
// OPERATORS
// ─────────────────────────────────────────────────────────────

// CreateOperator — crée un nouveau compte opérateur
func (db *Database) CreateOperator(op *models.Operator) error {
	_, err := db.conn.Exec(`
		INSERT INTO operators (id, username, password_hash, role, created_at)
		VALUES (?, ?, ?, ?, ?)`,
		op.ID, op.Username, op.PasswordHash, op.Role, time.Now(),
	)
	return err
}

// GetOperatorByUsername — récupère un opérateur par son nom
func (db *Database) GetOperatorByUsername(username string) (*models.Operator, error) {
	op := &models.Operator{}
	err := db.conn.QueryRow(`
		SELECT id, username, password_hash, role FROM operators WHERE username = ?`,
		username,
	).Scan(&op.ID, &op.Username, &op.PasswordHash, &op.Role)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return op, err
}

// ─────────────────────────────────────────────────────────────
// Helper
// ─────────────────────────────────────────────────────────────

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// Close — ferme proprement la connexion à la DB
func (db *Database) Close() error {
	return db.conn.Close()
}
