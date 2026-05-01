// Mythos C2 — Team Server
//
// Point d'entrée principal. Ce fichier :
//   1. Charge la configuration
//   2. Initialise la base de données
//   3. Crée le compte admin par défaut si nécessaire
//   4. Démarre le listener HTTPS (pour les agents)
//   5. Démarre l'API REST (pour les opérateurs)
//
// Usage :
//   go run main.go
//   go run main.go --listener-port 443 --api-port 8443

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/sherko/mythos-c2/server/api"
	"github.com/sherko/mythos-c2/server/db"
	"github.com/sherko/mythos-c2/server/listener"
	"github.com/sherko/mythos-c2/server/models"
	"golang.org/x/crypto/bcrypt"
)

// Config — configuration du team server
type Config struct {
	ListenerHost string
	ListenerPort int
	APIHost      string
	APIPort      int
	DBPath       string
	TLSCert      string
	TLSKey       string
	AdminPass    string
}

func main() {
	// Banner
	printBanner()

	// Parsing des arguments
	cfg := parseFlags()

	// ── 1. Base de données ──────────────────────────────────────
	log.Println("[MYTHOS] Initialisation de la base de données...")
	database, err := db.New(cfg.DBPath)
	if err != nil {
		log.Fatalf("[MYTHOS] FATAL: DB init failed: %v", err)
	}
	defer database.Close()
	log.Printf("[MYTHOS] ✓ Base de données: %s", cfg.DBPath)

	// ── 2. Clé de signature JWT ─────────────────────────────────
	// En production : charger depuis un fichier ou variable d'environnement
	signingKey := []byte(getEnv("MYTHOS_JWT_SECRET", "mythos-super-secret-key-change-in-prod"))

	// ── 3. Compte admin par défaut ──────────────────────────────
	if err := ensureAdminAccount(database, cfg.AdminPass); err != nil {
		log.Printf("[MYTHOS] Warning: could not create admin account: %v", err)
	}

	// ── 4. Listener HTTPS (pour les agents) ─────────────────────
	listenerConfig := &models.Listener{
		ID:      uuid.New().String(),
		Name:    "default-https",
		Type:    "https",
		Host:    cfg.ListenerHost,
		Port:    cfg.ListenerPort,
		TLSCert: cfg.TLSCert,
		TLSKey:  cfg.TLSKey,
		Active:  true,
	}

	agentListener := listener.New(listenerConfig, database)

	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.ListenerHost, cfg.ListenerPort)
		log.Printf("[MYTHOS] ✓ Listener agent démarré → %s", addr)
		if err := agentListener.Start(); err != nil {
			log.Printf("[MYTHOS] Listener error: %v", err)
		}
	}()

	// ── 5. API REST (pour les opérateurs) ───────────────────────
	operatorAPI := api.New(database, signingKey)

	go func() {
		addr := fmt.Sprintf("%s:%d", cfg.APIHost, cfg.APIPort)
		log.Printf("[MYTHOS] ✓ API opérateur démarrée → http://%s/api", addr)
		if err := operatorAPI.Start(addr); err != nil {
			log.Printf("[MYTHOS] API error: %v", err)
		}
	}()

	// ── 6. Watchdog — marque les agents morts ───────────────────
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			// Un agent est "mort" s'il n'a pas checké-in depuis 3x son intervalle
			if err := database.MarkDeadAgents(5 * time.Minute); err != nil {
				log.Printf("[MYTHOS] Watchdog error: %v", err)
			}
		}
	}()

	log.Println("[MYTHOS] ══════════════════════════════════════════")
	log.Println("[MYTHOS]  Mythos C2 opérationnel — En attente...")
	log.Println("[MYTHOS] ══════════════════════════════════════════")

	// ── 7. Attendre le signal d'arrêt (Ctrl+C) ──────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[MYTHOS] Signal reçu — Arrêt propre en cours...")
	if err := agentListener.Stop(); err != nil {
		log.Printf("[MYTHOS] Listener stop error: %v", err)
	}
	log.Println("[MYTHOS] ✓ Mythos C2 arrêté proprement.")
}

// ─────────────────────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────────────────────

func parseFlags() *Config {
	cfg := &Config{}
	flag.StringVar(&cfg.ListenerHost, "listener-host", "0.0.0.0", "Adresse d'écoute pour les agents")
	flag.IntVar(&cfg.ListenerPort, "listener-port", 8080, "Port d'écoute pour les agents")
	flag.StringVar(&cfg.APIHost, "api-host", "127.0.0.1", "Adresse de l'API opérateur")
	flag.IntVar(&cfg.APIPort, "api-port", 8443, "Port de l'API opérateur")
	flag.StringVar(&cfg.DBPath, "db", "mythos.db", "Chemin vers la base de données SQLite")
	flag.StringVar(&cfg.TLSCert, "tls-cert", "", "Chemin vers le certificat TLS")
	flag.StringVar(&cfg.TLSKey, "tls-key", "", "Chemin vers la clé TLS")
	flag.StringVar(&cfg.AdminPass, "admin-pass", "MythosAdmin2024!", "Mot de passe admin initial")
	flag.Parse()
	return cfg
}

// ensureAdminAccount — crée le compte admin si la DB est vide
func ensureAdminAccount(database *db.Database, password string) error {
	existing, err := database.GetOperatorByUsername("admin")
	if err != nil {
		return err
	}
	if existing != nil {
		return nil // Compte admin déjà existant
	}

	// Hasher le mot de passe avec bcrypt (coût 12)
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 12)
	if err != nil {
		return err
	}

	admin := &models.Operator{
		ID:           uuid.New().String(),
		Username:     "admin",
		PasswordHash: string(hash),
		Role:         "admin",
	}

	if err := database.CreateOperator(admin); err != nil {
		return err
	}

	log.Printf("[MYTHOS] ✓ Compte admin créé (user: admin)")
	log.Printf("[MYTHOS] ⚠ CHANGEZ le mot de passe admin en production!")
	return nil
}

func getEnv(key, fallback string) string {
	if val := os.Getenv(key); val != "" {
		return val
	}
	return fallback
}

func printBanner() {
	banner := `
███╗   ███╗██╗   ██╗████████╗██╗  ██╗ ██████╗ ███████╗
████╗ ████║╚██╗ ██╔╝╚══██╔══╝██║  ██║██╔═══██╗██╔════╝
██╔████╔██║ ╚████╔╝    ██║   ███████║██║   ██║███████╗
██║╚██╔╝██║  ╚██╔╝     ██║   ██╔══██║██║   ██║╚════██║
██║ ╚═╝ ██║   ██║      ██║   ██║  ██║╚██████╔╝███████║
╚═╝     ╚═╝   ╚═╝      ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚══════╝
             C2 Framework — Red Team
             v1.0.0 — by SHERKO (Chercheur en Cybersécurité)
`
	fmt.Println(banner)
}
