#!/usr/bin/env bash
set -euo pipefail

# Erebus installer — privacy-first PII filter for AI code editors
# Usage: curl -fsSL https://raw.githubusercontent.com/ethux/erebus/main/install.sh | bash

REPO="https://github.com/ethux/erebus.git"
BOLD="\033[1m"
DIM="\033[2m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

info()  { printf "${GREEN}[+]${RESET} %s\n" "$1"; }
warn()  { printf "${YELLOW}[!]${RESET} %s\n" "$1"; }
fail()  { printf "${RED}[x]${RESET} %s\n" "$1"; exit 1; }
step()  { printf "\n${BOLD}%s${RESET}\n" "$1"; }

# ── Check prerequisites ──────────────────────────────────────────────────────

step "Checking prerequisites..."

if command -v uv &>/dev/null; then
    info "uv found: $(uv --version)"
elif command -v pip &>/dev/null; then
    warn "uv not found, will use pip (uv is recommended: https://docs.astral.sh/uv)"
else
    fail "Neither uv nor pip found. Install uv: curl -LsSf https://astral.sh/uv/install.sh | sh"
fi

# ── Install erebus ────────────────────────────────────────────────────────────

step "Installing Erebus..."

if command -v uv &>/dev/null; then
    uv tool install "git+$REPO" 2>/dev/null || uv tool install --force "git+$REPO"
else
    pip install "git+$REPO"
fi

if ! command -v erebus-setup &>/dev/null; then
    fail "Installation failed: erebus-setup not found on PATH"
fi

info "Erebus installed"

# ── Pick editor ───────────────────────────────────────────────────────────────

step "Which editor(s) do you use?"
echo ""
echo "  1) Claude Code"
echo "  2) Mistral Vibe"
echo "  3) OpenAI Codex"
echo "  4) All of the above"
echo ""

read -rp "Enter numbers separated by spaces (e.g. 1 2): " choices

editors=()
for c in $choices; do
    case $c in
        1) editors+=("claude") ;;
        2) editors+=("vibe") ;;
        3) editors+=("codex") ;;
        4) editors=("all"); break ;;
        *) warn "Unknown option: $c" ;;
    esac
done

if [ ${#editors[@]} -eq 0 ]; then
    warn "No editor selected, running setup for all editors"
    editors=("all")
fi

# ── Run setup ─────────────────────────────────────────────────────────────────

step "Setting up Erebus..."

for editor in "${editors[@]}"; do
    erebus-setup --editor "$editor"
done

# ── Optional: Ollama for file guards ─────────────────────────────────────────

echo ""
read -rp "Install Ollama for file guard + image scanning? (y/N): " install_ollama

if [[ "$install_ollama" =~ ^[Yy]$ ]]; then
    step "Setting up Ollama..."
    if command -v brew &>/dev/null; then
        brew install ollama 2>/dev/null || info "Ollama already installed"
    elif command -v ollama &>/dev/null; then
        info "Ollama already installed"
    else
        warn "Install Ollama manually: https://ollama.com/download"
    fi
    if command -v ollama &>/dev/null; then
        ollama pull ministral-3:3b 2>/dev/null && info "Ministral 3B model ready" || warn "Could not pull model (is Ollama running?)"
    fi
fi

# ── Done ──────────────────────────────────────────────────────────────────────

step "Done!"
echo ""
info "Erebus is active. Start your editor and PII will be filtered automatically."
echo ""
echo "  erebus-log            View filtering activity"
echo "  erebus-log --usage    Token usage stats"
echo "  erebus-log --latency  Per-editor latency stats"
echo "  erebus-update         Update Erebus and restart services"
echo "  erebus-uninstall      Remove Erebus"
echo ""
