#!/usr/bin/env bash
set -euo pipefail

# credstore one-click installer for macOS, Linux, and WSL.
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/juzcn/credstore/main/install.sh | bash
#
# No prerequisites — the script installs uv if needed, then uses
# ``uv tool install --force`` in an isolated environment.  --force makes
# the script idempotent: first run installs, re-runs upgrade to the latest
# PyPI release.  Python is managed automatically by uv.

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO="https://github.com/juzcn/credstore"

echo -e "${CYAN}credstore Installer${NC}"
echo ""
echo "Install method : uv tool install --force (isolated environment; re-run = update)"
echo "User data      : ~/.credstore/ (encrypted credential backup)"
echo "Python         : 3.13+ (managed by uv)"
echo ""

# [1/2] Ensure uv is available.
if ! command -v uv &>/dev/null; then
    echo -e "${YELLOW}[1/2] Installing uv…${NC}"
    curl --progress-bar -Lf https://astral.sh/uv/install.sh | sh
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
fi

# Report uv's failure instead of a green tick: a command substitution's exit
# status is discarded by the enclosing echo, so `echo "uv $(uv --version)"`
# printed "  ✓ uv bash: uv: command not found" and carried on.
if ! UV_VERSION="$(uv --version 2>&1)"; then
    echo -e "${RED}Error: uv is not available.${NC}"
    echo -e "${YELLOW}  ${UV_VERSION}${NC}"
    echo -e "${YELLOW}  Install it manually: https://docs.astral.sh/uv/${NC}"
    exit 1
fi
echo -e "${GREEN}  ✓${NC} ${UV_VERSION}"

# [2/2] Install/update credstore from PyPI.  --force: re-running this
# script upgrades an existing install (a plain ``uv tool install`` no-ops
# with "already installed").
#
# --python is required, not cosmetic: without it uv builds the tool env on
# whatever interpreter it prefers (often an older one it already manages)
# and then resolves to the newest release compatible with THAT Python.
# credstore 0.10+ needs >= 3.13, so a 3.12 tool env silently installs 0.9.0.
# With the constraint uv fetches a suitable interpreter, or fails loudly.
echo -e "${YELLOW}[2/2] Installing/updating credstore…${NC}"
if uv tool install --force --python '>=3.13' credstore; then
    echo -e "${GREEN}  ✓${NC} credstore ready"
else
    echo -e "${RED}Error: credstore installation failed.${NC}"
    echo -e "${YELLOW}Help: $REPO${NC}"
    exit 1
fi

# Is the shim directory on the PATH the user's *next* shell will have?  This
# check must come before any `export PATH=...` of that directory: exporting
# first made `command -v credstore` always succeed, so the warning below was
# unreachable and a user whose uv came from brew/apt (the [1/2] step skipped,
# so no profile edit happened) was told everything was fine and then got
# "credstore: command not found" in a fresh terminal.
if ! command -v credstore &>/dev/null; then
    echo ""
    echo -e "${YELLOW}IMPORTANT: credstore is installed but not on your current PATH.${NC}"
    if [ -f "$HOME/.local/bin/env" ]; then
        echo -e "${YELLOW}  Run: source \"\$HOME/.local/bin/env\"${NC}"
    else
        echo -e "${YELLOW}  Add it to your shell profile: export PATH=\"\$HOME/.local/bin:\$PATH\"${NC}"
    fi
    echo -e "${YELLOW}  Or simply open a new terminal.${NC}"
fi

echo ""
echo -e "${GREEN}credstore installed successfully!${NC}"
echo ""
echo -e "${CYAN}Get started:${NC}"
echo "  credstore set-password    # set up encrypted backup (first time)"
echo "  credstore set API_KEY     # store a secret (masked input)"
echo ""
echo -e "${CYAN}More info:${NC} $REPO"
