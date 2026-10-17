#!/usr/bin/env bash
set -euo pipefail

# credstore uninstaller for macOS, Linux, and WSL.
# Usage:
#   ./uninstall.sh

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
GRAY='\033[0;90m'
NC='\033[0m'

# Set when a step fails, so the script can exit non-zero — a wrapper doing
# `./uninstall.sh && ...` must not be told the tool is gone when it is not.
FAILED=0

echo ""
echo -e "${CYAN}credstore Uninstaller${NC}"
echo ""

# 1. Uninstall from uv tool
if uv tool list 2>/dev/null | grep -qF "credstore"; then
    echo -e "${YELLOW}Uninstalling credstore…${NC}"
    if uv tool uninstall credstore 2>&1; then
        echo -e "  ${GREEN}✓${NC} credstore removed"
    else
        echo -e "  ${RED}✗${NC} uninstall failed"
        FAILED=1
    fi
else
    echo -e "${GRAY}credstore is not installed.${NC}"
fi

# 2. Clean up wrapper binaries
LOCAL_BIN="$HOME/.local/bin"
for bin in "$LOCAL_BIN/credstore"; do
    if [ -f "$bin" ] || [ -L "$bin" ]; then
        # Guarded: under `set -e` a failing rm (read-only or root-owned
        # directory) killed the script here, before the summary below.
        if rm -f "$bin" 2>/dev/null; then
            echo -e "  ${GRAY}Removed: $bin${NC}"
        else
            echo -e "  ${RED}✗${NC} could not remove: $bin"
            FAILED=1
        fi
    fi
done

# 3. Remaining data
echo ""
DATA_DIR="$HOME/.credstore"
if [ -d "$DATA_DIR" ]; then
    # `|| true`: with `set -o pipefail` an unreadable directory (a stray
    # `sudo credstore set-password` is enough) makes du exit non-zero, which
    # aborted the uninstaller right here — after the tool was removed, before
    # anything was reported.  SIZE is only a nicety, so let it come up empty.
    SIZE=$(du -sh "$DATA_DIR" 2>/dev/null | cut -f1 || true)
    echo -e "${YELLOW}Data files NOT removed (delete manually if desired):${NC}"
    echo -e "${GRAY}  ~/.credstore/           (${SIZE:-?}) — encrypted credential backup${NC}"
else
    echo -e "${GREEN}  ✓${NC} No remaining data files."
fi

echo ""
if [ "$FAILED" -ne 0 ]; then
    echo -e "${RED}Uninstall did not complete — see the failed step(s) above.${NC}"
    exit 1
fi
echo -e "${CYAN}Done.${NC}"
