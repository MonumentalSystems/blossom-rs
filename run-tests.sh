#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$REPO_DIR"

echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${CYAN}  blossom-rs — full test suite${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"

echo ""
echo -e "${YELLOW}[1/5] Build (workspace, all targets)...${NC}"
cargo build --workspace --all-targets 2>&1
echo -e "${GREEN}  OK${NC}"

echo ""
echo -e "${YELLOW}[2/5] Clippy (workspace, -D warnings)...${NC}"
cargo clippy --workspace --all-targets -- -D warnings 2>&1
echo -e "${GREEN}  OK${NC}"

echo ""
echo -e "${YELLOW}[3/5] Format check...${NC}"
cargo fmt -- --check 2>&1
echo -e "${GREEN}  OK${NC}"

echo ""
echo -e "${YELLOW}[4/5] Tests (workspace)...${NC}"
cargo test --workspace 2>&1
echo -e "${GREEN}  OK${NC}"

echo ""
echo -e "${YELLOW}[5/5] Code coverage (workspace)...${NC}"
if command -v cargo-tarpaulin &>/dev/null; then
  cargo tarpaulin --workspace --timeout 300 --out Stdout \
    --exclude blossom-cli --exclude blossom-server --exclude xtask 2>&1 | \
    grep -E "(Tested/Total|src/.*[0-9]/[0-9]|coverage,)"
else
  echo -e "${YELLOW}  cargo-tarpaulin not installed. Install with: cargo install cargo-tarpaulin${NC}"
fi

echo ""
echo -e "${GREEN}  Done.${NC}"
