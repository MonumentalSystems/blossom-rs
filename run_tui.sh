#!/bin/sh
set -eu
: "${BLOSSOM_SECRET_KEY:?set BLOSSOM_SECRET_KEY to run the TUI}"
exec cargo run --features tui --bin blossom-tui -- \
  -s https://blossom.gnostr.cloud -k "$BLOSSOM_SECRET_KEY"
