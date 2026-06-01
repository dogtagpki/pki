#!/usr/bin/env bash
# Record startup timing baseline using IDM-CI helper scripts.
# Run from the PKI repository root.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
cd "$ROOT"
LOG=${ROOT}/benchmarks/startup-baseline.log
CREATE=${CREATE:-../IDM-CI/bash/pki-create.sh}
SPAWN=${SPAWN:-../IDM-CI/bash/pki-spawn.sh}
CFG=${CFG:-/usr/share/pki/server/examples/installation/ca.cfg}
SKIP_BUILD=${SKIP_BUILD:-}

mkdir -p benchmarks

{
  echo "=== Startup baseline run ==="
  echo "date: $(date -Iseconds)"
  echo "host: $(hostname -f 2>/dev/null || hostname)"
  echo "branch: $(git branch --show-current 2>/dev/null || true)"
  echo "commit: $(git rev-parse --short HEAD 2>/dev/null || true)"
  echo ""

  create_args=(-x)
  [[ -n "$SKIP_BUILD" ]] && create_args+=(-s)

  echo "=== pki-create.sh ${create_args[*]} ==="
  echo "started: $(date -Iseconds)"
  /usr/bin/time -f 'TIME_RESULT create elapsed_sec=%e user_sec=%U sys_sec=%S exit=%x' \
    "$CREATE" "${create_args[@]}"
  echo "finished: $(date -Iseconds)"
  echo ""

  echo "=== pki-spawn.sh -x $CFG ==="
  echo "started: $(date -Iseconds)"
  /usr/bin/time -f 'TIME_RESULT spawn_full elapsed_sec=%e user_sec=%U sys_sec=%S exit=%x' \
    "$SPAWN" -x "$CFG"
  echo "finished: $(date -Iseconds)"
  echo ""

  echo "=== pkispawn only (warm container) ==="
  echo "started: $(date -Iseconds)"
  /usr/bin/time -f 'TIME_RESULT pkispawn_only elapsed_sec=%e exit=%x' \
    docker exec pki pkispawn \
      -f "$CFG" \
      -s CA \
      -D pki_audit_signing_nickname= \
      -D "pki_ds_url=ldap://ds.example.com:3389" \
      -v
  echo "finished: $(date -Iseconds)"
} 2>&1 | tee -a "$LOG"

echo "Log appended to $LOG"
echo "Update benchmarks/startup-baseline.md with new TIME_RESULT lines."
