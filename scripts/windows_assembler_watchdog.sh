#!/usr/bin/env bash
#
# Windows/Docker-Desktop-only workaround: the assembler only learns about new
# pcaps by fsnotify events on its watch dir, and Docker Desktop's Windows bind
# mounts don't reliably deliver those (the file lands, the CREATE/WRITE event
# doesn't). The assembler DOES do a full directory scan on every boot, so
# periodically restarting it is enough to pick up whatever piled up since the
# last restart. Not needed on native Linux Docker — inotify works there.
#
#   scripts/windows_assembler_watchdog.sh          loop forever (Ctrl-C to stop)
#   INTERVAL_SECONDS=60 scripts/windows_assembler_watchdog.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

INTERVAL_SECONDS="${INTERVAL_SECONDS:-120}"

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

log "restarting assembler every ${INTERVAL_SECONDS}s (Ctrl-C to stop)"
while true; do
  sleep "$INTERVAL_SECONDS"
  MSYS_NO_PATHCONV=1 docker compose restart assembler >/dev/null 2>&1 \
    && log "assembler restarted" \
    || log "assembler restart failed"
done
