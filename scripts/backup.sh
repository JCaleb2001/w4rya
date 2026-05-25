#!/usr/bin/env bash
# Snapshot the w4rya operational state (users + suricata rules + DB-backed
# config / audit / notes) into a single timestamped tarball. Suitable for
# cron during a CTF.
#
# Usage:
#   ./scripts/backup.sh              # writes ./backups/<UTCISO>.tgz
#   BACKUP_DIR=/srv/bk ./scripts/backup.sh
#
# Restore:
#   tar xzvf <tarball>
#   # then docker compose exec timescale psql -U w4rya -d w4rya < app_config.sql
#   # and same for audit_log.sql / flow_notes.sql

set -euo pipefail

cd "$(dirname "$0")/.."

BACKUP_DIR="${BACKUP_DIR:-./backups}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$BACKUP_DIR"

WORK="$(mktemp -d -t w4rya-backup-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT

# 1) Files on disk: auth users + suricata rules (only the .rules file, not
#    the runtime socket dir).
if [[ -f auth/users.yaml ]]; then
  cp auth/users.yaml "$WORK/users.yaml"
fi
if [[ -d suricata-rules ]]; then
  # Just the rule files, no .gitkeep.
  find suricata-rules -name '*.rules' -exec cp {} "$WORK/" \;
fi

# 2) DB tables: app_config (services/teams/game), flow_notes, audit_log.
#    pg_dump per-table so a restore can be partial. We invoke psql via the
#    timescale container so we don't need pg_dump on the host.
if docker compose ps --status running --services 2>/dev/null | grep -qx timescale; then
  for tbl in app_config flow_notes audit_log; do
    docker compose exec -T timescale \
      pg_dump -U w4rya -d w4rya --data-only --column-inserts -t "$tbl" \
      > "$WORK/${tbl}.sql" 2>/dev/null || echo "[warn] failed to dump $tbl" >&2
  done
else
  echo "[warn] timescale container not running — skipping DB dump" >&2
fi

# 3) .env (config secrets — be careful where this tarball ends up).
if [[ -f .env ]]; then
  cp .env "$WORK/.env"
fi

OUT="${BACKUP_DIR}/w4rya_${STAMP}.tgz"
tar -czf "$OUT" -C "$WORK" .
SIZE_KB=$(du -k "$OUT" | cut -f1)
echo "wrote $OUT (${SIZE_KB} KB) — files:"
tar -tzf "$OUT" | sed 's/^/  /'
