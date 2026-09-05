#!/usr/bin/env bash
#
# Pulls closed pcap files from the vulnbox into w4rya's traffic directory,
# verifies each one by checksum, then deletes it from the vulnbox — so the
# vulnbox never accumulates capture data it doesn't need to keep.
#
#   scripts/pull_vulnbox_pcaps.sh          loop forever (Ctrl-C to stop)
#   scripts/pull_vulnbox_pcaps.sh --once   a single pass (good for cron)
#
# The newest file on the vulnbox is always skipped: tcpdump (via
# vulnbox_capture.sh) is still appending to it. A file only gets pulled once
# it has stopped being the newest AND is at least SETTLE_SECONDS old, which
# covers the moment right at rotation where "newest" is momentarily unclear.
#
# Env overrides:
#   VULNBOX_HOST      ssh target                  (default root@vulnbox.glitch.ad)
#   VULNBOX_PCAP_DIR  capture dir on the vulnbox   (default /root/pcaps)
#   TRAFFIC_DIR_HOST  destination (default: read from .env, else ./services/vulnbox_pcap)
#   POLL_SECONDS      loop interval                (default 30)
#   SETTLE_SECONDS    min age before pulling        (default 5)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

HOST="${VULNBOX_HOST:-root@vulnbox.glitch.ad}"
REMOTE_DIR="${VULNBOX_PCAP_DIR:-/root/pcaps}"
POLL_SECONDS="${POLL_SECONDS:-30}"
SETTLE_SECONDS="${SETTLE_SECONDS:-5}"

if [[ -z "${TRAFFIC_DIR_HOST:-}" ]]; then
  TRAFFIC_DIR_HOST="$(awk -F= '$1=="TRAFFIC_DIR_HOST"{gsub(/"/,"",$2); print $2}' .env 2>/dev/null | tail -1)"
fi
LOCAL_DIR="${TRAFFIC_DIR_HOST:-./services/vulnbox_pcap}"
STAGING="./.vulnbox_pull_tmp"

mkdir -p "$LOCAL_DIR" "$STAGING"

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

pull_once() {
  local files
  files="$(ssh "$HOST" "cd '$REMOTE_DIR' 2>/dev/null && find . -maxdepth 1 -name '*.pcap*' -printf '%T@ %f\n' 2>/dev/null | sort -rn" || true)"
  if [[ -z "$files" ]]; then
    log "no pcaps on vulnbox"
    return 0
  fi

  local newest
  newest="$(head -1 <<<"$files" | awk '{print $2}')"
  local now
  now="$(date +%s)"

  while read -r mtime name; do
    [[ -z "${name:-}" ]] && continue
    [[ "$name" == "$newest" ]] && continue

    local age=$(( now - ${mtime%.*} ))
    if [[ "$age" -lt "$SETTLE_SECONDS" ]]; then
      continue
    fi

    local final="$LOCAL_DIR/$name"
    if [[ -f "$final" ]]; then
      # already pulled — a previous pass must have died before the remote rm
      ssh "$HOST" "rm -f '$REMOTE_DIR/$name'" || true
      continue
    fi

    local tmp="$STAGING/$name"
    log "fetching $name"
    if ! scp -q "$HOST:$REMOTE_DIR/$name" "$tmp"; then
      log "scp failed for $name — will retry next pass"
      rm -f "$tmp"
      continue
    fi

    local remote_sum local_sum
    remote_sum="$(ssh "$HOST" "sha256sum '$REMOTE_DIR/$name'" 2>/dev/null | awk '{print $1}')"
    local_sum="$(sha256sum "$tmp" 2>/dev/null | awk '{print $1}')"
    if [[ -z "$remote_sum" || "$remote_sum" != "$local_sum" ]]; then
      log "checksum mismatch for $name — leaving it on the vulnbox, will retry"
      rm -f "$tmp"
      continue
    fi

    mv "$tmp" "$final"
    ssh "$HOST" "rm -f '$REMOTE_DIR/$name'"
    log "pulled + verified + removed from vulnbox: $name"
  done <<<"$files"
}

if [[ "${1:-}" == "--once" ]]; then
  pull_once
else
  log "watching $HOST:$REMOTE_DIR -> $LOCAL_DIR every ${POLL_SECONDS}s (Ctrl-C to stop)"
  while true; do
    pull_once
    sleep "$POLL_SECONDS"
  done
fi
