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
# Shell-quoted once up front (same reasoning as vulnbox_capture.sh's
# REMOTE_CMD): a naive '$REMOTE_DIR' embedded in a remote command string
# breaks (or injects) if the value contains a single quote.
REMOTE_DIR_Q="$(printf '%q' "$REMOTE_DIR")"

# Same key=value reader install.sh (env_get) and smoke.sh use — gsub only
# strips a quote at the very start/end of the value, not every embedded
# quote, unlike a bare `gsub(/"/,"",$2)`.
env_get() { awk -F= -v k="$1" '$1==k{sub("^" k "=",""); gsub(/^"|"$/,""); v=$0} END{print v}' .env 2>/dev/null; }

if [[ -z "${TRAFFIC_DIR_HOST:-}" ]]; then
  TRAFFIC_DIR_HOST="$(env_get TRAFFIC_DIR_HOST)"
fi
LOCAL_DIR="${TRAFFIC_DIR_HOST:-./services/vulnbox_pcap}"
STAGING="./.vulnbox_pull_tmp"
# Remembers which filename was "newest" on the previous pass, across both
# loop iterations and separate --once invocations (e.g. from cron) — see
# the newest-file handling in pull_once below.
STATE_FILE="$STAGING/.last_newest"

mkdir -p "$LOCAL_DIR" "$STAGING"

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

pull_once() {
  local files
  files="$(ssh "$HOST" "cd $REMOTE_DIR_Q 2>/dev/null && find . -maxdepth 1 -name '*.pcap*' -printf '%T@ %f\n' 2>/dev/null | sort -rn" || true)"
  if [[ -z "$files" ]]; then
    log "no pcaps on vulnbox"
    return 0
  fi

  local newest
  newest="$(head -1 <<<"$files" | awk '{print $2}')"
  local prev_newest=""
  [[ -f "$STATE_FILE" ]] && prev_newest="$(cat "$STATE_FILE" 2>/dev/null || true)"
  printf '%s' "$newest" > "$STATE_FILE"

  local now
  now="$(date +%s)"

  # Names eligible to pull this pass. The newest file is only skipped
  # while it's a NEW arrival (not also last pass's newest) — tcpdump is
  # presumably still appending to a file that just became the newest.
  # Once it's been the newest across two passes with nothing replacing
  # it (rotation is slow, or capture was stopped entirely), the settle-age
  # check below is what actually gates pulling it, so a stopped capture's
  # final file isn't stranded forever just for occupying position 1.
  local -a candidates=()
  while read -r mtime name; do
    [[ -z "${name:-}" ]] && continue
    if [[ "$name" == "$newest" && "$name" != "$prev_newest" ]]; then
      continue
    fi

    local age=$(( now - ${mtime%.*} ))
    if [[ "$age" -lt "$SETTLE_SECONDS" ]]; then
      continue
    fi

    local final="$LOCAL_DIR/$name"
    if [[ -f "$final" ]]; then
      # already pulled — a previous pass must have died before the remote rm
      ssh "$HOST" "rm -f $(printf '%q' "$REMOTE_DIR/$name")" || true
      continue
    fi

    candidates+=("$name")
  done <<<"$files"

  [[ ${#candidates[@]} -eq 0 ]] && return 0

  # One remote round trip for every candidate's checksum instead of one
  # per file — SSH latency dominates the pull loop on a slow link.
  local quoted_names=""
  local name
  for name in "${candidates[@]}"; do
    quoted_names+="$(printf '%q ' "$name")"
  done
  local remote_sums
  remote_sums="$(ssh "$HOST" "cd $REMOTE_DIR_Q 2>/dev/null && sha256sum -- $quoted_names 2>/dev/null" || true)"

  local tmp final remote_sum local_sum
  for name in "${candidates[@]}"; do
    final="$LOCAL_DIR/$name"
    tmp="$STAGING/$name"
    log "fetching $name"
    if ! scp -q "$HOST:$REMOTE_DIR/$name" "$tmp"; then
      log "scp failed for $name — will retry next pass"
      rm -f "$tmp"
      continue
    fi

    # sha256sum -b/binary-mode output prefixes the filename with "*" —
    # strip it before comparing so this doesn't depend on the remote
    # sha256sum's default mode.
    remote_sum="$(awk -v f="$name" '{n=$2; sub(/^\*/,"",n); if (n==f) print $1}' <<<"$remote_sums")"
    local_sum="$(sha256sum "$tmp" 2>/dev/null | awk '{print $1}')"
    if [[ -z "$remote_sum" || "$remote_sum" != "$local_sum" ]]; then
      log "checksum mismatch for $name — leaving it on the vulnbox, will retry"
      rm -f "$tmp"
      continue
    fi

    mv "$tmp" "$final"
    ssh "$HOST" "rm -f $(printf '%q' "$REMOTE_DIR/$name")" || true
    log "pulled + verified + removed from vulnbox: $name"
  done
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
