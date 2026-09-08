#!/usr/bin/env bash
#
# Lists flows that are neither the game checker nor our own local traffic —
# candidate real attacks from other teams. Known noise sources on this box:
#   - the checker (one fixed IP, plants+reads its own flag each tick)
#   - our own vulnbox talking to itself (thrower/f1.py, mitmproxy relay hop)
# Anything else hitting our service ports is worth looking at.
#
#   scripts/show_attacker_flows.sh                  last 50, any time
#   scripts/show_attacker_flows.sh --since 10min     only recent ones
#   scripts/show_attacker_flows.sh --watch           poll every 10s, print only new rows
#
# Env overrides:
#   CHECKER_IP   known checker source IP   (default 10.100.0.1)
#   SELF_IP      our own vulnbox IP        (default 10.100.2.1)
#   WATCH_SECONDS  poll interval for --watch (default 10)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

CHECKER_IP="${CHECKER_IP:-10.100.0.1}"
SELF_IP="${SELF_IP:-10.100.2.1}"
WATCH_SECONDS="${WATCH_SECONDS:-10}"

query() {
  local since="$1"
  MSYS_NO_PATHCONV=1 docker compose exec -T timescale psql -U w4rya -d w4rya -At -F'|' -c "
    select time, ip_src, port_dst, packets_size, tags, flags
    from flow
    where ip_src not in ('$CHECKER_IP', '$SELF_IP')
    $since
    order by time desc
    limit 50;
  "
}

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

case "${1:-}" in
  --since)
    query "and time > now() - interval '${2:?falta el intervalo, ej: 10min}'"
    ;;
  --watch)
    log "watching for non-checker, non-self flows every ${WATCH_SECONDS}s (Ctrl-C to stop)"
    seen_file="$(mktemp)"
    trap 'rm -f "$seen_file"' EXIT
    while true; do
      query "and time > now() - interval '2 minutes'" | while IFS='|' read -r t ip port size tags flags; do
        [[ -z "${t:-}" ]] && continue
        key="$t|$ip|$port"
        if ! grep -qF "$key" "$seen_file" 2>/dev/null; then
          echo "$key" >> "$seen_file"
          echo "*** POSIBLE ATAQUE DE OTRO TEAM *** $t ip=$ip port=$port size=$size tags=$tags flags=$flags"
        fi
      done
      sleep "$WATCH_SECONDS"
    done
    ;;
  *)
    query ""
    ;;
esac
