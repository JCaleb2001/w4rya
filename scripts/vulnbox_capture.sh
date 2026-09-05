#!/usr/bin/env bash
#
# Local control for the rotating tcpdump capture on the vulnbox.
#
#   scripts/vulnbox_capture.sh start
#   scripts/vulnbox_capture.sh stop
#   scripts/vulnbox_capture.sh status
#
# Env overrides:
#   VULNBOX_HOST      ssh target                 (default root@vulnbox.glitch.ad)
#   VULNBOX_IFACE     capture interface          (default game)
#   VULNBOX_PCAP_DIR  capture dir on the vulnbox (default /root/pcaps)
#   ROTATE_SECONDS    new file every N seconds   (default 60)
#   ROTATE_MB         or sooner past N MB        (default 100)
#   BPF_FILTER        tcpdump expression, by port only — e.g.
#                     'tcp port 8008 or tcp port 8000' (default: none, capture all)
#
# Pairs with scripts/pull_vulnbox_pcaps.sh, which fetches closed files into
# w4rya's traffic dir and deletes them from the vulnbox once verified.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

HOST="${VULNBOX_HOST:-root@vulnbox.glitch.ad}"
IFACE="${VULNBOX_IFACE:-game}"
REMOTE_DIR="${VULNBOX_PCAP_DIR:-/root/pcaps}"
ROTATE_SECONDS="${ROTATE_SECONDS:-60}"
ROTATE_MB="${ROTATE_MB:-100}"
BPF_FILTER="${BPF_FILTER:-}"
REMOTE_SCRIPT_PATH="/root/.w4rya_remote_capture.sh"

CMD="${1:-}"
case "$CMD" in
  start|stop|status) ;;
  *) echo "usage: $0 {start|stop|status}" >&2; exit 1 ;;
esac

scp -q "$(dirname "${BASH_SOURCE[0]}")/vulnbox/remote_capture.sh" "$HOST:$REMOTE_SCRIPT_PATH"
ssh "$HOST" "bash '$REMOTE_SCRIPT_PATH' '$CMD' '$IFACE' '$REMOTE_DIR' '$ROTATE_SECONDS' '$ROTATE_MB' '$BPF_FILTER'"
