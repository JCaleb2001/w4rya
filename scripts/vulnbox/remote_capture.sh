#!/usr/bin/env bash
#
# Runs ON the vulnbox. Controls a rotating tcpdump capture (root only).
# Deployed and invoked by ../vulnbox_capture.sh over SSH — not meant to be
# copied by hand.
#
#   remote_capture.sh start [iface] [dir] [rotate_seconds] [rotate_mb] [bpf_filter]
#   remote_capture.sh stop  [dir]
#   remote_capture.sh status [dir]
#
# bpf_filter is a normal tcpdump expression, e.g.:
#   'tcp port 8008 or tcp port 8000 or tcp port 5151'
# Filter by port, never by direction (src/dst) — w4rya's assembler needs
# BOTH sides of a connection to reassemble the flow. Empty = capture
# everything on the interface.
set -euo pipefail

CMD="${1:-}"
IFACE="${2:-game}"
DIR="${3:-/root/pcaps}"
ROTATE_SECONDS="${4:-60}"
ROTATE_MB="${5:-100}"
FILTER="${6:-}"
PIDFILE="$DIR/.tcpdump.pid"

running() { [[ -f "$PIDFILE" ]] && kill -0 "$(cat "$PIDFILE")" 2>/dev/null; }

case "$CMD" in
  start)
    mkdir -p "$DIR"
    if running; then
      echo "already running (pid $(cat "$PIDFILE"))"
      exit 0
    fi
    # -U: flush to disk after each packet, so a rotated file is safely
    # readable as soon as tcpdump moves on to the next one.
    # -G + -C together: a new file every ROTATE_SECONDS, or sooner if the
    # current one hits ROTATE_MB — whichever comes first.
    # -Z root: Debian/Ubuntu tcpdump drops privileges to the 'tcpdump' user
    # by default once the capture socket is open, and that user can't even
    # traverse a 700 /root to reach $DIR — stay root so the dump file opens.
    nohup tcpdump -i "$IFACE" -s 0 -U -Z root \
      -w "$DIR/%Y-%m-%d_%H-%M-%S.pcap" \
      -G "$ROTATE_SECONDS" -C "$ROTATE_MB" \
      $FILTER \
      >"$DIR/tcpdump.log" 2>&1 &
    echo $! > "$PIDFILE"
    disown
    sleep 1
    if running; then
      echo "started (pid $(cat "$PIDFILE"), iface=$IFACE, dir=$DIR, rotate=${ROTATE_SECONDS}s/${ROTATE_MB}MB, filter='${FILTER:-<none>}')"
    else
      echo "failed to start — see $DIR/tcpdump.log"
      tail -20 "$DIR/tcpdump.log" 2>/dev/null || true
      exit 1
    fi
    ;;
  stop)
    if running; then
      kill "$(cat "$PIDFILE")"
      rm -f "$PIDFILE"
      echo stopped
    else
      echo "not running"
    fi
    ;;
  status)
    if running; then
      echo "running (pid $(cat "$PIDFILE"))"
    else
      echo "not running"
    fi
    du -sh "$DIR" 2>/dev/null || true
    ls -1t "$DIR"/*.pcap* 2>/dev/null | head -5 || true
    ;;
  *)
    echo "usage: $0 {start|stop|status} [iface] [dir] [rotate_seconds] [rotate_mb]" >&2
    exit 1
    ;;
esac
