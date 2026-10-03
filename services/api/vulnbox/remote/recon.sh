#!/usr/bin/env bash
#
# Runs ON the vulnbox. Inventory of the service directories and of the
# containers publishing their ports. Read-only. Piped in over SSH by
# services/api/vulnbox/recon.py (`ssh ... bash -s -- <services_path>`).
#
#   recon.sh <services_path>
#
# A container is tied to its service directory through the label docker
# compose puts on every container it starts
# (com.docker.compose.project.working_dir), so the mapping is exact rather
# than guessed from container names.
#
# Output (tab-separated, one record per line):
#   DIR  <TAB> <name>
#   CTR  <TAB> <container> <TAB> <ports> <TAB> <image> <TAB> <compose working dir>
#   NOTE <TAB> <message>
set -uo pipefail

SERVICES_PATH="${1:-/root/services}"
TAB=$'\t'

if [[ -d "$SERVICES_PATH" ]]; then
  for d in "$SERVICES_PATH"/*/; do
    [[ -d "$d" ]] || continue
    echo "DIR${TAB}$(basename "$d")"
  done
else
  echo "NOTE${TAB}services path not found: $SERVICES_PATH"
fi

if command -v docker >/dev/null 2>&1; then
  # A real tab in the format string (not "\t") so docker passes it through
  # verbatim regardless of how it handles escapes.
  if out="$(docker ps --format "{{.Names}}${TAB}{{.Ports}}${TAB}{{.Image}}${TAB}{{.Label \"com.docker.compose.project.working_dir\"}}" 2>&1)"; then
    while IFS= read -r line; do
      [[ -n "$line" ]] && echo "CTR${TAB}${line}"
    done <<<"$out"
  else
    echo "NOTE${TAB}docker ps failed: $(head -1 <<<"$out")"
  fi
else
  echo "NOTE${TAB}docker is not installed; ports could not be mapped"
fi
