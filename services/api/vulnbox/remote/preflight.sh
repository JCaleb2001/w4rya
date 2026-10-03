#!/usr/bin/env bash
#
# Runs ON the vulnbox. Read-only readiness checks — creates nothing, changes
# nothing. Piped in over SSH by services/api/vulnbox/preflight.py
# (`ssh ... bash -s -- <services_path>`); nothing is installed on the box.
#
#   preflight.sh <services_path>
#
# Reachability and SSH auth are checked from the w4rya side (if this script
# runs at all, both worked). This only covers what has to be looked at on the
# box itself.
#
# Output (tab-separated, one record per line):
#   CHECK <TAB> <name> <TAB> ok|fail <TAB> <detail>
set -uo pipefail

SERVICES_PATH="${1:-/root/services}"
TAB=$'\t'

check() { echo "CHECK${TAB}$1${TAB}$2${TAB}$3"; }

if [[ -d "$SERVICES_PATH" ]]; then
  n="$(find "$SERVICES_PATH" -mindepth 1 -maxdepth 1 -type d ! -name '.*' 2>/dev/null | wc -l)"
  check services_path ok "$SERVICES_PATH ($n service dirs)"
else
  check services_path fail "$SERVICES_PATH does not exist"
fi

if command -v git >/dev/null 2>&1; then
  check git ok "$(git --version 2>/dev/null)"
else
  check git fail "git is not installed (backups need it)"
fi

if command -v docker >/dev/null 2>&1; then
  check docker ok "$(docker --version 2>/dev/null | head -1)"
else
  check docker fail "docker is not installed (recon cannot map ports)"
fi
exit 0
