#!/usr/bin/env bash
#
# Runs ON the vulnbox. Snapshots every service directory into its own bare git
# repo under ~/.w4rya-backups/<service>.git. Piped in over SSH by
# services/api/vulnbox/backup.py (`ssh ... bash -s -- <path> <max_bytes>`).
#
#   backup.sh <services_path> <max_file_bytes>
#
# Commits go through --git-dir/--work-tree (the "dotfiles bare repo" pattern),
# so NO .git is ever created inside a service directory. That matters: a .git
# inside a directory a service serves statically hands our source to every
# team that requests /.git/.
#
# The first run for a service creates the repo and commits the baseline (the
# pristine code, ideally taken in the window before other teams can connect).
# Later runs only commit when something changed. Files over max_file_bytes are
# left out via the repo's info/exclude — rewritten every run, so a file that
# shrinks back under the cap is picked up again — and reported.
#
# Output (tab-separated, one record per line):
#   SVC   <TAB> <name> <TAB> created|updated|unchanged|error <TAB> <commit> <TAB> <files> <TAB> <detail>
#   BIG   <TAB> <name> <TAB> <relative path> <TAB> <bytes>
#   FATAL <TAB> <message>
set -uo pipefail

SERVICES_PATH="${1:-/root/services}"
MAX_BYTES="${2:-26214400}"
BACKUP_ROOT="$HOME/.w4rya-backups"
TAB=$'\t'

if ! command -v git >/dev/null 2>&1; then
  echo "FATAL${TAB}git is not installed on the vulnbox"
  exit 0
fi
if [[ ! -d "$SERVICES_PATH" ]]; then
  echo "FATAL${TAB}services path not found: $SERVICES_PATH"
  exit 0
fi

mkdir -p "$BACKUP_ROOT"
chmod 700 "$BACKUP_ROOT"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

repo=""
dir=""
# -c identity: commit without writing any git config on the vulnbox.
g() {
  git --git-dir="$repo" --work-tree="$dir" \
    -c user.name=w4rya-backup -c user.email=backup@w4rya.local "$@"
}
svc() { echo "SVC${TAB}$1${TAB}$2${TAB}$3${TAB}$4${TAB}$5"; }

for d in "$SERVICES_PATH"/*/; do
  [[ -d "$d" ]] || continue
  name="$(basename "$d")"
  dir="${d%/}"
  # Same rule as vulnbox.config.SERVICE_RE: the name becomes part of a path.
  if [[ ! "$name" =~ ^[A-Za-z0-9._-]+$ ]]; then
    svc "$name" error "" 0 "unsafe directory name, skipped"
    continue
  fi
  repo="$BACKUP_ROOT/$name.git"
  status=updated
  if [[ ! -d "$repo" ]]; then
    if ! git init -q --bare "$repo" >/dev/null 2>&1; then
      svc "$name" error "" 0 "git init failed"
      continue
    fi
    status=created
  fi

  mkdir -p "$repo/info"
  : >"$repo/info/exclude"
  while IFS= read -r -d '' f; do
    rel="${f#"$dir"/}"
    echo "BIG${TAB}${name}${TAB}${rel}${TAB}$(stat -c %s "$f" 2>/dev/null || echo 0)"
    # Anchor at the work-tree root and escape gitignore glob characters, so
    # the pattern matches exactly this one file.
    printf '/%s\n' "$(printf '%s' "$rel" | sed 's/[][*?\\]/\\&/g')" >>"$repo/info/exclude"
  done < <(find "$dir" -type f -size +"${MAX_BYTES}"c -print0 2>/dev/null)

  if ! g add -A >/dev/null 2>&1; then
    svc "$name" error "" 0 "git add failed"
    continue
  fi
  if [[ "$status" == created ]]; then
    # --allow-empty: even an empty directory gets a baseline commit, so the
    # repo always has a branch to clone.
    if ! g commit -q --allow-empty -m "baseline $STAMP" >/dev/null 2>&1; then
      svc "$name" error "" 0 "git commit failed"
      continue
    fi
  elif g diff --cached --quiet 2>/dev/null; then
    status=unchanged
  elif ! g commit -q -m "snapshot $STAMP" >/dev/null 2>&1; then
    svc "$name" error "" 0 "git commit failed"
    continue
  fi
  svc "$name" "$status" "$(g rev-parse --short HEAD 2>/dev/null)" "$(g ls-files 2>/dev/null | wc -l)" ""
done
