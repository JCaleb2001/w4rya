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
# Later runs only commit when something changed.
#
# A snapshot holds every file in the directory, including the ones the
# service's own .gitignore hides (`add -f`): its .env or its database are what
# a restore needs. Two kinds of path are left out, and reported:
#   - files over max_file_bytes (dumps, build artifacts, stray pcaps);
#   - nested git checkouts, of which git would store only a link to a commit,
#     never the files.
# They are kept out of `git add` with exclude pathspecs, so a huge file is
# never hashed into the repo, and unstaged in case an earlier snapshot holds
# them: a file that grows past the cap leaves the snapshot.
#
# Output (tab-separated, one record per line):
#   SVC   <TAB> <name> <TAB> created|updated|unchanged|error <TAB> <commit> <TAB> <files> <TAB> <detail>
#   BIG   <TAB> <name> <TAB> <relative path> <TAB> <bytes>
#   NEST  <TAB> <name> <TAB> <relative path>
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
# Runs from the service directory, so pathspecs are relative to its root.
# -c identity: commit without writing any git config on the vulnbox.
g() {
  git -C "$dir" --git-dir="$repo" --work-tree="$dir" \
    -c user.name=w4rya-backup -c user.email=backup@w4rya.local "$@"
}
svc() { echo "SVC${TAB}$1${TAB}$2${TAB}$3${TAB}$4${TAB}$5"; }
# File names are other people's data (a service may create files with any
# name): a tab or newline in one must not break the record format.
clean() { local s="${1//$'\t'/?}"; printf '%s' "${s//$'\n'/?}"; }
# ${a[@]+"${a[@]}"}: expands an empty array without tripping `set -u` on
# bash < 4.4.
in_nested() {
  local sub
  for sub in ${nested[@]+"${nested[@]}"}; do
    [[ "$1" == "$sub"/* ]] && return 0
  done
  return 1
}

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
  if [[ ! -d "$repo" ]] && ! git init -q --bare "$repo" >/dev/null 2>&1; then
    svc "$name" error "" 0 "git init failed"
    continue
  fi

  nested=()
  left_out=()
  # The service's own top-level .git, if it has one, is not nested: git never
  # adds a path named .git.
  while IFS= read -r -d '' p; do
    [[ "$p" == ./.git ]] && continue
    rel="${p#./}"
    rel="${rel%/.git}"
    nested+=("$rel")
    left_out+=("$rel")
    echo "NEST${TAB}${name}${TAB}$(clean "$rel")"
  done < <(cd "$dir" && find . -name .git -prune -print0 2>/dev/null)
  while IFS= read -r -d '' p; do
    rel="${p#./}"
    in_nested "$rel" && continue
    left_out+=("$rel")
    echo "BIG${TAB}${name}${TAB}$(clean "$rel")${TAB}$(stat -c %s "$dir/$rel" 2>/dev/null || echo 0)"
  done < <(cd "$dir" && find . -name .git -prune -o -type f -size +"${MAX_BYTES}"c -print0 2>/dev/null)

  # literal: a name with * or [ in it must match only itself.
  unstage=()
  exclude=()
  for rel in ${left_out[@]+"${left_out[@]}"}; do
    unstage+=(":(literal)$rel")
    exclude+=(":(exclude,literal)$rel")
  done
  if (( ${#unstage[@]} )) && ! g rm -r -q -f --cached --ignore-unmatch -- "${unstage[@]}" >/dev/null 2>&1; then
    svc "$name" error "" 0 "git rm --cached failed"
    continue
  fi
  if ! g add -A -f -- . ${exclude[@]+"${exclude[@]}"} >/dev/null 2>&1; then
    svc "$name" error "" 0 "git add failed"
    continue
  fi

  if ! g rev-parse -q --verify HEAD >/dev/null 2>&1; then
    # --allow-empty: even an empty directory gets a baseline commit, so the
    # repo always has a branch to clone.
    status=created
    g commit -q --allow-empty -m "baseline $STAMP" >/dev/null 2>&1 || status=error
  elif g diff --cached --quiet 2>/dev/null; then
    status=unchanged
  else
    status=updated
    g commit -q -m "snapshot $STAMP" >/dev/null 2>&1 || status=error
  fi
  if [[ "$status" == error ]]; then
    svc "$name" error "" 0 "git commit failed"
    continue
  fi
  svc "$name" "$status" "$(g rev-parse HEAD 2>/dev/null)" "$(g ls-files 2>/dev/null | wc -l)" ""
done
exit 0
