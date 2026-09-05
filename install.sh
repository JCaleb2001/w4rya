#!/usr/bin/env bash
#
# w4rya installer — one command, four questions.
#
#   ./install.sh            install or re-install (idempotent, safe to re-run)
#   ./install.sh --check    diagnose an existing install, read-only
#   ./install.sh --help     everything else
#
# Deliberately NOT provided: a --admin-password flag. Argv is world-readable
# through /proc, so the password only ever arrives on stdin.

set -euo pipefail
IFS=$'\n\t'

cd "$(dirname "${BASH_SOURCE[0]}")"

readonly LOG="./install.log"
readonly ENV_FILE="./.env"
readonly ENV_EXAMPLE="./.env.example"
readonly DEFAULT_COMPOSE="docker-compose.yml"
readonly SURICATA_COMPOSE="docker-compose-suricata.yml"
readonly DEFAULT_UI_PORT=3001

# --- flags -----------------------------------------------------------------
MODE=install
ASSUME_YES=0
INTERACTIVE=1
USE_SURICATA=""
DO_BUILD=1
ROTATE_SECRET=0
RESET_ENV=0
RESET_TICK=0
ALLOW_ROOT=0
ADMIN_PASSWORD_FILE=""

# --- output ----------------------------------------------------------------
if [[ -t 1 ]]; then
  C_OK=$'\033[32m'; C_WARN=$'\033[33m'; C_ERR=$'\033[31m'
  C_DIM=$'\033[2m'; C_B=$'\033[1m'; C_R=$'\033[0m'
else
  C_OK=""; C_WARN=""; C_ERR=""; C_DIM=""; C_B=""; C_R=""
fi

ok()    { printf '%s[ok]%s   %s\n'   "$C_OK"   "$C_R" "$*"; }
warn()  { printf '%s[warn]%s %s\n'   "$C_WARN" "$C_R" "$*"; }
fail()  { printf '%s[FAIL]%s %s\n'   "$C_ERR"  "$C_R" "$*"; }
info()  { printf '%s       %s%s\n'   "$C_DIM"  "$*"  "$C_R"; }
step()  { printf '\n%s▎ %s%s\n'      "$C_B"    "$*"  "$C_R"; }
die()   { fail "$*"; exit 1; }

CHECK_FAILURES=0
check_fail() { fail "$*"; CHECK_FAILURES=$((CHECK_FAILURES + 1)); }

usage() {
  cat <<'USAGE'
w4rya installer

  ./install.sh                     interactive install / re-install
  ./install.sh --check             diagnose this install (read-only, no prompts)

Options
  --yes                  accept every default; still prompts for the admin password
  --non-interactive      no prompts at all; password from --admin-password-file or stdin
  --suricata             include the Suricata container (rule-based tagging)
  --no-suricata          plain stack (default)
  --no-build             skip the image build, just bring the stack up
  --rotate-secret        generate a new session secret (logs everyone out)
  --reset-env            recreate .env from .env.example (backs the old one up first)
  --reset-tick           re-baseline the tick clock to now (new game, new ticks)
  --admin-password-file  read the admin password from this file (CI only)
  --allow-root           permit running as root (not recommended)
  -h, --help             this message

The admin password is never accepted as a command-line argument: argv is
world-readable via /proc.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --check)               MODE=check ;;
    --yes|-y)              ASSUME_YES=1 ;;
    --non-interactive)     INTERACTIVE=0; ASSUME_YES=1 ;;
    --suricata)            USE_SURICATA=1 ;;
    --no-suricata)         USE_SURICATA=0 ;;
    --no-build)            DO_BUILD=0 ;;
    --rotate-secret)       ROTATE_SECRET=1 ;;
    --reset-env)           RESET_ENV=1 ;;
    --reset-tick)          RESET_TICK=1 ;;
    --admin-password-file) ADMIN_PASSWORD_FILE="${2:-}"; shift ;;
    --allow-root)          ALLOW_ROOT=1 ;;
    -h|--help)             usage; exit 0 ;;
    *) die "unknown option: $1  (try --help)" ;;
  esac
  shift
done

trap 'rc=$?; if [[ $rc -ne 0 && $rc -ne 130 ]]; then
  fail "aborted on line $LINENO (exit $rc)"
  info "see $LOG for details — install.sh is safe to re-run"
fi' ERR

# --- .env helpers ----------------------------------------------------------
# Read a key from .env without sourcing it. Sourcing would execute whatever is
# in there and mangles values containing '#'.
env_get() {
  local key="$1" file="${2:-$ENV_FILE}"
  [[ -f "$file" ]] || return 0
  awk -F= -v k="$key" '
    $1 == k { sub("^" k "=", ""); gsub(/^"|"$/, ""); val = $0 }
    END { print val }
  ' "$file"
}

# env_get always exits 0 (awk prints an empty line for a missing key), so
# `env_get X || echo default` never fires the fallback. Use this instead.
env_get_or() {
  local v; v="$(env_get "$1")"
  printf '%s\n' "${v:-$2}"
}

ENV_BACKED_UP=0
env_backup_once() {
  [[ $ENV_BACKED_UP -eq 1 ]] && return 0
  [[ -f "$ENV_FILE" ]] || return 0
  local b=".env.bak.$(date -u +%Y%m%dT%H%M%SZ)"
  cp "$ENV_FILE" "$b"
  info "backed up existing .env → $b"
  ENV_BACKED_UP=1
}

# Upsert KEY=VALUE. Replaces an existing line, or uncomments a commented one
# (this is how BPF and VISUALIZER_URL stop emitting "variable is not set"),
# or appends. Uses awk into a temp file rather than sed -i, which is not
# portable and replaces the file's inode.
env_set() {
  local key="$1" value="$2"
  env_backup_once
  local tmp
  tmp="$(mktemp "${ENV_FILE}.XXXXXX")"
  KEY="$key" VALUE="$value" awk '
    BEGIN { k = ENVIRON["KEY"]; v = ENVIRON["VALUE"]; done = 0 }
    # First hit wins and is rewritten in place...
    !done && $0 ~ "^" k "=" { print k "=" v; done = 1; next }
    # ...including a commented-out one, which is how BPF and VISUALIZER_URL
    # stop emitting "variable is not set".
    !done && $0 ~ "^[[:space:]]*#[[:space:]]*" k "=" { print k "=" v; done = 1; next }
    # Any later duplicate is dropped. Compose takes last-wins, so a stale
    # duplicate further down would silently override the value we just wrote.
    done && $0 ~ "^" k "=" { next }
    { print }
    END { if (!done) { print ""; print k "=" v } }
  ' "$ENV_FILE" > "$tmp"
  mv "$tmp" "$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

gen_secret() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  elif [[ -r /dev/urandom ]]; then
    head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'
  elif command -v python3 >/dev/null 2>&1; then
    python3 -c 'import secrets; print(secrets.token_hex(32))'
  else
    return 1
  fi
}

ask() {
  local prompt="$1" default="$2" reply
  if [[ $INTERACTIVE -eq 0 || $ASSUME_YES -eq 1 ]]; then
    printf '%s\n' "$default"
    return 0
  fi
  read -r -p "$(printf '%s%s%s [%s]: ' "$C_B" "$prompt" "$C_R" "$default")" reply </dev/tty || reply=""
  printf '%s\n' "${reply:-$default}"
}

compose() { docker compose -f "$COMPOSE_FILE" "$@"; }

port_in_use() {
  local p="$1"
  if command -v ss >/dev/null 2>&1; then
    ss -ltn 2>/dev/null | awk '{print $4}' | grep -qE "[:.]${p}$"
  else
    ! (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && return 1 || { exec 3<&- 3>&-; return 0; }
  fi
}

# Account names, one per line. users.yaml is two levels deep and the name is
# the only key indented by exactly two spaces.
user_names() {
  local f="./auth/users.yaml"
  [[ -f "$f" ]] || return 0
  sed -n 's/^  \([A-Za-z0-9_-]\{1,32\}\):[[:space:]]*$/\1/p' "$f"
}

user_count() {
  local f="./auth/users.yaml"
  [[ -f "$f" ]] || { echo 0; return; }
  grep -c 'password_hash' "$f" 2>/dev/null || echo 0
}

lan_ip() { ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}'; }

# ===========================================================================
# preflight
# ===========================================================================
preflight() {
  step "Preflight"

  [[ "${BASH_VERSINFO[0]}" -ge 4 ]] || die "bash 4+ required (run with bash, not sh)"
  ok "bash ${BASH_VERSION%%(*}"

  command -v docker >/dev/null 2>&1 || die "docker not found — install Docker Engine first"
  docker info >/dev/null 2>&1 || die "cannot reach the Docker daemon.
       Start it, or add yourself to the 'docker' group and log back in.
       Do NOT re-run this with sudo: it leaves auth/ and suricata-rules/ root-owned."
  ok "docker daemon reachable"

  docker compose version >/dev/null 2>&1 \
    || die "Docker Compose v2 required ('docker compose'). The old 'docker-compose' v1 is not supported."
  ok "compose $(docker compose version --short 2>/dev/null || echo v2)"

  if [[ "$(id -u)" -eq 0 && $ALLOW_ROOT -eq 0 ]]; then
    die "refusing to run as root: it makes auth/users.yaml and suricata-rules/ root-owned
       on the host, which you then cannot edit. Run as your normal user (you need to be
       in the 'docker' group). Override with --allow-root if you really mean it."
  fi
  ok "running as $(id -un), not root"

  gen_secret >/dev/null 2>&1 || die "need one of: openssl, /dev/urandom, or python3 to generate a session secret"

  local root avail_kb avail_gb
  root="$(docker info -f '{{.DockerRootDir}}' 2>/dev/null || echo /var/lib/docker)"
  avail_kb="$(df -Pk "$root" 2>/dev/null | awk 'NR==2 {print $4}')" || avail_kb=""
  if [[ -n "${avail_kb:-}" ]]; then
    avail_gb=$((avail_kb / 1024 / 1024))
    if   [[ $avail_gb -lt 3 ]];  then die "only ${avail_gb} GB free on $root — the images need ~5 GB"
    elif [[ $avail_gb -lt 10 ]]; then warn "${avail_gb} GB free on $root — tight; images need ~5 GB and pcaps grow fast"
    else ok "disk: ${avail_gb} GB free on $root"; fi
  fi

  local ram_mb
  ram_mb="$(free -m 2>/dev/null | awk '/^Mem:/ {print $2}')" || ram_mb=""
  if [[ -n "$ram_mb" ]]; then
    if [[ $ram_mb -lt 8192 ]]; then
      warn "${ram_mb} MB RAM — the container memory limits sum to ~6 GB, so heavy ingest may get OOM-killed"
    else
      ok "RAM: ${ram_mb} MB"
    fi
  fi

  if [[ "$MODE" == "install" ]] && ! curl -fsI --max-time 5 https://github.com >/dev/null 2>&1; then
    warn "github.com unreachable — the timescale image git-clones pg_hint_plan at build time, so a first build will fail offline"
  fi

  if command -v getenforce >/dev/null 2>&1 && [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]]; then
    warn "SELinux is enforcing — if the api cannot read ./auth, add :z to that bind mount"
  fi
}

# ===========================================================================
# install
# ===========================================================================
do_install() {
  printf '%s\n' "$C_B
 w4rya installer$C_R"
  : > /dev/null
  echo "--- install.sh run $(date -u +%Y-%m-%dT%H:%M:%SZ) ---" >> "$LOG"

  preflight

  # --- .env ---------------------------------------------------------------
  step "Configuration"
  if [[ $RESET_ENV -eq 1 && -f "$ENV_FILE" ]]; then
    env_backup_once
    rm -f "$ENV_FILE"
  fi
  if [[ ! -f "$ENV_FILE" ]]; then
    [[ -f "$ENV_EXAMPLE" ]] || die "$ENV_EXAMPLE missing — is this a w4rya checkout?"
    cp "$ENV_EXAMPLE" "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    # Nothing to preserve: this .env is a pristine copy of .env.example, and
    # the first env_set would otherwise leave a useless .env.bak.* next to it
    # on every fresh clone.
    ENV_BACKED_UP=1
    ok "created .env from .env.example"
  else
    chmod 600 "$ENV_FILE"
    ok "using existing .env (values you already set are kept)"
  fi

  # session secret
  local secret; secret="$(env_get W4RYA_SECRET_KEY)"
  if [[ -n "$secret" && $ROTATE_SECRET -eq 0 ]]; then
    # Rewrite it with its own value: harmless, and it collapses any duplicate
    # W4RYA_SECRET_KEY lines left behind by hand-editing.
    env_set W4RYA_SECRET_KEY "$secret"
    ok "session secret: kept existing"
  else
    [[ -n "$secret" && $ROTATE_SECRET -eq 1 ]] && warn "rotating the session secret — every logged-in user will be signed out"
    env_set W4RYA_SECRET_KEY "$(gen_secret)"
    ok "session secret: generated"
  fi

  # --- the four questions -------------------------------------------------
  step "Setup"

  local pcap_dir; pcap_dir="$(ask 'Where are your pcaps?' "$(env_get_or TRAFFIC_DIR_HOST ./services/test_pcap)")"
  pcap_dir="${pcap_dir%\"}"; pcap_dir="${pcap_dir#\"}"
  if [[ ! -d "$pcap_dir" ]]; then
    if [[ "$(ask "  $pcap_dir does not exist — create it?" y)" =~ ^[Yy] ]]; then
      mkdir -p "$pcap_dir"
    else
      die "pcap directory $pcap_dir does not exist"
    fi
  fi
  env_set TRAFFIC_DIR_HOST "\"$pcap_dir\""
  local n_pcaps; n_pcaps="$(find "$pcap_dir" -maxdepth 1 -name '*.pcap*' -type f 2>/dev/null | wc -l)"
  if [[ "$n_pcaps" -eq 0 ]]; then
    warn "no .pcap files in $pcap_dir yet — the assembler will idle until you copy some in"
  else
    ok "$n_pcaps pcap file(s) in $pcap_dir"
  fi
  info "note: only files whose last extension starts with .pcap are ingested."
  info "a rotated name like capture.pcap.1712345678 is silently ignored."

  local flag_regex; flag_regex="$(ask 'Flag format (regex)?' "$(env_get_or FLAG_REGEX '[A-Z0-9]{31}=')")"
  flag_regex="${flag_regex%\"}"; flag_regex="${flag_regex#\"}"
  # grep exits 0 = matched, 1 = no match, 2+ = the regex itself is invalid.
  local rc=0
  printf '' | grep -qE "$flag_regex" 2>/dev/null || rc=$?
  [[ $rc -le 1 ]] || die "that is not a valid regex: $flag_regex"
  if printf '' | grep -qE "$flag_regex" 2>/dev/null; then
    warn "that regex matches the empty string — it will tag every flow as containing a flag"
  fi
  env_set FLAG_REGEX "\"$flag_regex\""

  local tick_ms; tick_ms="$(env_get_or TICK_LENGTH 180000)"
  [[ "$tick_ms" =~ ^[0-9]+$ ]] || tick_ms=180000
  local tick; tick="$(ask 'Tick length in seconds?' "$((tick_ms / 1000))")"
  [[ "$tick" =~ ^[0-9]+$ && "$tick" -gt 0 ]] || die "tick length must be a positive integer, got: $tick"
  env_set TICK_LENGTH "$((tick * 1000))"
  # TICK_START is the epoch every tick number is counted from. Re-stamping it
  # on an existing install renumbers every tick and shifts the graph buckets
  # under a game already in progress -- and the summary tells you to re-run
  # this script once your real capture directory is ready. So it is written
  # only when there is nothing worth keeping: no value at all, or still the
  # placeholder .env.example ships. --reset-tick forces a new baseline.
  local tick_start; tick_start="$(env_get TICK_START)"
  local tick_start_stale; tick_start_stale="$(env_get TICK_START "$ENV_EXAMPLE")"
  if [[ $RESET_TICK -eq 1 || -z "$tick_start" || "$tick_start" == "$tick_start_stale" ]]; then
    env_set TICK_START "\"$(date -u +%Y-%m-%dT%H:%M:00Z)\""
    ok "tick: ${tick}s, starting now"
  else
    ok "tick: ${tick}s, counting from $tick_start"
    info "--reset-tick re-baselines the clock to now"
  fi

  # compose file
  if [[ -z "$USE_SURICATA" ]]; then USE_SURICATA=0; fi
  if [[ "$USE_SURICATA" -eq 1 ]]; then
    COMPOSE_FILE="$SURICATA_COMPOSE"
  else
    COMPOSE_FILE="$DEFAULT_COMPOSE"
  fi
  local prev_compose; prev_compose="$(env_get W4RYA_COMPOSE_FILE)"
  if [[ -n "$prev_compose" && "$prev_compose" != "$COMPOSE_FILE" && -f "$prev_compose" ]]; then
    warn "switching stacks ($prev_compose → $COMPOSE_FILE); stopping the old one first"
    docker compose -f "$prev_compose" down --remove-orphans >>"$LOG" 2>&1 || true
  fi
  env_set W4RYA_COMPOSE_FILE "$COMPOSE_FILE"
  ok "stack: $COMPOSE_FILE"

  # port
  local port; port="$(env_get_or W4RYA_UI_PORT "$DEFAULT_UI_PORT")"
  if port_in_use "$port" && ! compose ps --status running 2>/dev/null | grep -q frontend; then
    warn "port $port is already in use"
    port="$(ask '  use which port instead?' "$((port + 10))")"
    port_in_use "$port" && die "port $port is busy too — free one up and re-run"
  fi
  env_set W4RYA_UI_PORT "$port"
  ok "UI port: $port"

  # suricata dirs — nothing else creates these, and if Docker auto-creates
  # them they come out root-owned.
  if [[ "$USE_SURICATA" -eq 1 ]]; then
    local sdir; sdir="$(env_get_or SURICATA_DIR_HOST ./suricata)"
    sdir="${sdir%\"}"; sdir="${sdir#\"}"
    mkdir -p "$sdir"/{etc,lib/rules,log}
    ok "suricata dirs under $sdir"
  fi
  mkdir -p ./suricata-rules ./suricata-run ./auth
  [[ -f ./suricata-rules/suricata.rules ]] || touch ./suricata-rules/suricata.rules

  # --- build + up ---------------------------------------------------------
  if [[ $DO_BUILD -eq 1 ]]; then
    step "Building images (first run takes a while — it compiles a Postgres extension)"
    local log_mark; log_mark=$(( $(wc -l <"$LOG" 2>/dev/null || echo 0) + 1 ))
    if ! compose build >>"$LOG" 2>&1; then
      # $LOG is append-only across runs, so diagnose from what THIS build wrote:
      # a stale error from an earlier attempt would otherwise pick the workaround
      # for a failure that has already been fixed. Held in a variable and matched
      # with a here-string rather than piped — under `pipefail`, `grep -q` exits
      # on the first match and the SIGPIPE'd producer would make the whole
      # pipeline report 141, i.e. every one of these tests would read as false.
      local build_out; build_out="$(tail -n "+$log_mark" "$LOG")"
      if grep -qE 'Temporary failure in name resolution|Could not resolve host|Failed to establish a new connection' <<<"$build_out"; then
        warn "BuildKit's DNS is wedged — a known issue on some hosts. Retrying with --network=host."
        DOCKER_BUILDKIT=0 compose build >>"$LOG" 2>&1 \
          || { tail -30 "$LOG"; die "build failed even with the workaround — see $LOG"; }
      elif grep -qE 'ESOCKETTIMEDOUT|ETIMEDOUT|There appears to be trouble with your network connection|context deadline exceeded|TLS handshake timeout|i/o timeout' <<<"$build_out"; then
        # Not a broken network — a slow one. Compose builds every service at once,
        # so on a thin link (a NAT'd VM, hotel wifi, a CTF venue) ten downloads
        # share the pipe and each one stalls past its own timeout. Building one
        # service at a time gives each the whole link.
        warn "a download timed out — the parallel build is starving your connection."
        info "retrying one service at a time; slower, but it finishes"
        local svc
        for svc in $(compose config --services); do
          info "building $svc"
          # Services that only pull an image (suricata) are a no-op here, not an error.
          compose build "$svc" >>"$LOG" 2>&1 \
            || { tail -30 "$LOG"; die "build failed on $svc even one at a time — see $LOG"; }
        done
      else
        tail -30 "$LOG"
        die "build failed — see $LOG"
      fi
    fi
    ok "images built"
  fi

  step "Starting the stack"
  compose up -d >>"$LOG" 2>&1 || { tail -30 "$LOG"; die "docker compose up failed — see $LOG"; }

  printf '       waiting for the api to become healthy'
  local waited=0
  # --max-time is load-bearing: the frontend proxy accepts the connection long
  # before the api behind it answers, so a curl without a deadline hangs here
  # forever instead of retrying.
  until curl -fsS --connect-timeout 3 --max-time 5 "http://127.0.0.1:${port}/api/healthz" >/dev/null 2>&1; do
    [[ $waited -ge 180 ]] && { printf '\n'; compose logs api --tail 40; die "api did not come up within 180s"; }
    printf '.'; sleep 3; waited=$((waited + 3))
  done
  printf '\n'
  ok "api healthy (${waited}s)"

  # --- admin account ------------------------------------------------------
  step "Admin account"
  local existing; existing="$(user_count)"
  if [[ "$existing" -gt 0 ]]; then
    ok "$existing account(s) already exist — skipping"
    info "add more from the UI at /users, or with auth/add_user.py"
    # create_admin is what normally sets ADMIN_USER, so on a re-run the
    # summary would announce "no account yet" one line after saying accounts
    # exist. Name the single account when there is one, stay vague otherwise.
    if [[ "$existing" -eq 1 ]]; then
      ADMIN_USER="$(user_names | head -1)"
    else
      ADMIN_USER="one of your $existing existing accounts"
    fi
  else
    create_admin "$port"
  fi

  print_summary "$port"
}

create_admin() {
  local port="$1" admin_user pw pw2

  if [[ -n "$ADMIN_PASSWORD_FILE" ]]; then
    [[ -r "$ADMIN_PASSWORD_FILE" ]] || die "cannot read $ADMIN_PASSWORD_FILE"
    admin_user="$(ask 'Admin username' admin)"
    printf '%s\n' "$(head -n1 "$ADMIN_PASSWORD_FILE")" \
      | compose exec -T api python /app/auth/add_user.py "$admin_user" --role admin --stdin >>"$LOG" 2>&1 \
      || die "could not create the admin account — see $LOG"
    ok "admin '$admin_user' created (password from file)"
    ADMIN_USER="$admin_user"
    return 0
  fi

  if [[ $INTERACTIVE -eq 0 ]]; then
    warn "non-interactive and no --admin-password-file: no account created"
    info "open http://localhost:${port} and the first-run wizard will ask you to create one"
    ADMIN_USER=""
    return 0
  fi

  while :; do
    admin_user="$(ask 'Admin username' "${USER:-admin}")"
    [[ "$admin_user" =~ ^[A-Za-z0-9_-]{1,32}$ ]] && break
    warn "username must match [A-Za-z0-9_-]{1,32}"
  done

  while :; do
    # `read` never lands in shell history, and the value is piped to the
    # container through stdin — never argv (visible in /proc), never an env
    # var (visible in docker inspect), never a file.
    read -rsp "$(printf '%sPassword%s (min 8 chars): ' "$C_B" "$C_R")" pw </dev/tty; echo
    read -rsp "$(printf '%sConfirm%s:              ' "$C_B" "$C_R")" pw2 </dev/tty; echo
    if [[ "$pw" != "$pw2" ]];  then warn "passwords don't match"; continue; fi
    if [[ "${#pw}" -lt 8 ]];   then warn "password must be at least 8 characters"; continue; fi
    break
  done

  if printf '%s\n' "$pw" \
      | compose exec -T api python /app/auth/add_user.py "$admin_user" --role admin --stdin >>"$LOG" 2>&1; then
    ok "admin '$admin_user' created"
  else
    unset pw pw2
    die "could not create the admin account — see $LOG"
  fi
  unset pw pw2
  ADMIN_USER="$admin_user"
}

print_summary() {
  local port="$1" ip; ip="$(lan_ip || true)"
  cat <<EOF

${C_B}w4rya is running.${C_R}

  UI              http://localhost:${port}
EOF
  [[ -n "$ip" ]] && printf '                  http://%s:%s   %s(teammates on your network)%s\n' "$ip" "$port" "$C_DIM" "$C_R"
  cat <<EOF
  Sign in as      ${ADMIN_USER:-<none yet — the UI will ask you to create one>}
  Stack           ${COMPOSE_FILE}
  Pcaps           $(env_get TRAFFIC_DIR_HOST)

${C_B}Next${C_R}
  1. Set your services and teams in the UI at /config
  2. Add your teammates at /users  (admin only) — each gets their own login
  3. When your real capture directory is ready, re-run ./install.sh

  ./install.sh --check      diagnose this install
  ./scripts/smoke.sh        verify the running stack over HTTP
  docker compose logs -f assembler

${C_DIM}The session cookie is not marked Secure, because this serves plain HTTP.
Keep the instance on your internal network or behind a VPN. If you put TLS in
front of it, set W4RYA_COOKIE_SECURE=1 in .env and restart the api.${C_R}
EOF
}

# ===========================================================================
# --check
# ===========================================================================
do_check() {
  printf '%s\n' "$C_B
 w4rya doctor$C_R"

  step "Environment"
  [[ -f "$ENV_FILE" ]] || { check_fail ".env is missing — run ./install.sh"; exit 1; }
  ok ".env present"
  [[ "$(stat -c %a "$ENV_FILE")" == "600" ]] && ok ".env mode 600" || warn ".env is not mode 600 (it holds the session secret)"

  local secret; secret="$(env_get W4RYA_SECRET_KEY)"
  if [[ -z "$secret" ]];        then check_fail "W4RYA_SECRET_KEY is empty — the api cannot start"
  elif [[ ${#secret} -lt 32 ]]; then warn "W4RYA_SECRET_KEY is shorter than 32 chars"
  else ok "session secret set (${#secret} chars)"; fi

  COMPOSE_FILE="$(env_get_or W4RYA_COMPOSE_FILE "$DEFAULT_COMPOSE")"
  if [[ -f "$COMPOSE_FILE" ]]; then ok "stack: $COMPOSE_FILE"
  else check_fail "W4RYA_COMPOSE_FILE points at '$COMPOSE_FILE', which does not exist"; fi

  local cfg_out
  if cfg_out="$(compose config -q 2>&1)"; then
    if grep -q 'variable is not set' <<<"$cfg_out"; then
      grep 'variable is not set' <<<"$cfg_out" | while read -r l; do check_fail "$l"; done
    else
      ok "compose config valid, no unset variables"
    fi
  else
    check_fail "compose config invalid: $(head -1 <<<"$cfg_out")"
  fi

  step "Data"
  local pcap_dir; pcap_dir="$(env_get TRAFFIC_DIR_HOST)"; pcap_dir="${pcap_dir%\"}"; pcap_dir="${pcap_dir#\"}"
  if [[ -d "$pcap_dir" ]]; then
    local n; n="$(find "$pcap_dir" -maxdepth 1 -name '*.pcap*' -type f 2>/dev/null | wc -l)"
    [[ "$n" -gt 0 ]] && ok "pcaps: $n file(s) in $pcap_dir" \
                     || warn "no pcaps in $pcap_dir — the assembler is running but ingesting nothing"
    local odd; odd="$(find "$pcap_dir" -maxdepth 1 -type f -name '*pcap*' ! -name '*.pcap' ! -name '*.pcapng' 2>/dev/null | head -3)"
    [[ -n "$odd" ]] && { warn "these will be silently ignored (last extension is not .pcap*):"; printf '       %s\n' $odd; }
  else
    check_fail "TRAFFIC_DIR_HOST '$pcap_dir' does not exist"
  fi

  step "Permissions"
  local rootowned; rootowned="$(find ./auth ./suricata-rules ./suricata-run -uid 0 2>/dev/null | head -5)"
  if [[ -n "$rootowned" ]]; then
    warn "root-owned files (a sudo run, probably):"
    printf '       %s\n' $rootowned
    info "fix: sudo chown -R \$USER:\$USER auth suricata-rules suricata-run"
  else
    ok "no root-owned files in auth/, suricata-rules/, suricata-run/"
  fi

  step "Runtime"
  local not_running; not_running="$(compose ps --format '{{.Service}} {{.State}}' 2>/dev/null | awk '$2 != "running" {print $1}')"
  if [[ -n "$not_running" ]]; then
    for s in $not_running; do check_fail "service '$s' is not running"; done
  else
    ok "all services running"
  fi

  local port; port="$(env_get_or W4RYA_UI_PORT "$DEFAULT_UI_PORT")"
  if curl -fsS --connect-timeout 3 --max-time 5 "http://127.0.0.1:${port}/api/healthz" >/dev/null 2>&1; then
    ok "frontend proxy → api → timescale reachable on :${port}"
  elif compose exec -T api python -c "import urllib.request;urllib.request.urlopen('http://localhost:5000/healthz',timeout=3)" >/dev/null 2>&1; then
    check_fail "the api is healthy but the frontend /api proxy on :${port} is not responding"
  else
    check_fail "api unreachable on :${port} — try: docker compose logs api"
  fi

  local st; st="$(curl -fsS --connect-timeout 3 --max-time 5 "http://127.0.0.1:${port}/api/setup/status" 2>/dev/null || true)"
  if grep -q '"needs_setup":true' <<<"$st"; then
    warn "no account exists yet — run ./install.sh, or open http://localhost:${port} for the wizard"
  elif [[ -n "$st" ]]; then
    ok "accounts configured ($(user_count) in users.yaml)"
  fi

  # The rules-path check: the api writes ./suricata-rules/suricata.rules but
  # suricata reads /var/lib/suricata/rules. If those are different inodes,
  # every rule made in the UI goes to a file suricata never reads.
  if [[ "$COMPOSE_FILE" == "$SURICATA_COMPOSE" ]]; then
    step "Suricata"
    local a b
    a="$(compose exec -T api      stat -c %s /app/suricata-rules/suricata.rules      2>/dev/null || echo x)"
    b="$(compose exec -T suricata stat -c %s /var/lib/suricata/rules/suricata.rules  2>/dev/null || echo y)"
    if [[ "$a" == "$b" && "$a" != "x" ]]; then
      ok "api and suricata see the same rules file"
    else
      check_fail "api and suricata see DIFFERENT rules files — rules created in the UI will never load"
    fi
  fi

  printf '\n'
  if [[ $CHECK_FAILURES -eq 0 ]]; then
    ok "no problems found"
    exit 0
  else
    fail "$CHECK_FAILURES problem(s) found"
    exit 1
  fi
}

# ===========================================================================
COMPOSE_FILE="$DEFAULT_COMPOSE"
ADMIN_USER=""
case "$MODE" in
  check)   do_check ;;
  install) do_install ;;
esac
