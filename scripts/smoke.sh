#!/usr/bin/env bash
# End-to-end smoke test against a RUNNING w4rya stack.
#
#   ./scripts/smoke.sh              read-only checks (safe during a CTF)
#   ./scripts/smoke.sh --yellow     also exercise writes, restoring each one
#
# Credentials come from SMOKE_USER / SMOKE_PASS, or are prompted for. Never
# passed as arguments: argv is world-readable through /proc.
#
# Goes through the frontend's /api proxy rather than straight at the api
# container, because that is the path the browser actually takes — a broken
# proxy is a real failure mode this would otherwise miss.

set -uo pipefail   # deliberately not -e: we want a full tally, not a stop at the first failure
cd "$(dirname "${BASH_SOURCE[0]}")/.."

RUN_YELLOW=0
for arg in "$@"; do
  case "$arg" in
    --yellow) RUN_YELLOW=1 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

if [[ -t 1 ]]; then
  C_OK=$'\033[32m'; C_ERR=$'\033[31m'; C_SKIP=$'\033[2m'; C_B=$'\033[1m'; C_R=$'\033[0m'
else
  C_OK=""; C_ERR=""; C_SKIP=""; C_B=""; C_R=""
fi

env_get() { awk -F= -v k="$1" '$1==k{sub("^" k "=",""); gsub(/^"|"$/,""); v=$0} END{print v}' .env 2>/dev/null; }

PORT="$(env_get W4RYA_UI_PORT)"; PORT="${PORT:-3001}"
BASE="http://127.0.0.1:${PORT}/api"

TMPD="$(mktemp -d)"; trap 'rm -rf "$TMPD"' EXIT
JAR="$TMPD/cookies"; BODY="$TMPD/body"

N_OK=0; N_FAIL=0; N_SKIP=0

req() {
  local method="$1" path="$2" data="${3:-}"
  local args=(-s -o "$BODY" -w '%{http_code}' -b "$JAR" -c "$JAR"
              --connect-timeout 3 --max-time 20 -X "$method" "${BASE}${path}")
  [[ -n "$data" ]] && args+=(-H 'Content-Type: application/json' -d "$data")
  curl "${args[@]}" 2>/dev/null || echo 000
}

expect() {
  local want="$1" method="$2" path="$3" got="$4"
  if [[ "$got" == "$want" ]]; then
    printf '%s[ok]%s   %-6s %-34s %s\n' "$C_OK" "$C_R" "$method" "$path" "$got"
    N_OK=$((N_OK + 1))
  else
    printf '%s[FAIL]%s %-6s %-34s %s  expected %s\n' "$C_ERR" "$C_R" "$method" "$path" "$got" "$want"
    [[ -s "$BODY" ]] && printf '       %s\n' "$(head -c 200 "$BODY")"
    N_FAIL=$((N_FAIL + 1))
  fi
}

get_ok()  { expect 200 GET  "$1" "$(req GET "$1")"; }
skip()    { printf '%s[skip] %-6s %-34s %s%s\n' "$C_SKIP" "" "$1" "$2" "$C_R"; N_SKIP=$((N_SKIP + 1)); }
section() { printf '\n%s▎ %s%s\n' "$C_B" "$1" "$C_R"; }

json_field() { python3 -c "import json,sys;d=json.load(open('$BODY'));print(d.get('$1',''))" 2>/dev/null; }

# --- 0. preflight ----------------------------------------------------------
section "Preflight"
code="$(req GET /healthz)"
if [[ "$code" == "000" ]]; then
  echo "${C_ERR}[FAIL]${C_R} the stack is unreachable on ${BASE} — is it running?" >&2
  exit 2
fi
expect 200 GET /healthz "$code"

code="$(req GET /setup/status)"
expect 200 GET /setup/status "$code"
if grep -q '"needs_setup":true' "$BODY" 2>/dev/null; then
  echo "${C_ERR}[FAIL]${C_R} no account exists yet — run ./install.sh first" >&2
  exit 2
fi

# --- 1. auth ---------------------------------------------------------------
section "Auth"
expect 401 GET /me "$(req GET /me)"

SMOKE_USER="${SMOKE_USER:-}"; SMOKE_PASS="${SMOKE_PASS:-}"
if [[ -z "$SMOKE_USER" ]]; then read -r  -p "user: " SMOKE_USER </dev/tty; fi
if [[ -z "$SMOKE_PASS" ]]; then read -rs -p "password: " SMOKE_PASS </dev/tty; echo; fi

code="$(req POST /login "{\"username\":\"${SMOKE_USER}\",\"password\":\"${SMOKE_PASS}\"}")"
expect 200 POST /login "$code"
if [[ "$code" != "200" ]]; then
  echo "${C_ERR}cannot continue without a session${C_R}" >&2
  exit 1
fi
ROLE="$(json_field role)"
printf '       signed in as %s (role: %s)\n' "$SMOKE_USER" "$ROLE"
unset SMOKE_PASS

expect 200 GET /me "$(req GET /me)"
skip "POST /login (bad password)" "would consume the 5-per-5min lockout budget; set SMOKE_ALLOW_RL=1 to run"

# --- 2. GREEN: read-only ---------------------------------------------------
section "Reads"
for p in /tick_info /services /flag_regex /config /config/services /config/teams \
         /tags /stats "/services/stats?ticks=2" "/attacks?limit=10" /rules; do
  get_ok "$p"
done

# /under_attack has three legitimate outcomes depending on config, so a plain
# "expect 200" would be wrong: 200 = unset (returns {}) or a reachable
# visualizer; 502 = configured but unreachable, which is normal without one;
# 400 = the stored visualizer_url is not a valid http(s) URL, which IS a real
# config problem worth surfacing.
code="$(req GET /under_attack)"
case "$code" in
  200) expect 200 GET /under_attack "$code" ;;
  502) skip "GET /under_attack" "visualizer configured but unreachable (normal if you run none)" ;;
  400) printf '%s[FAIL]%s %-6s %-34s %s  visualizer_url in /config is not a valid http(s) URL\n' \
         "$C_ERR" "$C_R" GET /under_attack "$code"; N_FAIL=$((N_FAIL + 1)) ;;
  *)   expect 200 GET /under_attack "$code" ;;
esac

if [[ "$ROLE" == "admin" ]]; then
  get_ok "/audit?limit=5"
  get_ok /audit/actors
  get_ok /users
  code="$(req GET /audit/export.csv)"; expect 200 GET /audit/export.csv "$code"
else
  skip "GET /audit, /users" "needs the admin role (you are $ROLE)"
fi

section "Flows"
code="$(req POST /query '{"limit":1}')"
expect 200 POST /query "$code"
FLOW_ID="$(python3 -c "
import json
try:
    d = json.load(open('$BODY'))
    print(d[0]['id'] if isinstance(d, list) and d else '')
except Exception:
    print('')
" 2>/dev/null)"

if [[ -z "$FLOW_ID" ]]; then
  skip "flow-scoped routes" "no flows ingested yet — copy pcaps into TRAFFIC_DIR_HOST"
else
  printf '       using flow %s\n' "$FLOW_ID"
  for p in "/flow/${FLOW_ID}" "/to_python_request/${FLOW_ID}" "/to_pwn/${FLOW_ID}" \
           "/attack/preview/${FLOW_ID}" "/attack/exploit-script/${FLOW_ID}"; do
    get_ok "$p"
  done
fi

section "Negative paths"
expect 403 GET "/download/?file=../../../etc/passwd" "$(req GET "/download/?file=../../../etc/passwd")"
expect 400 GET "/download/"                          "$(req GET "/download/")"
expect 400 POST "/query (no body)"                   "$(req POST /query)"

# --- 3. YELLOW: mutate then restore ---------------------------------------
if [[ $RUN_YELLOW -eq 0 ]]; then
  section "Writes"
  skip "write tests" "read-only run; pass --yellow to include them"
else
  section "Writes (each one is restored)"

  if [[ "$ROLE" == "admin" ]]; then
    req GET /config >/dev/null
    ORIG_VIS="$(json_field visualizer_url)"
    code="$(req PUT /config '{"visualizer_url":"http://smoke.invalid"}')"
    expect 200 PUT "/config (set)" "$code"
    # app_config caches for 5s PER gunicorn worker, and there are 3 of them, so
    # a read straight after the write can land on a worker still holding the old
    # value. Poll instead of asserting once.
    changed=0
    for _ in 1 2 3 4 5 6 7 8; do
      req GET /config >/dev/null
      if [[ "$(json_field visualizer_url)" == "http://smoke.invalid" ]]; then changed=1; break; fi
      sleep 1
    done
    if [[ $changed -eq 1 ]]; then
      printf '%s[ok]%s   value changed and was read back\n' "$C_OK" "$C_R"; N_OK=$((N_OK+1))
    else
      printf '%s[FAIL]%s value never became visible (per-worker config cache?)\n' "$C_ERR" "$C_R"; N_FAIL=$((N_FAIL+1))
    fi
    code="$(req PUT /config "{\"visualizer_url\":\"${ORIG_VIS}\"}")"
    expect 200 PUT "/config (restore)" "$code"

    # A throwaway account. Abort rather than risk touching a real one.
    if req GET /users >/dev/null && grep -q '"smoke-tmp"' "$BODY"; then
      skip "user create/delete" "an account named smoke-tmp already exists"
    else
      expect 201 POST /users "$(req POST /users '{"username":"smoke-tmp","password":"smoke-temp-pw","role":"viewer"}')"
      expect 200 DELETE /users/smoke-tmp "$(req DELETE /users/smoke-tmp)"
    fi
  else
    skip "config + user writes" "needs the admin role"
  fi

  if [[ "$ROLE" == "admin" || "$ROLE" == "operator" ]]; then
    # sid 999999 sits below the 1_000_000 auto-assign range, so it cannot
    # collide with a rule the team created from the UI.
    RULE='alert tcp any any -> any any (msg:"w4rya smoke test"; sid:999999; rev:1;)'
    expect 200 POST /rules "$(req POST /rules "{\"raw\":$(python3 -c "import json,sys;print(json.dumps('''$RULE'''))")}")"
    expect 200 DELETE /rules/999999 "$(req DELETE /rules/999999)"

    if [[ -n "$FLOW_ID" ]]; then
      expect 200 POST "/star (on)"  "$(req POST /star "{\"id\":\"${FLOW_ID}\",\"star\":true}")"
      expect 200 POST "/star (off)" "$(req POST /star "{\"id\":\"${FLOW_ID}\",\"star\":false}")"
      code="$(req POST "/flow/${FLOW_ID}/notes" '{"body":"w4rya smoke test note"}')"
      expect 200 POST "/flow/<id>/notes" "$code"
      NOTE_ID="$(json_field id)"
      [[ -n "$NOTE_ID" ]] && expect 200 DELETE "/notes/<id>" "$(req DELETE "/notes/${NOTE_ID}")"
    fi
  else
    skip "rules + star + notes" "needs the operator role"
  fi
fi

# --- 4. RED: never run -----------------------------------------------------
section "Not run, on purpose"
skip "POST /attack/replay"       "opens real TCP connections to the configured teams"
skip "PUT /config flag_regex"    "the Go assembler reads it at boot; changing it mid-game is destructive"
if [[ "$(env_get W4RYA_COMPOSE_FILE)" == "docker-compose-suricata.yml" ]]; then
  code="$(req POST /rules/reload)"
  [[ "$code" == "200" ]] && expect 200 POST /rules/reload "$code" \
                         || skip "POST /rules/reload" "suricata socket not available (got $code)"
else
  skip "POST /rules/reload" "not running the suricata stack"
fi

section "Logout"
expect 200 POST /logout "$(req POST /logout)"
expect 401 GET /me "$(req GET /me)"

printf '\n%s%d ok, %d failed, %d skipped%s\n' "$C_B" "$N_OK" "$N_FAIL" "$N_SKIP" "$C_R"
[[ $N_FAIL -eq 0 ]] && exit 0 || exit 1
