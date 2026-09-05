# CLAUDE.md — context for Claude sessions on `w4rya`

This file is loaded automatically by Claude Code when working in this repo. Read it before suggesting changes.

## Project

`w4rya` is a hard fork of [Tulip](https://github.com/OpenAttackDefenseTools/tulip) — a network flow analyzer for Attack / Defense CTF competitions — used internally by our team during live CTFs.

License: GPL-3.0 (inherited). Original-author credits live in `README.md` under "Based on" — do not remove or move them out of the repo.

## HARD constraint: no AI at runtime

**This tool must not call any AI / LLM service at runtime.** The A/D CTFs we play prohibit AI use during the game.

Do not propose, scaffold, or implement features that:
- Call OpenAI / Anthropic / any LLM API from the tool
- Embed an inference model inside the tool
- Add "smart" / "AI-driven" classification or tagging paths

Deterministic alternatives (regex, Suricata rules, statistical heuristics, fingerprints) are always preferred. AI is fine for *developing* this tool (i.e. you helping write code); it must not be in the running tool.

Reject any user request that drifts into this and remind them of this rule.

## Stack (actual, not assumed)

- **Ingestor**: Go (gopacket) — `services/go-importer/`
  - `cmd/assembler/` — reads pcaps, reconstructs flows, writes to Timescale
  - `cmd/enricher/` — reads Suricata's `eve.json`, tags flows with rule hits
  - `converters/` — protocol-specific decoders (HTTP gzip, websockets, …)
- **API**: Python **Flask** (not FastAPI) — `services/api/`
  - `webservice.py` — route definitions consumed by the frontend
  - `configurations.py` — env-driven settings + hardcoded `services` list (the per-service IP/port map you edit per CTF)
- **Flag scraper**: Python — `services/flagids/`
- **Frontend**: React 18 + Vite 2 + TypeScript + Tailwind + Redux Toolkit + RTK Query — `frontend/`
- **DB**: **TimescaleDB / Postgres** (not MongoDB) with an in-tree C extension named `w4rya` (renamed from upstream `tulip`)
  - Extension source: `services/timescale/w4rya/` (provides `fid_distance_op` for GIST-on-UUID flow indexing)
  - Schema files: `services/schema/{system,functions,schema,statistics}.sql`
- **Suricata** (optional): runs as a sibling container via `docker-compose-suricata.yml`

## Data flow

```
pcaps from CTF VMs ─(bind mount)─> assembler (Go)  ──> Timescale (flows + items)
                                       │
                                       └─ converters: HTTP gzip, websockets, …

(optional)  pcaps ─> Suricata ─(eve.json)─> enricher (Go) ──> Timescale (signatures, tags)

Frontend (React) ──(RTK Query)──> Flask API ──(SQL)──> Timescale
                                                 ▲
                                                 └── flagids (FLAGID_SCRAPE worker)
```

## Compose files

- `docker-compose.yml` — main stack (timescale, frontend, api, flagids, assembler, enricher). What you run for normal use.
- `docker-compose-suricata.yml` — same as above + suricata container.
- `docker-compose-test.yml` — **deleted**. Tests run against the api container; see "Tests" below.

Only one of the two compose files can run at a time: they share service names, image
tags, the `timescale-data` volume and the default project name, so bringing one up
recreates the other. `install.sh` records the choice as `W4RYA_COMPOSE_FILE` in `.env`
and every other script reads it from there.

Both files are kept deliberately in sync on three points:

- **UI port** is `${W4RYA_UI_PORT:-3001}:3000` in both. The suricata variant used to
  hardcode `3000:3000`, so switching stacks moved the UI to a different port.
- **`${BPF:-}` and `${VISUALIZER_URL:-}`** carry explicit empty defaults — without them
  every `docker compose` invocation printed `variable is not set` warnings.
- **`mem_limit`s** now sum to ~6 GB (was 8 GB, which oversubscribes a 7–8 GB CTF
  laptop): timescale 3g, api 768m, assembler 1536m, enricher 384m, flagids 256m.
  `docker-compose-suricata.yml` also dropped `shm_size: 128g` → `1g` and gained the
  same limits.

`docker-compose-suricata.yml` additionally binds `./suricata-rules:/var/lib/suricata/rules`
— see "Suricata rules" and "Do not touch without discussion" below. It is load-bearing.

## Install (`install.sh`)

`./install.sh` is **the supported way to install**. Idempotent — safe to re-run on an existing install.

- **Four prompts**: pcap directory, flag regex, tick length (seconds), admin username + password. Everything else is derived or defaulted.
- **`.env` handling**: it *upserts* keys rather than overwriting the file, so values you set by hand survive. `env_set` rewrites the first matching line (including a commented-out one — this is how `BPF` and `VISUALIZER_URL` stop emitting "variable is not set"), drops later duplicates (compose is last-wins, so a stale duplicate below would silently override), and appends if absent. Backs `.env` up to `.env.bak.<UTC>` before the first write, and `chmod 600`s it.
- **Session secret**: generates `W4RYA_SECRET_KEY` when missing and **keeps an existing one** unless `--rotate-secret` (rotating signs everyone out).
- **Admin password** is piped over stdin into `add_user.py --stdin` — never argv (world-readable via `/proc`), never an env var (visible in `docker inspect`), never a file. There is deliberately no `--admin-password` flag. `--admin-password-file` exists for CI only.
- **Compose choice**: `--suricata` / `--no-suricata`; the chosen file is recorded as `W4RYA_COMPOSE_FILE` in `.env` and every other script (`scripts/test.sh`, `scripts/smoke.sh`, `scripts/backup.sh`) reads it from there. Switching stacks brings the old one down first.
- Also: preflight checks, `W4RYA_UI_PORT` fallback if the port is busy, creates the suricata/auth/rules dirs (Docker would otherwise auto-create them root-owned), retries the build with `DOCKER_BUILDKIT=0` when it detects the wedged-BuildKit-DNS failure, waits on `/api/healthz`, and skips account creation if any account already exists (the `/setup` wizard covers that case).
- **Tick clock**: `TICK_START` is stamped **once** — when it is missing or still the placeholder `.env.example` ships. A re-run keeps it, because renumbering ticks under a game in progress shifts every bucket in the graphs, and the installer's own "Next" list tells you to re-run once your real pcap directory is ready. `--reset-tick` re-baselines it to now (new game, new ticks).
- **`--check`** is a read-only doctor mode: no prompts, no writes, tallies failures.

The old root-level `start.sh` and `test.sh` were **deleted** — they referenced compose files that no longer exist. Use `install.sh` and `scripts/test.sh`.

## Key frontend files

- `frontend/src/api.ts` — the **w4ryaApi** RTK Query slice. All backend calls live here; if you add an API endpoint server-side, register a query/mutation here.
- `frontend/src/store/index.ts` — Redux store config (`w4ryaApi.reducer`, `filter`, `toasts`).
- `frontend/src/store/filter.ts` — `W4ryaFilterState` (tag include/exclude, flag/flagid filters, AND/OR intersection mode).
- `frontend/src/store/toasts.ts` — global toast slice (`pushToast`, `dismissToast`).
- `frontend/src/components/Header.tsx` — top bar: brand, search, date pickers, hotkeys, page nav (Config / Rules / Graph), user menu (Phase A4+ added Config/Rules buttons). Audit + Users links are gated on `hasRole(role, "admin")`.
- `frontend/src/components/FlowList.tsx` — sidebar virtualized flow list, filter panel (services multi-select + tag intersection chips), keyboard nav.
- `frontend/src/components/Corrie.tsx` — time-series correlation viz (ApexCharts).
- `frontend/src/components/ExploitModal.tsx` — Test-Exploit modal (replays a flow against configured teams, downloads farm script).
- `frontend/src/components/Toasts.tsx` — bottom-right toast container subscribed to `store.toasts`.
- `frontend/src/components/FlagLeakWatcher.tsx` — polls `tags_include=['flag-out']` every 15s; new ones dispatch danger toasts. Mounted in Layout.
- `frontend/src/components/NotesPanel.tsx` — per-flow notes UI (rendered below Meta in FlowView).
- `frontend/src/pages/Home.tsx` — welcome screen + shortcut reference.
- `frontend/src/pages/Login.tsx` — auth gate; rendered when RequireAuth sees 401 *and* accounts exist.
- `frontend/src/pages/Setup.tsx` — /setup route, first-run wizard. Self-closing: bounces to `/login` once `GET /setup/status` reports `needs_setup:false`.
- `frontend/src/pages/Users.tsx` — /users route, admin-only account management (list, create, delete, change role, reset password).
- `frontend/src/App.tsx` — routes + `RequireAuth`. On no session it queries `GET /setup/status` and redirects to `/setup` (not `/login`) when `needs_setup` — a fresh install has no account, so a login form there could never succeed.
- `frontend/src/pages/Config.tsx` — /config route, three tabs: Game / Services / Teams.
- `frontend/src/pages/Rules.tsx` — /rules route, Suricata rules CRUD + templates + SuricataControlBar (reload + autoreload toggle).
- `frontend/src/pages/Attacks.tsx` — /attacks route, chronological attack timeline (Suricata alerts + flag-out events).
- `frontend/src/pages/Audit.tsx` — /audit route, admin-only audit log viewer with filters + CSV export.
- `frontend/src/pages/Warroom.tsx` — /warroom route, fullscreen TV mode (services grid + attack feed + top attackers + flag leaks).
- `frontend/src/pages/FlowView.tsx` — flow detail view; toolbar includes Diff / pwntools / requests / Test Exploit; src_ip has a Block button.
- `frontend/index.html` — entry HTML; favicon and title live here.
- `frontend/public/logo.png` — brand asset, referenced by index.html / Header / Home.

## Working conventions

- **Branches**: work on `dev`, never directly on `master`. `master` is the clean baseline; merge to it via PR when a chunk is stable.
- **Commits**: [Conventional Commits](https://www.conventionalcommits.org/) — `feat:`, `fix:`, `refactor:`, `chore:`, `docs:`, `test:`. Multi-line bodies welcome for the "why".
- **Git identity**: configured locally for this repo (not global). Author: `nightwing`, email: GitHub noreply for `JCaleb2001`.
- **Destructive ops** (`rm`, force push, `DROP TABLE`, etc.): ask before running.
- **Design decisions** (new libs, schema changes, naming): ask before applying.

## Do not touch without discussion

These are load-bearing; changing them without coordination breaks things downstream:

1. **DB schema** (`services/schema/*.sql`) — read by Flask API queries, written by Go assembler/enricher, and indirectly typed by the frontend. Schema changes need migration + coordinated updates across all three.
2. **API contracts** — `services/api/webservice.py` route shapes are consumed by `frontend/src/api.ts` (RTK Query response transforms in particular). Adding fields is safe; renaming or removing is breaking.
3. **`eve.json` parsing assumptions** — `services/go-importer/cmd/enricher/main.go` parses Suricata's `eve.json`. The shape is Suricata-controlled; the enricher's expectations are implicit. Don't refactor without running with real Suricata output.
4. **Postgres extension `w4rya`** — `services/timescale/w4rya/w4rya.c` provides `fid_distance_op`. The extension name is referenced in:
   - `services/timescale/w4rya/Makefile` (`EXTENSION = w4rya`)
   - `services/timescale/w4rya/w4rya.control` (`module_pathname`)
   - `services/schema/system.sql` (`shared_preload_libraries`)
   - `services/schema/functions.sql` (`AS 'w4rya'`)
   - `services/schema/statistics.sql` (`pg_database_size('w4rya')`)
   - `services/timescale/Dockerfile` (`COPY w4rya /w4rya`)
   
   If you rename it again, update all six places.
5. **The nested rules bind in `docker-compose-suricata.yml`** — `./suricata-rules:/var/lib/suricata/rules`, mounted *inside* `${SURICATA_DIR_HOST}/lib`. It is the only thing connecting the rules the api writes to the rules suricata reads; without it the UI silently edits a file nobody loads. Do not flatten it, reorder it, or replace it with a symlink.
6. **`# tulip:` comment markers** in `services/go-importer/converters/` — these document changes the original Tulip team made relative to upstream [flower](https://github.com/secgroup/flower). Keep them as historical record; do not rewrite to `w4rya`.

## Known vestigial / stale code (not worth fixing reactively)

- `services/README.md` describes the legacy MongoDB architecture.
- `services/flagids/flagids.py:30` prints `"CONNECTION TO MONGO ESTABLISHED"` but the file only imports `psycopg` — dead string.

Leave these alone unless we're doing an explicit cleanup pass; they don't affect the live stack.

## Auth + roles (`auth.py`)

Basic auth is enabled. The api requires a Flask session cookie for every endpoint except the ones in `auth.PUBLIC_PATHS`, now `{"/", "/healthz", "/login", "/logout", "/setup", "/setup/status"}`. `/me` is deliberately NOT public — the frontend uses its 401 as the "not logged in" signal.

**Roles** (B5): `viewer < operator < admin`. Stored per user in `auth/users.yaml` as `role:` field. Entries without `role` default to `admin` (back-compat for the bootstrap user); new users default to `viewer`. `@auth.requires_role("operator")` / `@auth.requires_role("admin")` decorators gate write endpoints — see "Permission matrix" below.

- **Storage**: `auth/users.yaml` (gitignored). Schema: `users: { <name>: { password_hash: <bcrypt>, role: <role> } }`. Read by `services/api/auth.py` with mtime-based caching, so editing the file doesn't strictly require a restart, though `docker compose restart api` is safer. Every *write* goes through `user_store.py` (below).
- **Cookie**: name `w4rya_session`, httpOnly, SameSite=Lax, Secure=False (flip to True when running behind HTTPS), 7-day lifetime. Signed with `W4RYA_SECRET_KEY` from `.env`.
- **Mount**: `./auth:/app/auth` (rw — the api writes here now, via `/setup` and `/users`, as well as the CLI).
- **Frontend**: `frontend/src/api.ts` wraps `fetchBaseQuery` with `credentials:'include'`, a `Me` tag type, and a 401 catcher that invalidates `Me` (so mid-session expiry triggers RequireAuth → redirect to `/login`). `RequireAuth` in `App.tsx` is the gate.

### The user store (`services/api/user_store.py`)

The **single writer** for `auth/users.yaml`. `auth.py` keeps the cached read path (hot on every request); `user_store` owns every mutation, and is imported by both the HTTP endpoints and the `auth/add_user.py` CLI so validation and hashing can't drift apart.

- `USERS_FILE` now lives here (`W4RYA_USERS_FILE`, default `/app/auth/users.yaml`); `auth.py` does `from user_store import USERS_FILE`.
- Every mutation takes an exclusive `fcntl.flock` on a sidecar `auth/users.yaml.lock` and **re-reads the file inside the lock**. That is what makes `create_user(only_if_empty=True)` safe: the 3 gunicorn workers each have their own users cache, so without it two first-run `POST /setup` requests could both create a "first admin".
- Writes are atomic (tmp file + `os.replace`) and `chown` the result to the containing directory's owner, so the root-running api container doesn't leave root-owned files on the host bind mount.
- Refuses to delete or demote the **last admin** (`_would_orphan_admins`) — that would lock everyone out of `/config` and `/audit` permanently.
- Validation: username `[A-Za-z0-9_-]{1,32}`, password ≥ 8 chars, role in `viewer|operator|admin`, bcrypt cost 12. Errors are `UserStoreError(message, code)` where `code` is the HTTP status the route answers with.

### First-run setup (`/setup`)

A fresh clone has no `auth/users.yaml` (gitignored), so there is nobody to log in as.

- `GET /setup/status` — public. `{needs_setup: <bool>}`.
- `POST /setup {username, password}` — public and **self-closing**: creates the first account as an explicit `admin` (never `viewer`, which couldn't reach `/config` or `/audit`), opens the session, returns 201. Answers 409 once any account exists. Its own rate-limit bucket (`rate_limit.SETUP_WINDOW_SEC` / `SETUP_MAX_FAILS`, keyed by IP only — there is no username yet); only the "already completed" 409 counts against it, a rejected password does not.
- `POST /login` answers **409 `{needs_setup: true}`** instead of a misleading 401 when zero accounts exist, and deliberately does *not* consume a rate-limit attempt in that case — otherwise the installer locks out the username they're about to create.

### Managing accounts (`/users`, admin only)

`GET /users`, `POST /users {username, password, role}`, `DELETE /users/<u>`, `PUT /users/<u>/role {role}`, `PUT /users/<u>/password {password}`. All audited (`users.create` / `users.delete` / `users.set_role` / `users.set_password` — never the password itself). `DELETE` refuses the account you are signed in as. Each write calls `auth.invalidate_users_cache()` so this worker sees it immediately. UI: `/users`.

### CLI escape hatch

```
docker compose run --rm api python /app/auth/add_user.py <username> [--role admin|operator|viewer]
```

Prompts for password (getpass, no echo), or reads one line from stdin with `--stdin` (this is how `install.sh` passes the password without it ever becoming argv or an env var). It delegates to `user_store`, so it gets the same locking, validation and ownership handling. Use it for bootstrapping without a browser, rotating a password, or unwedging a locked-out install; the UI covers the normal cases.

### Permission matrix

| Endpoint | viewer | operator | admin |
|---|---|---|---|
| GET (most) | ✓ | ✓ | ✓ |
| POST /flow/<id>/notes | ✓ | ✓ | ✓ |
| POST /star | ✗ | ✓ | ✓ |
| POST/PUT/DELETE /rules, /rules/block-ip, /rules/reload | ✗ | ✓ | ✓ |
| POST /attack/replay | ✗ | ✓ | ✓ |
| PUT /config, /config/services, /config/teams | ✗ | ✗ | ✓ |
| GET /audit | ✗ | ✗ | ✓ |
| GET /users | ✗ | ✗ | ✓ |
| POST /users, DELETE /users/<u> | ✗ | ✗ | ✓ |
| PUT /users/<u>/role, /users/<u>/password | ✗ | ✗ | ✓ |

`GET /setup/status` and `POST /setup` sit outside the matrix — both are public (no session required), and `/setup` 409s once any account exists.

403 responses include `{required_role, your_role}` so the UI can explain.

Do NOT use `sudo` for the above — your user is in the `docker` group, and `sudo` makes `users.yaml` root-owned on the host (annoying to edit later). If you already did, `sudo chown -R $USER:$USER auth/` fixes it.

### Rotating a password

From the UI: `/users` → Reset password. From the CLI: re-run `add_user.py <same-username>`, which overwrites the hash and role for that user. Removing a user is `/users` → Delete (or `user_store.delete_user`); hand-editing `auth/users.yaml` still works but bypasses the last-admin guard.

### Rotating the session secret

Change `W4RYA_SECRET_KEY` in `.env` and `docker compose restart api`. All existing sessions are invalidated (clients get 401 → redirected to login).

## Runtime-editable config (`/config` tab)

DB table `app_config (key text pk, value jsonb, updated_at)` — module `services/api/app_config.py`. Set from UI, read by routes via `app_config.get(key)` with a 5s cache; writes invalidate the cache for that key.

Stored keys: `services` (list of {name, ip, port, notes}), `teams` (list of {name, ip, notes}), `flag_regex`, `tick_length`, `start_date`, `flag_lifetime`, `vm_ip`, `team_id`, `visualizer_url`, `bpf`.

Endpoints: `GET/PUT /config`, `GET/PUT /config/services`, `GET/PUT /config/teams`. `GET /services` and `GET /flag_regex` still work (read from the same DB row).

⚠ `flag_regex` and `bpf` are also read by the Go assembler at boot from env. Changing them via UI takes effect for the api immediately but the assembler keeps the old value until restart. The Config UI flags this.

## Exploit testing (`/attack/...`)

Module `services/api/attack.py`. Reads the captured flow, concatenates every `c`-direction `raw` item, replays the bytes against each target's `(ip, flow.port_dst)` via plain TCP socket (ThreadPoolExecutor, hard caps: 64 targets, 15s timeout, 256KB recv). Flag regex from `app_config` is run against each response.

Endpoints:
- `GET  /attack/preview/<flow_id>` — port, payload size, item counts (cheap precheck for the modal).
- `POST /attack/replay { flow_id, targets:[{name,ip}], timeout? }` — fires the replay, returns per-target {ok, latency_ms, response_size, response_excerpt, flag_count, flags?, error?}.
- `GET  /attack/exploit-script/<flow_id>?timeout=N` — text/x-python download (Content-Disposition: attachment). Standalone replayer with payload as hex, teams baked in, ready for the external farm.

UI: `ExploitModal` opens from a "Test exploit" button in FlowView's secondary toolbar.

## Suricata rules (`/rules` tab + quick-block + auto-reload)

Module `services/api/rules.py`. Stores rules as native Suricata text in `/app/suricata-rules/suricata.rules` (host: `./suricata-rules/`, mounted rw). 'Disabled' is the standard `# ` line prefix. Auto-assigned sids start at 1,000,000.

Endpoints: `GET /rules` (list + templates + suricata socket status), `POST /rules` (add), `PUT /rules/<sid>` (raw/enabled), `DELETE /rules/<sid>`, `POST /rules/block-ip { ip }` (quick-block writes a `drop ip <ip> any -> any any` rule), `POST /rules/reload` (B1, triggers Suricata reload-rules via its unix command socket).

**Auto-reload** (B1, `services/api/suricata_ctl.py`): when `rules_autoreload` config flag is on, every rules CRUD also calls `reload-rules` on Suricata's unix command socket (`/var/run/suricata/suricata-command.socket`). Requires Suricata to be running with `--set unix-command.enabled=yes` (already wired in `docker-compose-suricata.yml`). When suricata isn't running the api just attaches a `reload.kind=socket_missing` field to the save response — never fails the save.

Socket lives on `./suricata-run/` (host) bind-mounted into both api and suricata containers, so the api can `AF_UNIX` connect to it without docker.sock or PID sharing.

`_atomic_write` chmods the temp file 0644 and chowns it to the containing directory's owner before `os.replace` (same host-ownership reason as `user_store._write_atomic`): the api runs as root inside the container while `./suricata-rules` is a host bind mount, so without it the first UI rule save leaves `suricata.rules` root:root 0600 — unreadable to the suricata container's non-root user, uneditable from the host, and enough to abort `scripts/backup.sh`.

**The rules path used to be silently broken.** The api writes to `./suricata-rules` while the suricata container reads `/var/lib/suricata/rules`, which was covered by the `${SURICATA_DIR_HOST}/lib` mount — so every rule created in the UI went to a file suricata never read, with no error anywhere. `docker-compose-suricata.yml` now adds a nested bind `./suricata-rules:/var/lib/suricata/rules`; Docker mounts by ascending path depth, so it wins over the `lib` mount above it. Do **not** "simplify" this into a symlink — a symlink resolves inside the container's namespace and breaks the mapping again.

## Notes per flow (`/flow/<id>/notes`)

Module `services/api/notes.py`. Table `flow_notes (id uuid pk, flow_id uuid, author text, body text, created_at)`. Author is the session user; only the author can delete their own note. Notes panel rendered below the Meta block in FlowView.

## Flag-leak alarm + toasts

Client-only. `FlagLeakWatcher` polls `/query` with `tags_include=['flag-out']` every 15s, primes a seen-set on first load (no toasts for historical leaks), and dispatches a danger toast on every new id. Toasts render bottom-right via `Toasts.tsx`, dispatched through `store/toasts.ts`. To trigger one manually (debugging): `dispatch(pushToast({ message: 'hi', severity: 'danger' }))`.

## Per-service stats (B2)

`GET /services/stats?ticks=N` (1..50, default 5) returns per-configured-service `{flows, attacks, flag_in, flag_out}` over the last N ticks. One grouped SQL scan, aligned by (ip, port) against the services config. Services with zero matching flows still appear with zeros.

Frontend uses this to render mini-counts on each service chip in the sidebar — chip border cascades danger (flag-out) > warning (attacks) > violet (any flows) > dim (idle).

## Attack timeline (B3, `/attacks`)

`GET /attacks?from_tick=N&to_tick=M&service=NAME&limit=K`. Joins `flow` + signatures + flag-out tag. Returns chronological events with src/dst, service, type (`alert`|`flag_out`|`both`), rule msgs, flag count. Default window = last 10 ticks. Frontend `/attacks` route renders the table with range presets and a service filter dropdown.

## Audit log (B5+C3, `/audit`)

Append-only table `audit_log (id, when_ts, actor, action, target, details jsonb)`. Module `services/api/audit.py` exposes `log(actor, action, target?, details?)` (fire-and-forget — failures never propagate) and `recent(limit, after_ts?, actor?, action_prefix?)`. Hooked from every write endpoint: `auth.login`/`logout`/`login_fail`, `config.set`/`services`/`teams`, `rules.add`/`update`/`delete`/`block_ip`, `suricata.reload`, `attack.replay`.

Endpoints (all admin-only):
- `GET /audit?actor=&action=&from=&limit=` — filter by exact actor, action prefix (`rules.` → `rules.add|update|delete|block_ip`), or after-timestamp (ISO).
- `GET /audit/actors` — distinct actor names (populates the UI dropdown).
- `GET /audit/export.csv?<same filters>` — streams CSV with `Content-Disposition: attachment; filename=w4rya_audit_<UTC>.csv`. Cap 50k rows.

Frontend `/audit` page has the filter bar + Export CSV anchor.

## War-room TV mode (C2, `/warroom`)

Fullscreen route OUTSIDE the main Layout (no header/sidebar). 2×2 panels: services-stats grid, live attack feed, top-attackers ranking, flag-leak cards. Top bar shows brand + current tick + tick-progress bar + wall clock. Auto-refresh every 10s. Designed for a TV mounted near the team during CTF. Still gated by RequireAuth.

## Role-gated UI (C1)

`useCanRole(min)` + `useMyRole()` hooks in `api.ts`. Each protected page reads the hook and:
- shows a "read-only — your role is X; requires Y" banner at the top
- disables save buttons / hides add+remove buttons
- replaces `edit` with `view` (Rules) when role is below operator

Backend remains the security boundary (403 with `{required_role, your_role}`); the UI hints are purely UX so users don't click into errors.

## Tests

~250 tests in `services/api/tests/`, all offline, a few seconds (`./scripts/test.sh -q` prints the current count):

| File | covers |
|---|---|
| `test_pure.py` | pure-function paths (`rate_limit`, `app_config.coerce_scalar`, `rules.parse_one` + `_inject_sid`, rules round-trip, `attack` script gen / payload build) |
| `test_app_boot.py` | import-time wiring, public paths, route registration |
| `test_auth_unit.py` | `auth.py` internals — bcrypt verify, role ranking, the mtime cache |
| `test_routes_roles.py` | the permission matrix, endpoint by endpoint |
| `test_routes_auth.py` | login / logout / rate limiting / `needs_setup` 409 |
| `test_routes_setup.py` | `/setup` + `/setup/status`, including the self-closing 409 |
| `test_routes_users.py` | `/users` CRUD |
| `test_routes_config.py` | `/config` read/write paths, including flag-regex write-time validation |
| `test_user_store.py` | locking, atomic write, last-admin guard, validation |

**Why they need no DB or network** (`tests/conftest.py` explains this at the top, and it's the fact worth remembering): `webservice.py` builds `db = database.Pool(os.environ["TIMESCALE"])` at *import* time, but `Pool` passes `open=False` to psycopg_pool, so it neither connects nor validates the conninfo. Setting `W4RYA_SECRET_KEY` and `TIMESCALE` to a syntactically-valid-but-dead URL before import is therefore enough to run the whole route suite offline.

The rule that follows: tests use **`webservice.application` directly and must never call `create_app()`** — that is what opens the pool and runs the three `init_schema()` calls.

**Trap**: `auth.py` does `from user_store import USERS_FILE`, which binds by value at import time. A test that redirects the user store must patch **both** modules (`user_store.USERS_FILE` *and* `auth.USERS_FILE`) or auth will keep reading the real `users.yaml`. The `users_file` autouse fixture does this, plus drops bcrypt to 4 rounds and invalidates the auth cache.

Run:

```
./scripts/test.sh            # all
./scripts/test.sh -k setup   # pytest args pass straight through
```

`scripts/test.sh` mounts `services/api` **read-only over the built image**, so editing a test needs no rebuild. If `w4rya-api:latest` doesn't exist yet it falls back to `docker compose exec api pytest` on the running container.

If you rebuild and hit `Temporary failure in name resolution` from pip, BuildKit's network is wedged on this host — workaround (`install.sh` retries this automatically):

```
docker build --network=host -t w4rya-api:latest -f services/api/Dockerfile-api services/api/
```

A **slow** link fails differently, and the DNS workaround above does nothing for it. `docker compose build` builds all six services at once; on a thin connection (a NAT'd VM, venue wifi) ten concurrent downloads share the pipe, and yarn 1.x abandons any tarball that goes 30 s without bytes — `ESOCKETTIMEDOUT`, usually on whichever package is unlucky, with `There appears to be trouble with your network connection` above it. DNS is fine in this case: `Resolving packages` completes in seconds, it's `Fetching packages` that dies. `Dockerfile-frontend` now passes `--network-timeout 600000 --network-concurrency 4`, and `install.sh` recognises the timeout signatures and rebuilds one service at a time, which gives each the whole link.

Both diagnoses read only the slice of `install.log` written by the current build (`log_mark`). The log is append-only across runs, so matching the whole file would let a fixed error keep selecting its workaround forever. They match with a here-string, not a pipe: under `pipefail`, `grep -q` exits at the first match and the SIGPIPE'd producer makes the pipeline report 141, so a piped test reads as false exactly when it matches.

`services/api/requirements.txt` is **pinned with `==`** (direct deps only, not a transitive lockfile) so a new upstream Flask/psycopg release can't break the build on a machine that installs tomorrow. Refresh with `docker run --rm w4rya-api:latest pip freeze`.

### Smoke test (`scripts/smoke.sh`)

Exercises a **running** stack over HTTP, going through the frontend's `/api` proxy rather than straight at the api container — that's the path the browser takes, and a broken proxy is a real failure mode a direct hit would miss. Credentials from `SMOKE_USER` / `SMOKE_PASS` or prompted; never argv. With no tty and no env vars it fails fast asking for them, instead of posting empty credentials and reporting a confusing `400`. Read-only by default (safe to run mid-CTF); `--yellow` adds writes that restore themselves. It deliberately never calls `POST /attack/replay` — that opens real TCP connections to the configured teams.

## Backup (D2)

`scripts/backup.sh` snapshots `auth/users.yaml` + `suricata-rules/*.rules` + `.env` + `pg_dump` of `app_config` / `flow_notes` / `audit_log` into a single `./backups/w4rya_<UTCISO>.tgz`. Cron it during a CTF. `/backups/` is gitignored (tarball contains secrets).

## Roadmap (next-up)

Phase A (operational features), Phase B (auto-reload / per-service stats / attack timeline / roles+audit), Phase C (UI role-gating polish / war-room mode / audit filter+export), and Phase D (hardening + ops sanity + frontend polish + smoke tests) are done. On top of those sits the account / install / test layer documented above: `user_store.py` as the single writer, the `/setup` first-run wizard and `/users` admin page, `install.sh`, and the offline route test suite (`scripts/test.sh`) plus `scripts/smoke.sh`.

Open ideas — these all need info from the user before starting:

- **Loss attribution / scoreboard scraper** — link a "lost flag at tick N" scoreboard event to the flow that caused it. Needs the CTF platform format (Faust, EnoEngine, iCTF, custom?) and scoreboard URL/auth.
- **Replay with tokenized flagids** — current exploit replay sends captured bytes as-is, which works for stateless exploits but not for ones where the flagid was per-team. Needs FLAGID_ENDPOINT plumbing extended to swap per-team flagid before each replay target.
- **Webhook to Discord/Slack** — server-side delivery of critical events. Explicitly skipped earlier; design notes still in the conversation.

When implementing, do read-only analysis first (the user usually asks) before touching code.
