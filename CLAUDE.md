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
vulnbox: rotating tcpdump ─(scp + sha256 verify)─> pcaps in TRAFFIC_DIR_HOST
                                                   (scripts/pull_vulnbox_pcaps.sh)

pcaps in TRAFFIC_DIR_HOST ─(bind mount)─> assembler (Go)  ──> Timescale (flows + items)
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

- **UI port** is `${W4RYA_BIND_IP:-127.0.0.1}:${W4RYA_UI_PORT:-3001}:3000` in both. The
  suricata variant used to hardcode `3000:3000`, so switching stacks moved the UI to a
  different port. The **interface prefix is load-bearing**: without it Docker publishes
  on `0.0.0.0`, and because the frontend proxies `/api` to `api:5000`, publishing the UI
  port publishes the whole API — login form included — to whatever network the host is
  on, which during a game is the network every other team is also on. Reach the UI from
  another machine over the team VPN or an SSH tunnel
  (`ssh -L 3001:127.0.0.1:3001 <host>`); if you must bind an interface, set
  `W4RYA_BIND_IP` to the VPN interface IP, never `0.0.0.0`.
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
- **Bind interface**: `W4RYA_BIND_IP` is upserted next to `W4RYA_UI_PORT` (default
  `127.0.0.1`) and never prompted for — loopback is the right answer and anything else
  should be a deliberate edit. `0.0.0.0` draws a warning. The final summary adapts: under
  a loopback bind it prints an `ssh -L` line instead of a LAN URL that could not work.
- **`--check`** is a read-only doctor mode: no prompts, no writes, tallies failures. It
  asks Docker (`compose port frontend 3000`) what the UI is *actually* bound to rather
  than trusting `.env` — a stack brought up before `W4RYA_BIND_IP` existed stays on
  `0.0.0.0` until it is recreated, which is exactly the case worth catching.

The old root-level `start.sh` and `test.sh` were **deleted** — they referenced compose files that no longer exist. Use `install.sh` and `scripts/test.sh`.

## Capturing traffic from the vulnbox (`scripts/vulnbox_*`)

The assembler only ever reads pcaps out of `TRAFFIC_DIR_HOST` on this laptop. Getting the
game traffic there is a two-part pipeline, both halves driven from here over ssh — nothing
stays installed on the vulnbox.

- **`scripts/vulnbox_capture.sh {start|stop|status}`** — scp's `scripts/vulnbox/remote_capture.sh`
  to `/root/.w4rya_remote_capture.sh` and runs it there. That starts a rotating `tcpdump`:
  a new file every `ROTATE_SECONDS` (60) or `ROTATE_MB` (100), whichever comes first, into
  `VULNBOX_PCAP_DIR` (`/root/pcaps`), tracked by a pidfile. `-U` flushes per packet so a
  rotated file is readable the moment tcpdump moves on to the next one.
- **`scripts/pull_vulnbox_pcaps.sh [--once]`** — fetches closed files into
  `TRAFFIC_DIR_HOST` (read out of `.env`), verifies each by sha256, then deletes it from
  the vulnbox, so the box never accumulates capture data it doesn't need. Interrupted
  pulls are safe to re-run: a file that already exists locally just gets removed remotely.

Three details there are non-obvious and were each paid for once:

1. **`-Z root` is deliberate** (`89ac166`). Debian/Ubuntu `tcpdump` drops to the `tcpdump`
   user once the capture socket is open, and that user can't traverse a 700 `/root` to
   reach the dump dir — so the first rotation can't open its `-w` target and the capture
   dies quietly.
2. **`BPF_FILTER` filters by port, never by direction** (`e49cb82`). `tcp port 8008 or tcp
   port 8000` is right; `dst host <vulnbox>` captures one side only, and the assembler
   needs both to reassemble a flow.
3. **The newest file is always skipped**, plus a `SETTLE_SECONDS` (5) age floor — tcpdump
   is still appending to it, and the floor covers the instant at rotation where "newest"
   is briefly ambiguous.

Defaults assume `VULNBOX_HOST=root@vulnbox.glitch.ad` and `VULNBOX_IFACE=game`; both are
env overrides, so a different game means exporting them, not editing the scripts.

### Operator scripts

- **`scripts/show_attacker_flows.sh`** — flows whose `ip_src` is neither the checker
  (`CHECKER_IP`, default `10.100.0.1`) nor our own vulnbox (`SELF_IP`, default
  `10.100.2.1`). Those two account for nearly all the volume — the checker plants and
  reads its own flag every tick, and our own tooling talks to the box locally — so
  subtracting them leaves the traffic actually worth reading. `--since 10min` narrows the
  window; `--watch` polls every `WATCH_SECONDS` (10) and prints only rows it hasn't seen.
- **`scripts/windows_assembler_watchdog.sh`** — **deprecated**, kept only for an
  assembler image built before the rescan below. It restarted the container every 120s to
  force the boot-time directory scan, which also dropped whatever was mid-assembly at each
  restart.

### Why the assembler polls its watch dir

`WatchDir` in `cmd/assembler/main.go` does an initial full scan, then keeps watching with
**two** independent triggers, both funnelling into a single `scanDir` call:

- **fsnotify**, as before — but the event handler no longer ingests anything itself. It
  does a non-blocking send on a `wake` channel, so a burst of events collapses into one
  follow-up scan.
- **a poll ticker** (`WATCH_POLL_INTERVAL`, default `10s`), which is the whole point:
  Docker Desktop's Windows bind mounts drop inotify events, so a pcap can land in the
  watch dir with no event ever arriving.

`scanDir` is deliberately the **only** ingestion path once the watcher is up.
`ProcessPcapHandle` mutates shared assembler state, so two goroutines spotting the same
file must not both process it. It re-offers a file only when its size or mtime changed,
and re-offering is cheap and safe because `PcapFindOrInsert` records how many packets of
that filename were already ingested and skips them (`Skipped N packets from ...` in the
log). It also drops files that have disappeared from its map, so a retention sweep can't
leak memory over a long game.

Set `WATCH_POLL_INTERVAL=0` to rely on fsnotify alone — fine on native Linux Docker.

Both run `docker compose` under `MSYS_NO_PATHCONV=1`, for the same reason `install.sh`
does (`7a74ab8`): Git-Bash rewrites container-absolute paths into Windows paths before
Docker ever sees them.

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

   **Gotcha, found by bulk-loading 132 pcaps into `services/test_pcap/` at once for detection testing**: the enricher correlates each `eve.json` alert line to a `flow` row by exact 5-tuple + a ±1-minute window around the alert's `flow.start` timestamp (`SuricataIdFindFlow` in `services/go-importer/internal/pkg/db/db.go`) — and it scans `eve.json` **strictly forward, exactly once per line, with no retry**. If Suricata writes an alert for a flow *before* the assembler has finished inserting that flow's row (a real race under bulk load: Suricata alerts fast, the Go assembler's own TCP-reassembly + batched Postgres inserts for 24k+ flows took several minutes to catch up), the correlation silently misses — permanently, with nothing logged (only successful correlations get a log line). Normal incremental play (pcaps dumped every `DUMP_PCAPS_INTERVAL`, a handful of flows at a time) never hits this, since the assembler easily keeps ahead of Suricata's alert pace at that volume. Symptom: `flow.signatures` stays `[]` for the great majority of flows even though Suricata's own alert count (`grep -c '"event_type":"alert"' eve.json` inside the suricata container) shows plenty fired. Fix: once ingestion has fully settled, `docker compose -f docker-compose-suricata.yml restart enricher` — its `watchEve()` always re-scans `eve.json` from byte 0 on startup, and `FlowAddSignatures`/`FlowAddTags` merge via `jsonb_unique(...)`, so a full re-scan is idempotent and safe to re-run (verified: went from 10 correlated flows to 7,609 after one restart, no duplicates introduced).
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

Stored keys: `services` (list of {name, ip, port, notes}), `teams` (list of {name, ip, notes}), `flag_regex`, `tick_length`, `start_date`, `flag_lifetime`, `vm_ip`, `team_id`, `visualizer_url`, `bpf`, `noise_ips`.

**`noise_ips`** is the checker + our-own-tooling list that `show_attacker_flows.sh`
used to carry in environment variables. It is a comma-separated **string**, not a
list, specifically so it renders in the existing Game form instead of needing a list
editor. `app_config.parse_noise_ips()` turns it into `ip_network` objects (host bits
tolerated, `;` accepted as a separator); `coerce_scalar` validates at write time,
because a silently-dropped typo just looks like the checker coming back.

`POST /query` takes **`hide_noise: true`** and resolves the list server-side into
`FlowQuery.ip_src_exclude` — the frontend sends the intent and never learns which ips
count as noise. Excluding in SQL rather than filtering client-side matters: the row
limit then gets spent on real traffic. The sidebar toggle lives in the filter panel
under `▎noise` and defaults to **on** (`filter.hideNoise`), which is a no-op until
`noise_ips` is actually set.

Endpoints: `GET/PUT /config`, `GET/PUT /config/services`, `GET/PUT /config/teams`. `GET /services` and `GET /flag_regex` still work (read from the same DB row).

⚠ `flag_regex` and `bpf` are also read by the Go assembler at boot from env. Changing them via UI takes effect for the api immediately but the assembler keeps the old value until restart. The Config UI flags this.

## Exploit testing (`/attack/...`)

Module `services/api/attack.py`. Reads the captured flow, concatenates every `c`-direction `raw` item, replays the bytes against each target's `(ip, flow.port_dst)` via plain TCP socket (ThreadPoolExecutor, hard caps: 64 targets, 15s timeout, 256KB recv). Flag regex from `app_config` is run against each response.

Endpoints:
- `GET  /attack/preview/<flow_id>` — port, payload size, item counts (cheap precheck for the modal).
- `POST /attack/replay { flow_id, targets:[{name,ip}], timeout? }` — fires the replay, returns per-target {ok, latency_ms, response_size, response_excerpt, flag_count, flags?, error?}.
- `GET  /attack/exploit-script/<flow_id>?timeout=N` — text/x-python download (Content-Disposition: attachment). Standalone replayer with payload as hex, teams baked in, ready for the external farm.

UI: `ExploitModal` opens from a "Test exploit" button in FlowView's secondary toolbar.

### Incident packets (`GET /attack/incident/<flow_id>`)

Bundles what an alert fired into one copy-pasteable report for the patching team: `technique_map.classify()`'s tactic/technique/mitre/severity/**remediation** (a one-sentence generic fix hint — see `technique_map.py`'s `_HINT_*` constants), the decoded attacker payload (`decode.decode_item`), and `database.incident_stats(sid, src_ip)` — first/last-seen + occurrence count for that exact (rule, source) pair, via a jsonb-containment query (`signatures @> '[{"id": sid}]'`) against `flow`. `?sid=` picks which hit to report on when a flow matched more than one rule; defaults to the highest-severity hit. Response includes both structured JSON and a preformatted `text_packet` string for one-click copy. UI: "📋 incident packet" button in `ExploitModal`.

**Gotcha**: `flow.signatures` decodes off the jsonb column as plain `dict`s (`{"id", "message", "action"}`), not `database.Signature` dataclass instances, even though the dataclass exists and the type hint says otherwise — `class_row(FlowDetail)` doesn't recursively convert nested jsonb. Use `.get("message")`, never `.message` (this shipped broken once — see `test_routes_attack_incident.py`, which fakes signatures as dicts specifically to catch this class of regression, unlike `conftest.py`'s generic `fake_db` which returns `[]` from `flow_detail` and never exercises this path).

**Endpoint + vulnerable input** — what actually tells the patching team what to go fix, without any mapping to their own source code: when isolation succeeds (`attack.find_exploit_item`, same machinery "📋 Copy Exploit" uses — see below), the response also carries `endpoint` (`attack.describe_endpoint`, "METHOD /path") and `vulnerable_inputs` (`attack.locate_vulnerable_input`) — a list of `{buffer, location, value}` naming exactly which query parameter / JSON or form body field / cookie carried the payload, e.g. `query parameter "token" = "7da31352…"`, not just a raw byte dump. Reuses the firing rule's own buffer-scoped content clauses (`attack.rule_content_clauses`) so a clause scoped to the URI is checked against parsed query parameters (`urllib.parse.parse_qsl`), one scoped to the body against parsed JSON (`_flatten_json`, depth-first key-path) or form fields, one scoped to a cookie against parsed cookie pairs — never the item's raw bytes as a whole, for the same false-positive reason `find_exploit_item` cares about buffer scoping. `_find_pair_containing` checks a clause pattern against both a pair's value alone AND its `"key=value"` form, since a rule clause is sometimes written as `content:"token="` (checking the parameter's presence) rather than a fragment of its value. On `"full_flow"` (isolation failed) both fields come back empty/null rather than guessing which of several requests to inspect. UI: shown as an "Endpoint" line + bulleted "Vulnerable input(s)" list in `IncidentPacketPanel`, above the remediation text.

### Saved exploit library (`/exploits`)

Module `services/api/exploits.py` (same `set_pool`/`init_schema` pattern as `notes.py`). A one-shot captured flow only replays until you lose track of it; saving snapshots `attack.build_payload(flow)` + `port` at save time under a name/tag, so it survives independently of the source flow and the attack team can fire it at every team, every tick, without re-finding it. `attack.py`'s replay/script-generation logic is split into flow-based (`replay`, `generate_script`) and payload-based (`replay_payload`, `generate_script_from_payload`) halves so both a live flow and a saved exploit drive the identical replay path.

Endpoints: `GET /exploits` (list), `GET /exploits/<id>` (single, includes `payload_text` — see below), `POST /exploits {flow_id, name, tag?, notes?}` (operator, snapshots the flow's payload), `DELETE /exploits/<id>` (operator), `POST /exploits/<id>/replay {targets, timeout?}` (operator, same response shape as `/attack/replay`), `GET /exploits/<id>/exploit-script` (same standalone-`.py` generator as the flow-based one). UI: `/exploits` page (library table, "▶ send exploit" opens `SavedExploitModal`) + "💾 save as exploit" button in `ExploitModal`.

### Ad-hoc targets + editable payload/port

Every replay/save route (`/attack/replay`, `POST /exploits`, `/exploits/<id>/replay`) takes optional `port` and `payload_text` overrides — omit both to send byte-for-byte what was captured/saved (the original, still-default behavior). `payload_text` round-trips the payload through latin-1 (a lossless 1:1 mapping for byte values 0-255), so an operator can eyeball and hand-edit an HTTP request in a plain textarea without a hex editor; parsed server-side by `webservice._parse_payload_override`/`_parse_port_override` (shared by all three routes). `GET /attack/payload/<flow_id>` exposes a live flow's raw bytes the same way, for the editor to fetch before the operator starts typing.

Targets were never actually restricted to `/config → teams` — `_parse_targets` (also shared across the three routes) accepts any `{name, ip}`, `/config → teams` was just the only thing the old UI exposed. `components/SendExploitControls.tsx`'s `useTargetPicker`/`TargetPicker` add an "ad-hoc" input so an operator can type any IP directly (merged into the same target list as configured teams, keyed by IP so one host isn't double-targeted); `PayloadPortEditor` is the matching payload/port editor. Both `ExploitModal` and `SavedExploitModal` are built from these two shared pieces rather than duplicating the picker/editor UI.

**Gotcha discovered by actually inspecting a captured flow's items**: `attack.build_payload()` concatenates *every* client-direction item under one flow_id, and a w4rya "flow" groups a whole keep-alive session (we found one real example: signup → signin → create → list → upload → update → read, 7 requests, 23KB), not one request. Saving/replaying "the exploit" from a flow with more than one client item sends the *entire session* glued together, not just the malicious request — usually not what you want. The payload editor above is the current workaround (manually trim to the one request that matters before saving); there's no automatic per-item picker yet.

### Host header rewrite + checker-IP awareness

`attack.rewrite_host_header(payload, ip, port)` (pure, regex-based, `_HOST_HEADER_RE`) points a captured HTTP request's `Host:` line at the actual replay target instead of the original capture's host — without this, replaying byte-for-byte against a different team silently mis-routes on anything that does vhost/`server_name` routing (a bare IP:port test service won't notice either way). Wired into `_replay_one`/`replay_payload`/`replay` via a `rewrite_host` flag, applied **per target** (each connection gets its own ip:port). `webservice.py`'s replay routes enable it automatically *only* when there's no `payload_text` override — an operator's manual edit is a promise to send those exact bytes, so auto-rewrite never overwrites a deliberately-edited Host header.

`GET /attack/preview/<flow_id>` also returns `src_ip_is_checker` (checked against `app_config`'s `checker_ips` — same confirmed-checker list `/checker/candidates` populates), and `POST /exploits` echoes `source_ip_was_checker` in its response and audit log entry. Reasoning: IPs on an A/D network are often NAT'd/gatewayed, and the checker's own SLA traffic (create account → do the thing → read it back) can look procedurally identical to a real attacker's session — worth a visible warning before an operator saves or fires the checker's own routine behavior at other teams as if it were a stolen exploit. UI: warning banner at the top of `ExploitModal` when the flag is set.

### "📋 Copy Exploit" — isolating one request out of a captured session (`GET /attack/exploit-code/<flow_id>`)

The actual point of monitoring: get the same code the attacking team used, ready to hand to your own attack team. w4rya already ships `data2req.py` (`convert_flow_to_http_requests` / `convert_single_http_requests`, pre-existing upstream Tulip functionality, "Copy as requests" in FlowView) that turns a captured HTTP request into a readable `requests.post(url, headers=..., json=...)` Python call. The gap this closes: that converter runs over the *whole flow*, and a w4rya flow can bundle a multi-request session under one flow_id (see the `build_payload()` gotcha noted above) — "copy as requests" on a 7-request session hands back 7 python calls, most of them the irrelevant signup/signin/upload noise around the one request that actually matched a Suricata rule.

`attack.find_exploit_item(flow, sid)` re-checks the *firing rule's own* `content:"..."` clauses (extracted from its raw rule text via `attack.rule_content_clauses`, which greps both `suricata.rules` and `et-open/suricata.rules` by sid) against each client item, to find which single one Suricata actually meant:
- Decodes Suricata's `|hex bytes|` content syntax (`_decode_suricata_content_value`) and skips negated `content:!"..."` clauses (nothing to positively match on).
- **Respects Suricata's buffer scoping** (`attack._parse_rule_content_clauses`, a small token-by-token parser over the rule's option list): a clause under `http.uri`/`http_uri` is checked only against that item's URI, `http.request_body`/`http_client_body` only against the body, `http.method`/`http_user_agent`/`http_host`/`http_cookie` similarly — **not** against the item's raw bytes as a whole. This is load-bearing, found by testing against a real captured session: rule 1000008 requires `/api/sheets/` AND `token=` both **in the URI**; naive whole-payload substring matching let a `Cookie: auth-token=...` header (present on every authenticated request in the session) spuriously satisfy the `token=` clause on the wrong request, making the match ambiguous and silently degrading to the full multi-request session instead of the one real exploit request. Encountering any buffer keyword the parser doesn't recognize (`http.header`, `file.data`, `dns.query`, …) bails the whole rule to `"full_flow"` rather than risk scoping a match against the wrong bytes.
- `endswith`/`startswith` modifiers are checked against the item's full request-target (`_item_uri` — path **plus** query string; do not strip the query, `token=` clauses only ever match via it) — needed for e.g. `/api/route` (list) vs `/api/route/<id>` (detail), which both contain the substring `/api/route` but only the list endpoint's URI *ends with* it.
- A pcre/flowbit-only rule, zero matches, or no signature at all resolve to `"full_flow"` — safe degradation, never picks the *wrong* item. **More than one match no longer means giving up to `"full_flow"`** (see "Multi-match isolation" below) — that used to dump the *entire* session (up to hundreds of KB) any time a rule matched more than once, which was the actual root cause behind "sometimes Copy Exploit gives me way too many lines."

**Multi-match isolation (`_MAX_MATCHED_ITEMS`, "matched_items" basis)** — found by actually re-testing all 11 of this lab's rules against a *local* copy of the real vulnerable software (vulhub + friends, not stub listeners — see below) instead of trusting the earlier stub-based QA pass: two real rules were silently hitting the old ambiguous-match fallback and dumping the whole session every time. `find_exploit_item` now distinguishes three cases when >1 client item matches:
  1. **All matched items are byte-identical** (a replayed/brute-forced request fired the rule N times) → collapses to `("single_item", first_index)`; "request 3 of 40" and "request 37 of 40" carry no different information.
  2. **A small number (≤ `_MAX_MATCHED_ITEMS`, currently 5) of genuinely distinct items match** → `("matched_items", [indices])`. The real case that motivated this: MSSQL's `xp_cmdshell` rule (sid 1000018, content match with no buffer keyword → default `pkt`/raw-payload buffer) fires on **both** `EXEC sp_configure 'xp_cmdshell', 1` (the enable step) **and** `EXEC master..xp_cmdshell '...'` (the run step) in the same TDS session — both packets are genuinely part of the attack, and the old code fell back to dumping all 28 items in the flow (12KB) rather than just those 2 (now 1.1KB). `attack.narrow_flow_to_items(flow, indices)` builds a `copy.copy` of the flow with `.items` restricted to just the matched ones (server items dropped — `convert_flow_to_http_requests`/`flow2pwn` only look at `direction == "c"` items anyway, and keeping a server item would try to `recvuntil` a response to a request that got excluded); the existing flow-wide generators run unmodified against this narrowed flow.
  3. **More than `_MAX_MATCHED_ITEMS` distinct items match** → collapses to `("single_item", first_index)` too. The other real case found the same way: Nacos's unauth config-removal rule (sid 1000019, `http.method`+`http.uri`) matched **100** distinct requests in one captured session — a scanner retrying the same RCE template with a fresh random function name (`S_EXAMPLE_<random>`) and multipart boundary on every attempt. These are not byte-identical, so case 1 doesn't collapse them, but listing all 100 (93KB) isn't "the exploit, isolated" either — past the cap, the first occurrence stands in as a representative, same resolution as case 1, cutting this one down to ~1KB.

`webservice.py`'s `/attack/incident` and `/attack/exploit-code` both handle `"matched_items"` explicitly: the incident packet reports the **union** of endpoint/vulnerable-input across every matched item (deduped by location) plus a `matched_item_count` field and a "multi-stage" note in `text_packet`, instead of silently reporting only the first and dropping the rest. `/attack/exploit-code` adds `"matched_ordinals"` (1-indexed positions among client items, parallel to `client_ordinal` for the single-item case) and only sets `"item_index"` when `basis == "single_item"`.

**Non-HTTP flows**: `data2req.py`'s `requests`-based generators assume every item parses as an HTTP request line and raise (not degrade) when fed a bare-TCP payload — found by testing against a real captured flow (a "Redact-service" rule on port 5151, no HTTP framing at all). `attack.is_http_request` gates which generator runs per response: HTTP items go through `convert_single_http_requests`/`convert_flow_to_http_requests` as before; anything else falls back to `attack.raw_socket_snippet` (single isolated item — plain socket connect/send/recv) or `flow2pwn` (full-flow fallback — pwntools `recvuntil`/`write` script, already used by "Copy as pwntools"). Response includes `"protocol": "http" | "raw"` so the UI can label which kind of code it got.

Route response includes `item_index` (position in the full client+server-interleaved items array — what `convert_single_http_requests` needs; only set when `basis == "single_item"`) and `client_ordinal`/`client_item_count` (1-indexed position among client requests only, and how many there are — what's actually meaningful to show; **do not** reuse `item_index` for display, they're answering different questions and only coincide when a flow has no server items interleaved before the match). `matched_ordinals` is the `"matched_items"` analogue of `client_ordinal` — a list of 1-indexed client positions, in the order they appear in `code`. UI: a highlighted "📋 Copy Exploit" button, first in FlowView's toolbar, with a small caption reporting which case it hit (`isolated request N of M`, `isolated requests N, M of K (multi-stage match)`, or `couldn't isolate — full session (M requests)`, plus `· raw TCP (not HTTP)` when `protocol` is `"raw"`).

## Suricata rules (`/rules` tab + quick-block + auto-reload)

Module `services/api/rules.py`. Stores rules as native Suricata text in `/app/suricata-rules/suricata.rules` (host: `./suricata-rules/`, mounted rw). 'Disabled' is the standard `# ` line prefix. Auto-assigned sids start at 1,000,000.

Suricata also loads a second, larger rule file the UI never touches: `suricata-rules/et-open/suricata.rules` (Emerging Threats Open, pulled via `suricata-update`, tuned down from ~52.6k to ~40.2k active rules). See `suricata-rules/README.md` for the full custom-rule inventory, the ET Open refresh procedure, the tuning rationale, and how both were validated (a 133-pcap real-exploit collection for detection breadth, this team's own captured A/D pcaps for false-positive rate).

Endpoints: `GET /rules` (list + templates + suricata socket status), `POST /rules` (add), `PUT /rules/<sid>` (raw/enabled), `DELETE /rules/<sid>`, `POST /rules/block-ip { ip }` (quick-block writes a `drop ip <ip> any -> any any` rule), `POST /rules/reload` (B1, triggers Suricata reload-rules via its unix command socket).

**Auto-reload** (B1, `services/api/suricata_ctl.py`): when `rules_autoreload` config flag is on, every rules CRUD also calls `reload-rules` on Suricata's unix command socket (`/var/run/suricata/suricata-command.socket`). Requires Suricata to be running with `--set unix-command.enabled=yes` (already wired in `docker-compose-suricata.yml`). When suricata isn't running the api just attaches a `reload.kind=socket_missing` field to the save response — never fails the save.

`reload_rules(blocking: bool = True)`: a real reload against the full ET Open ruleset (~40k rules) takes several seconds, and several gunicorn sync workers can each try to trigger one within the same few seconds (e.g. two operators saving rule edits back to back). A cross-process file lock (`_RELOAD_LOCK_PATH`, since each worker is a separate OS process) serializes the actual socket calls. The two call sites use it differently: auto-reload (`_maybe_autoreload`, fired on every rule CRUD) calls with `blocking=False` — if another worker already holds the lock, it returns immediately with `{"return": "PENDING", "message": "reload already in progress"}` instead of tying up the request thread for the full reload duration. The manual `POST /rules/reload` route keeps the default `blocking=True`, since that's a deliberate, infrequent, user-initiated wait. Coalescing (deciding whether an in-flight/just-finished reload already covers this caller's edit) compares the rules file's `st_mtime_ns` at request time against the `reloaded_version` the winning worker recorded — not wall-clock timestamps, which would let an edit written just before another reload completes get silently absorbed into a reload that predates it.

Socket lives on `./suricata-run/` (host) bind-mounted into both api and suricata containers, so the api can `AF_UNIX` connect to it without docker.sock or PID sharing.

`_atomic_write` chmods the temp file 0644 and chowns it to the containing directory's owner before `os.replace` (same host-ownership reason as `user_store._write_atomic`): the api runs as root inside the container while `./suricata-rules` is a host bind mount, so without it the first UI rule save leaves `suricata.rules` root:root 0600 — unreadable to the suricata container's non-root user, uneditable from the host, and enough to abort `scripts/backup.sh`.

**The rules path used to be silently broken.** The api writes to `./suricata-rules` while the suricata container reads `/var/lib/suricata/rules`, which was covered by the `${SURICATA_DIR_HOST}/lib` mount — so every rule created in the UI went to a file suricata never read, with no error anywhere. `docker-compose-suricata.yml` now adds a nested bind `./suricata-rules:/var/lib/suricata/rules`; Docker mounts by ascending path depth, so it wins over the `lib` mount above it. Do **not** "simplify" this into a symlink — a symlink resolves inside the container's namespace and breaks the mapping again.

## Ready-made rule packs (`services/api/rulepacks.py`, `/rules/packs`)

39 Suricata rules for the well-known web attack shapes, in five packs
(`web-injection`, `web-rce`, `web-traversal`, `recon`, `exfil`). A rule written at
03:00 while a service is being farmed is a rule written badly; these are meant to be
installed before the game starts.

**The tags are the point.** Every rule carries `metadata: tag <x>` — the one metadata key
`cmd/enricher` reads (`alert.metadata.tag`). Without it a rule only ever produces the
generic `suricata` tag and never becomes a filter chip. Tags auto-register in the `tag`
table within ~5s of first firing, so nothing else needs wiring. Packs contribute:
`sqli`, `nosqli`, `xss`, `ssti`, `xxe`, `proto_pollution`, `rce`, `reverse_shell`,
`deserialization`, `jndi`, `webshell`, `webshell_upload`, `path_traversal`, `lfi`, `rfi`,
`ssrf`, `recon`, `scanner`, `scripted_client`, `odd_method`, `data_leak`, `app_error`,
`rce_confirmed`.

Four constraints baked into the catalog, each enforced by a test:

1. **Everything is `alert`, never `drop`.** A misfiring drop takes down our own service,
   and if it catches the checker we bleed SLA for as long as nobody notices.
2. **No `$HOME_NET` / `$EXTERNAL_NET` / `$HTTP_PORTS`.** The stack ships Suricata's stock
   variables — HOME_NET is the RFC1918 default, HTTP_PORTS is only 80 — so a rule using
   them would silently miss CTF services on odd ports. Rules say `any any -> any any` and
   rely on http protocol probing.
3. **Every rule pins its own sid** in a reserved 2,1xx,xxx block, which is what makes
   installing idempotent: `rules.add_many()` skips sids already in the file.
4. **`metadata: tag <x>` on every rule** (see above).

Endpoints: `GET /rules/packs` (any role — knowing what exists isn't privileged) returns
the catalog annotated with what is installed, per rule, so a half-installed pack reports
honestly. `POST /rules/packs/<id>` (operator, audited as `rules.pack_install`) appends
what's missing in **one** load/save cycle — installing 12 rules via `add()` would rewrite
the file and poke Suricata 12 times. `{"include_noisy": false}` leaves out the rules
flagged as also matching legitimate traffic.

**Two Suricata gotchas** these rules were bitten by, both caught by `suricata -T`:

- A literal `;` inside `pcre:` must be escaped as `\;`. Suricata splits rule options on
  `;`, so an unescaped one truncates the regex and the whole rule fails to load.
- The classic `http_uri` / `http_user_agent` / `http_method` modifiers only attach to a
  preceding `content`. Trailing one after a `pcre` is a **load error**, not a no-op — use
  the sticky buffer (`http.uri; pcre:"...";`) instead.

To validate a rule change without a UI round trip:

```
docker compose exec -T suricata sh -c 'cat > /tmp/r.rules' < some.rules
docker compose exec -T suricata suricata -T -S /tmp/r.rules -l /tmp -v
```

## Flow query pcap-name filter (`pcap_name` on `POST /query`)

The sidebar's flow list is filtered by tick, and ticks are computed from real wall-clock time relative to `start_date` (the game's tick-0 anchor) — so a pcap whose own capture timestamp falls outside the current game (a historical/test pcap loaded for detection testing, e.g. a multi-year-old public exploit-traffic collection) can never appear in the default "last N ticks" view, or any `from`/`to` tick-range view, no matter how wide, unless you already know how far off its real date is from `start_date` to compute the right tick offset — not something anyone should have to do by hand. `database.FlowQuery.pcap_name` (substring, case-insensitive, matched against `pcap.name` in `flow_query()`'s existing `LEFT JOIN pcap`) sidesteps ticks entirely by filtering on the flow's *source file* instead of its *time*. UI: a "pcap source" text input in `FlowList`'s filter panel (`PCAP_FILTER_KEY = "pcap"` in the URL), which — client-side, not a backend constraint — drops the `from`/`to` time filter whenever it has a value, since the two are usually reached for the same reason (the time filter can't find the flow) and would otherwise silently AND together into "nothing."

## Flow query noise filter (`hide_noise` on `POST /query`)

`ip_src_exclude` on `database.FlowQuery`, resolved server-side from `app_config.parse_noise_ips(app_config.get("noise_ips"))` when the request sets `hide_noise` — the checker and the team's own tooling account for nearly all traffic volume, and hiding them server-side (rather than making the frontend know which IPs count as noise) is what leaves the sidebar's flow list actually readable. UI toggle lives in `FlowList`'s filter panel next to the pcap-source filter (`toggleHideNoise`), labeled "checker + self". Configure the underlying IP list at `/config` (`noise_ips`).

## Notes per flow (`/flow/<id>/notes`)

Module `services/api/notes.py`. Table `flow_notes (id uuid pk, flow_id uuid, author text, body text, created_at)`. Author is the session user; only the author can delete their own note. Notes panel rendered below the Meta block in FlowView.

## Flag-leak alarm + toasts

Client-only. `FlagLeakWatcher` polls `/query` with `tags_include=['flag-out']` every 15s, primes a seen-set on first load (no toasts for historical leaks), and dispatches a danger toast on every new id. Toasts render bottom-right via `Toasts.tsx`, dispatched through `store/toasts.ts`. To trigger one manually (debugging): `dispatch(pushToast({ message: 'hi', severity: 'danger' }))`.

## Per-service stats (B2)

`GET /services/stats?ticks=N` (1..50, default 5) returns per-configured-service `{flows, attacks, flag_in, flag_out}` over the last N ticks. One grouped SQL scan, aligned by (ip, port) against the services config. Services with zero matching flows still appear with zeros.

Frontend uses this to render mini-counts on each service chip in the sidebar — chip border cascades danger (flag-out) > warning (attacks) > violet (any flows) > dim (idle).

## Pipeline health (`/pipeline/health`)

"Why am I not seeing traffic?" is the most expensive question during a game, and answering
it by hand means checking the capture, the pull loop, the assembler and the database in
turn. This is that check as one call.

`GET /pipeline/health` (any role) returns `status` plus the evidence behind it:

| status | means | where to look |
|---|---|---|
| `ok` | newest flow is younger than the stale window | — |
| `lagging` | flows are old, **nothing** is waiting on disk | the vulnbox: capture or pull loop |
| `stalled` | flows are old **and** pcaps on disk aren't in the flow table | the assembler |
| `idle` | no flows at all within the horizon | fresh install, or nothing ever ingested |

The `lagging` / `stalled` split is the point of the endpoint: it says which half of the
pipeline to go look at.

- **Stale window** = 2 ticks (min 60s), so one slow rotate-then-pull cycle doesn't cry wolf.
- **Horizon** = 1 day, and it exists for query cost. `flow.time` is a generated column with
  no index of its own, so a bare `max(time)` scans the table; every predicate goes through
  `fid_pack_low()` on the primary key instead, exactly like the other query paths.
- **Disk side** reads `configurations.traffic_dir` (the api already bind-mounts the capture
  dir read-only). If it isn't mounted, `pcaps.readable` is `false` and the counts are
  `null` — the database half still answers rather than 500ing.
- `pcaps.ingested` counts rows in the `pcap` table, so it can exceed `on_disk` once files
  have been rotated away — the assembler remembers what it consumed.

UI: a lag counter in the war-room top bar, and a banner that appears **only** when the
status isn't `ok` (a wall display with a permanent status bar teaches people to ignore it).

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

~305 tests in `services/api/tests/`, all offline, a few seconds (`./scripts/test.sh -q` prints the current count):

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

### Functional QA of "Copy Exploit" against real vulnerable software (not part of this repo)

`pytest` above proves the code *generates* correctly and is byte-exact against captured ground truth — it does not prove the generated script actually *exploits* anything, since none of the 11 target technologies run in this repo's own `docker-compose.yml`. That was verified separately with a local lab at `~/projects/vuln-lab/` (vulhub clone + a few standalone containers, **not** part of this repo, not committed anywhere): `vulhub/{fastjson,log4j,nacos,shiro,struts2,tomcat,weblogic}` (each `docker compose up -d` in its own subdirectory — 3 of them collide on host port 8080 by default, remapped tomcat→18080 and struts2→28080 in their `docker-compose.yml`, nacos's 5005 debug port→5006) plus standalone `vulnerables/web-dvwa`, `vulfocus/zentaopms_9.1.2_sql` (entrypoint is `/zentaopms/www/index.php`, not `/`), `mcr.microsoft.com/mssql/server`, and `linuxserver/openssh-server`. **MSSQL's `xp_cmdshell` cannot be reproduced this way** — confirmed across both the 2017 and 2019 Linux images that this is a genuine platform limitation (`xp_cmdshell` doesn't exist in SQL Server for Linux at all, not an edition/config issue), so that one rule's *code generation* was verified but not full end-to-end command execution.

Fetching exploit code for QA without a browser session: exec into the `api` container and drive `webservice.application`'s Flask test client directly (`webservice.db.open()` first — the pool is lazy, `open=False`, see above — then `client.session_transaction()` to set `sess["user"] = "<an admin username>"`, bypassing the need to know a real bcrypt password). This is also how the two real isolation bugs documented above (Nacos's 100-distinct-match case, MSSQL's 2-distinct-match case) were actually found: re-running "Copy Exploit" against the 11 real captured flows turned up two that were still hitting `"full_flow"` and dumping 12–93KB, which a purely synthetic unit test wouldn't have surfaced.

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
