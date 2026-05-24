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
- `docker-compose-test.yml` — **stale**, still wired to MongoDB. Don't trust it.

## Key frontend files

- `frontend/src/api.ts` — the **w4ryaApi** RTK Query slice. All backend calls live here; if you add an API endpoint server-side, register a query/mutation here.
- `frontend/src/store/index.ts` — Redux store config (`w4ryaApi.reducer`, `filter`, `toasts`).
- `frontend/src/store/filter.ts` — `W4ryaFilterState` (tag include/exclude, flag/flagid filters, AND/OR intersection mode).
- `frontend/src/store/toasts.ts` — global toast slice (`pushToast`, `dismissToast`).
- `frontend/src/components/Header.tsx` — top bar: brand, search, date pickers, hotkeys, page nav (Config / Rules / Graph), user menu (Phase A4+ added Config/Rules buttons).
- `frontend/src/components/FlowList.tsx` — sidebar virtualized flow list, filter panel (services multi-select + tag intersection chips), keyboard nav.
- `frontend/src/components/Corrie.tsx` — time-series correlation viz (ApexCharts).
- `frontend/src/components/ExploitModal.tsx` — Test-Exploit modal (replays a flow against configured teams, downloads farm script).
- `frontend/src/components/Toasts.tsx` — bottom-right toast container subscribed to `store.toasts`.
- `frontend/src/components/FlagLeakWatcher.tsx` — polls `tags_include=['flag-out']` every 15s; new ones dispatch danger toasts. Mounted in Layout.
- `frontend/src/components/NotesPanel.tsx` — per-flow notes UI (rendered below Meta in FlowView).
- `frontend/src/pages/Home.tsx` — welcome screen + shortcut reference.
- `frontend/src/pages/Login.tsx` — auth gate; rendered when RequireAuth sees 401.
- `frontend/src/pages/Config.tsx` — /config route, three tabs: Game / Services / Teams.
- `frontend/src/pages/Rules.tsx` — /rules route, Suricata rules CRUD + templates.
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
5. **`# tulip:` comment markers** in `services/go-importer/converters/` — these document changes the original Tulip team made relative to upstream [flower](https://github.com/secgroup/flower). Keep them as historical record; do not rewrite to `w4rya`.

## Known vestigial / stale code (not worth fixing reactively)

- `dev.sh` runs `docker-compose up -d mongo`, but the main compose has no mongo service — it's broken.
- `docker-compose-test.yml` still wires MongoDB and an orphan `flagidendpoint` test image.
- `services/README.md` describes the legacy MongoDB architecture.
- `services/flagids/flagids.py:30` prints `"CONNECTION TO MONGO ESTABLISHED"` but the file only imports `psycopg` — dead string.

Leave these alone unless we're doing an explicit cleanup pass; they don't affect the live stack.

## Auth

Basic auth is enabled. The api requires a Flask session cookie for every endpoint except `/`, `/login`, `/logout`.

- **Storage**: `auth/users.yaml` (gitignored). Schema: `users: { <name>: { password_hash: <bcrypt> } }`. Read by `services/api/auth.py` with mtime-based caching, so editing the file doesn't strictly require a restart, though `docker compose restart api` is safer.
- **Cookie**: name `w4rya_session`, httpOnly, SameSite=Lax, Secure=False (flip to True when running behind HTTPS), 7-day lifetime. Signed with `W4RYA_SECRET_KEY` from `.env`.
- **Mount**: `./auth:/app/auth` (rw — the bootstrap CLI writes to it; the api code only reads).
- **Frontend**: `frontend/src/api.ts` wraps `fetchBaseQuery` with `credentials:'include'`, a `Me` tag type, and a 401 catcher that invalidates `Me` (so mid-session expiry triggers RequireAuth → redirect to `/login`). `RequireAuth` in `App.tsx` is the gate.

### Bootstrap a user

```
docker compose run --rm api python /app/auth/add_user.py <username>
```

Prompts for password (getpass, no echo). Writes bcrypt cost-12 hash to `auth/users.yaml`. Then `docker compose restart api` (or just wait for the mtime cache to expire on next request).

Do NOT use `sudo` for the above — your user is in the `docker` group, and `sudo` makes `users.yaml` root-owned on the host (annoying to edit later). If you already did, `sudo chown -R $USER:$USER auth/` fixes it.

### Rotating a password

Re-run `add_user.py <same-username>` — it overwrites the hash for that user. To remove a user, edit `auth/users.yaml` by hand and delete the entry.

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

## Suricata rules (`/rules` tab + quick-block)

Module `services/api/rules.py`. Stores rules as native Suricata text in `/app/suricata-rules/suricata.rules` (host: `./suricata-rules/`, mounted rw). 'Disabled' is the standard `# ` line prefix. Auto-assigned sids start at 1,000,000.

Endpoints: `GET /rules` (list + templates), `POST /rules` (add), `PUT /rules/<sid>` (raw/enabled), `DELETE /rules/<sid>`, `POST /rules/block-ip { ip }` (quick-block writes a `drop ip <ip> any -> any any` rule).

Reload is **manual** for now — `docker compose -f docker-compose-suricata.yml restart suricata` (the UI shows the command in a banner). Auto-reload (SIGUSR2 via docker.sock or a control FIFO) is a future sprint.

When running the suricata variant, the same `./suricata-rules/` dir is what api edits, but the suricata container expects rules under `${SURICATA_DIR_HOST}/lib/rules/`. Either align via a symlink or remount; this is left to the team's deploy.

## Notes per flow (`/flow/<id>/notes`)

Module `services/api/notes.py`. Table `flow_notes (id uuid pk, flow_id uuid, author text, body text, created_at)`. Author is the session user; only the author can delete their own note. Notes panel rendered below the Meta block in FlowView.

## Flag-leak alarm + toasts

Client-only. `FlagLeakWatcher` polls `/query` with `tags_include=['flag-out']` every 15s, primes a seen-set on first load (no toasts for historical leaks), and dispatches a danger toast on every new id. Toasts render bottom-right via `Toasts.tsx`, dispatched through `store/toasts.ts`. To trigger one manually (debugging): `dispatch(pushToast({ message: 'hi', severity: 'danger' }))`.

## Roadmap (planned, not yet implemented)

Phase A is done (Configs / Exploit testing / Multi-service filter / Suricata rules+block / Notes+alerts). Next ideas surface in the working brainstorm (this file's git log + the recent conversation):

- **Auto-reload Suricata** when rules are saved (decide: SIGUSR2 via docker.sock vs control FIFO vs suricatasc).
- **Per-service stats** badges on chip (`flows/tick`, attacks last 5 ticks, flags lost) — extends the multi-select.
- **Attack timeline** — chronological Suricata alerts grouped by service+attacker.
- **Loss attribution** — link a "lost flag at tick N" event from the scoreboard scraper to the flow that caused it.
- **Roles + audit log** layered on the existing auth.
- **Webhook to Discord/Slack** for critical toasts (server-side delivery instead of client).
- **War-room mode** — fullscreen auto-rotating service-grid for a TV.

When implementing, do read-only analysis first (the user usually asks) before touching code.
