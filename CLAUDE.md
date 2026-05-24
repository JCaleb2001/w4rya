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
- `frontend/src/store/index.ts` — Redux store config (mounts `w4ryaApi.reducer` + filter slice).
- `frontend/src/store/filter.ts` — `W4ryaFilterState` (tag include/exclude, flag/flagid filters, AND/OR intersection mode).
- `frontend/src/components/Header.tsx` — top bar: brand, text search, service select, start/end date pickers, hotkeys.
- `frontend/src/components/Corrie.tsx` — time-series correlation visualization.
- `frontend/src/pages/Home.tsx` — welcome screen + shortcut reference.
- `frontend/src/pages/FlowView.tsx` — flow detail view with hex/text representations, download buttons, pwntools/python export.
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

## Roadmap (planned, not yet implemented)

- **Basic auth** for team-internal use (bcrypt + session cookie or JWT, Flask middleware, frontend login/logout). Not internet-facing; threat model is "keep curious teammates / scoreboard scrapers out", not "production AuthN".
- **Suricata rules CRUD from UI** — list/create/edit/delete rules in `${SURICATA_DIR_HOST}/lib/rules/suricata.rules`, with basic syntax validation and Suricata container reload.

When implementing either, do read-only analysis first (the user will ask) before touching code.
