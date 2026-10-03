# Vulnbox ops module — implementation plan

**Goal:** a `/vulnbox` page to prepare + defend our own A/D vulnbox (SSH key,
preflight, recon→import, git baseline/backup), one button each.

**Architecture:** Flask Blueprint package `services/api/vulnbox/` (registered
once in `webservice.py`) + RTK Query `injectEndpoints` feature folder
`frontend/src/features/vulnbox/`. No DB schema change, no new dependency, no new
container. Dependency direction: `routes → jobs → {recon,backup,preflight} → ssh → keys → config`.

**Tech stack:** Python 3.10 / Flask / psycopg (api), subprocess (ssh/git/ssh-keygen);
React 18 / TS / RTK Query / Tailwind (`hax-*`); pytest offline.

**Spec:** `docs/superpowers/specs/2026-10-03-vulnbox-ops-design.md`

**Global constraints (from spec §9):** no runtime AI; no schema change; no new
dep; never touch `authorized_keys`; never render the private key; one job at a
time, button-only; host = `10.60.<team_id>.2` unless `vulnbox_ip` set; mount
`./vulnbox-data` in both compose files; Blueprint + feature folder; match
`hax-*`/`font-mono`/`▎`/`useCanRole` style.

**Review focus (high-risk inputs → test):**
1. Hostile service/dir name from the vulnbox (`../`, `;rm`, spaces) → path/command injection → rejected by `^[A-Za-z0-9._-]+$`, argv-only.
2. Private key leakage → assert it never appears in any route JSON, only the download route.
3. Concurrent job start (two operators) → second gets 409, lock holds.
4. Host unreachable vs auth-fail vs path-missing → preflight reports the right one, never a generic failure.
5. Missing `team_id` and no `vulnbox_ip` → `resolve_host()` raises a clear error, not a malformed `10.60..2`.

## File structure

**Backend — `services/api/vulnbox/` (new):**
- `__init__.py` — exposes `bp` only.
- `config.py` — paths/timeouts, `SERVICE_RE`, `resolve_host()`, size cap, new app_config keys/validators helpers.
- `keys.py` — `status()`, `generate(rotate)`, `private_key_path()`, `forget_host_key()`.
- `ssh.py` — `ssh_argv()`, `run_remote_script(name)`, `git_*` argv builders; no `shell=True`.
- `preflight.py` — `run() -> list[Check]`.
- `recon.py` — `run() -> list[ReconService]`, `parse_recon(text)`, `to_services(rows, host)`.
- `backup.py` — `run() -> list[BackupResult]`.
- `jobs.py` — `start(kind, fn)`, `current()`, `_write/_read` atomic, lock, stale detection.
- `routes.py` — Blueprint; validate → call → audit.
- `remote/preflight.sh`, `remote/recon.sh`, `remote/backup.sh` — tab-separated output, `shlex`-safe.
- `README.md` — what/flow/security/roadmap.

**Backend — modified:**
- `webservice.py` — import + `application.register_blueprint(vulnbox.bp)`; `vulnbox.set_pool`/`init_paths` in `create_app()`.
- `app_config.py` — 4 keys in `DEFAULTS` + `SCALAR_KEYS`, validators in `coerce_scalar`.

**Tests — `services/api/tests/vulnbox/` (new):** `__init__.py`, `test_config.py`, `test_keys.py`, `test_ssh.py`, `test_preflight.py`, `test_recon.py`, `test_backup.py`, `test_jobs.py`, `test_routes.py`; plus rows in `tests/test_routes_roles.py`.

**Frontend — `frontend/src/features/vulnbox/` (new):** `index.ts`, `types.ts`, `api.ts` (injectEndpoints), `VulnboxPage.tsx`, `components/{KeyCard,PreflightCard,ReconCard,BackupCard}.tsx`.

**Frontend — modified:** `api.ts` (+`"Vulnbox"` tag), `App.tsx` (route), `components/Header.tsx` (nav).

**Infra/docs — modified:** `docker-compose.yml`, `docker-compose-suricata.yml`, `install.sh`, `.gitignore`, `services/api/Dockerfile-api` (assert git+ssh present), `CLAUDE.md`, `CHANGELOG.md`, `README.md`.

## Tasks

Each task: write test(s) → run red → implement → run green → commit.

### T1 — config + app_config keys
- Create: `vulnbox/__init__.py` (temporarily empty `bp` placeholder), `vulnbox/config.py`.
- Modify: `app_config.py`.
- Test: `test_config.py`.
- Produces: `SERVICE_RE`, `resolve_host(team_id, override) -> str` (raises `ValueError` on no override + non-numeric team_id), `MAX_FILE_BYTES`, `paths` helpers. `app_config.coerce_scalar` handles the 4 vulnbox keys.
- Steps:
  1. Test `resolve_host("3","")=="10.60.3.2"`, `resolve_host("0","10.9.9.9")=="10.9.9.9"`, `resolve_host("x","")` raises.
  2. Test `app_config.coerce_scalar("vulnbox_ssh_port","22")==22`, out-of-range raises; `vulnbox_user` charset; `vulnbox_services_path` must be absolute.
  3. Implement; green; commit.

### T2 — keys
- Create: `vulnbox/keys.py`. Test: `test_keys.py`.
- Consumes: `config.paths`. Produces: `status()->dict` (no private material), `generate(rotate=False)->dict`, `private_key_path()->Path`, `forget_host_key()->bool`.
- Steps:
  1. Test generate writes 0600 private + .pub, returns fingerprint, no private bytes in dict.
  2. Test generate without rotate raises when key exists; with rotate replaces it.
  3. Test `status()` on empty dir → `{exists:False}`.
  4. Implement (`ssh-keygen` via subprocess; in tests, monkeypatch to write fixture files); green; commit.

### T3 — ssh argv + remote scripts
- Create: `vulnbox/ssh.py`, `vulnbox/remote/*.sh`. Test: `test_ssh.py`.
- Produces: `ssh_argv(host,port,user,key,known_hosts)->list[str]` (BatchMode, IdentitiesOnly, accept-new, ConnectTimeout), `run_remote_script(name,...)`, `git` argv builders.
- Steps:
  1. Test argv contains the hardening options and never `StrictHostKeyChecking=no`.
  2. Test `run_remote_script` rejects an unknown script name; builds `ssh … bash -s` with the script on stdin (subprocess faked).
  3. Test service-name guard rejects `../x`, `a;b`, `a b`.
  4. Implement; green; commit.

### T4 — preflight
- Create: `vulnbox/preflight.py`. Test: `test_preflight.py`.
- Produces: `run()->list[{name,ok,detail}]` covering key/reachable/auth/path/git/docker; faked ssh layer.
- Steps: test host-unreachable vs auth-fail vs path-missing map to distinct items; implement; green; commit.

### T5 — recon
- Create: `vulnbox/recon.py`. Test: `test_recon.py`.
- Produces: `parse_recon(text)->rows`, `to_services(rows,host)->config services`, `run()`.
- Steps: test parser on sample TSV incl. a hostile name (dropped) and 9000–9999 flagging; test `to_services` shape matches `app_config.validate_service`; implement; green; commit.

### T6 — backup
- Create: `vulnbox/backup.py`. Test: `test_backup.py`.
- Produces: `run()->list[{service,status,commit,files,skipped,detail}]`; status `created|updated|skipped|error`.
- Steps: test result shaping from faked git output incl. size-skip; test bare-repo path never inside service dir; implement; green; commit.

### T7 — jobs
- Create: `vulnbox/jobs.py`. Test: `test_jobs.py`.
- Produces: `start(kind,fn)->id`, `current()->record|None`, 409 when running, stale `running` → `interrupted`.
- Steps: test lock blocks a second start; test stale record past timeout reads error; atomic write; green; commit.

### T8 — routes (Blueprint) + wiring
- Create: `vulnbox/routes.py`, `vulnbox/README.md`; finalize `__init__.py`. Modify: `webservice.py`.
- Test: `test_routes.py` + new rows in `test_routes_roles.py`.
- Produces: the 10 routes in spec §4, each role-gated + audited; `GET /vulnbox/job`.
- Steps:
  1. Add matrix rows (admin: key POST/GET-private/known-host/import/seed; operator: preflight/recon/backup). Red.
  2. Implement Blueprint; register in `webservice.py`; `set_pool`/paths in `create_app()`.
  3. Test private key never in `GET /vulnbox/key` JSON; 409 on concurrent job; audit.log called per mutation (monkeypatched).
  4. Green; full `pytest` green; commit.

### T9 — frontend feature folder
- Create: `features/vulnbox/{index.ts,types.ts,api.ts,VulnboxPage.tsx,components/*}`. Modify: `api.ts` (+tag), `App.tsx`, `Header.tsx`.
- Steps:
  1. `injectEndpoints` for all routes + `"Vulnbox"` tag; types mirror backend dicts.
  2. Page: 4 cards ordered by timeline, read-only banner via `useCanRole`, polls `GET /vulnbox/job` while running (reuse `useVisibilityAwarePolling`).
  3. KeyCard: public key + Copy (`useCopy`), generate/rotate (confirm), download private (anchor), forget host key. PreflightCard: run + checklist. ReconCard: run + table + import. BackupCard: run + per-service rows.
  4. `tsc` clean; commit.

### T10 — infra + docs
- Modify compose ×2 (api `./vulnbox-data:/app/vulnbox-data`), `install.sh` (`mkdir -p vulnbox-data/{keys,backups}` + ownership note), `.gitignore` (`/vulnbox-data/`), `Dockerfile-api` (assert `git`+`ssh` on build), `CLAUDE.md` (module section + permission-matrix rows + Blueprint/feature-folder convention), `CHANGELOG.md`, `README.md`.
- Steps: apply; re-run `pytest`; commit.

### T11 — review + push
- Self-review diff vs spec (coverage, no leaked key, style); run full `pytest` + `tsc`; push `claude/cool-johnson-t1lmoy`.

## Plan audit (verified against the codebase before implementing)

Checked the real integration points; findings folded back into the tasks:

- **Blueprint auth works unchanged.** `@application.before_request → auth.require_auth()` is app-level and covers Blueprint routes; my routes aren't in `PUBLIC_PATHS`, so they require a session. No Blueprint exists yet — this is the first (documented in CLAUDE.md).
- **Inverse role test (`test_every_gated_route_is_in_the_matrix`) iterates `app.url_map` and reads each gated view via `__wrapped__`.** It will see the Blueprint's gated views. Every (method, role) pair I introduce — (POST,admin),(GET,admin),(DELETE,admin),(POST,operator) — already exists in the matrix, so no surprise failure; I still add explicit rows so the forward tests actually exercise each route.
- **FIX 1 — paths must be env-driven.** `config.py` reads `W4RYA_VULNBOX_DIR` (default `/app/vulnbox-data`), exactly like `W4RYA_USERS_FILE`/`W4RYA_RULES_FILE`, so a conftest fixture can redirect it at `tmp_path`. Added to T1.
- **FIX 2 — tests must stay network-free even though the role-matrix forward test actually invokes `POST /vulnbox/{preflight,recon,backup}`.** Design rule: **no key ⇒ no socket.** Preflight checks key *first*; if absent, the SSH-dependent checks report `skipped — no key` and open nothing. Recon/backup return an immediate `error` result when `keys.status().exists` is False. Jobs run in a `daemon` thread so pytest never blocks. Added tests: "preflight with no key opens no socket", "recon with no key errors without ssh". Folded into T4/T5/T7.
- **FIX 3 — no side effects at import.** `webservice.py` imports the Blueprint at module load, and tests import `webservice` with no pool. So: no `mkdir`/IO at import; `config.init_paths()` is called from `create_app()`, and every write lazily ensures its dir. `routes.py` uses `app_config.get` (pool-less → DEFAULTS) and `audit.log` (no-op without pool). Added to T1/T8.
- **No `/vulnbox*` path or name collision** anywhere in `services/api` or `frontend/src`.

## Self-review (writing-plans checklist)
- Spec coverage: every §4 route + §5 jobs + §6 security item owned by T1–T8; UI §4 by T9; infra §3.1/compose by T10. ✓
- Steps decide something (each has a red test first). ✓
- Types consistent: `resolve_host`, result dicts, config services shape reused across tasks. ✓
- Review-focus inputs each have a test (T3 hostile name, T8 key-leak + 409, T4 reachability split, T1 host derivation). ✓
- Proportion: 11 tasks for an 9-section spec — reasonable. ✓

## Execution notes

Executed in task order with a red/green test cycle per module. Deviations from the
tasks above are recorded in the spec's §10. Verification: full api suite green
(`pytest tests/`, which runs the real remote scripts with bash and a real local
git clone; only the ssh hop is faked), `tsc --noEmit` clean, `vite build` OK, and
the page rendered in a real browser against the real api. Not yet verified: a run
against a real vulnbox over ssh — do that in the Demo 2 slot.
