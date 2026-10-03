# Vulnbox ops module — implementation plan

**Goal:** a `/vulnbox` page to prepare and defend our own A/D vulnbox, with one
button each for: the SSH key, a preflight check, recon → import, and a git
baseline/backup.

**Architecture:** a Flask Blueprint package `services/api/vulnbox/`, registered once
in `webservice.py`, plus an RTK Query `injectEndpoints` feature folder,
`frontend/src/features/vulnbox/`. No DB schema change, no new dependency, no new
container. Dependency direction:
`routes → jobs → {preflight, recon, backup} → ssh → keys → config`. Game-specific
values are settings, and named bundles of them live in `presets.py`.

**Tech stack:** Python 3.10 / Flask / psycopg (api), subprocess (ssh/git/ssh-keygen);
React 18 / TS / RTK Query / Tailwind (`hax-*`); pytest, offline.

**Spec:** `docs/superpowers/specs/2026-10-03-vulnbox-ops-design.md`

**Global constraints (from the spec, §9):**
- no runtime AI;
- no schema change;
- no new dependency;
- never touch `authorized_keys`;
- never render the private key;
- one job at a time, button-only;
- game-agnostic code;
- mount `./vulnbox-data` in both compose files;
- Blueprint backend + feature-folder frontend;
- match the `hax-*` / `font-mono` / `▎` / `useCanRole` style.

**Review focus (high-risk input → the test that covers it):**
1. A hostile service/dir name from the vulnbox (`../`, `;rm`, spaces) could inject
   into a path or command → rejected by `^[A-Za-z0-9._-]+$`, argv-only.
2. The private key could leak → assert it never appears in any route JSON, only in
   the download route.
3. Two operators could start jobs at once → the second gets 409 and the lock holds.
4. Host unreachable vs auth failure vs missing path → preflight reports the right
   one, never a generic failure.
5. `vm_ip` unset or malformed → a clear 400 that says how to fix it.
6. A preset could hold a value `/config` rejects → every preset entry is validated
   by the suite.

## File structure

**Backend — `services/api/vulnbox/` (new):**
- `__init__.py` — exposes `bp` and `init_paths`.
- `config.py` — paths, timeouts, `SERVICE_RE`, `resolve_host()`, port ranges, validators.
- `presets.py` — game presets (data) and the `/config` → `.env` name map.
- `keys.py` — `status()`, `generate(rotate)`, `fingerprint()`, `forget_host_key()`.
- `ssh.py` — `ssh_argv()`, `run_remote_script(name)`, `git_ssh_command()`; never `shell=True`.
- `preflight.py` — `run(target) -> list[check]`.
- `recon.py` — `parse`, `build(parsed, path, service_ports)`, `to_config_services`, `merge_services`, `run`.
- `backup.py` — `parse`, `remote_url` (IPv6-safe), `run(target)`.
- `jobs.py` — `start(kind, fn, actor)`, `snapshot()`, the lock, interrupted detection.
- `routes.py` — the Blueprint.
- `remote/{preflight,recon,backup}.sh` — tab-separated output, `shlex`-safe args.
- `README.md` — flow, settings, presets, files, security, troubleshooting, roadmap.

**Backend — modified:**
- `webservice.py` — register the Blueprint; call `init_paths()` in `create_app()`.
- `app_config.py` — 4 `vulnbox_*` keys plus their validators.

**Tests — `services/api/tests/vulnbox/` (new):** `test_{config,presets,keys,ssh,preflight,recon,backup,jobs,routes}.py`. Also new rows in `tests/test_routes_roles.py` and per-test data-dir isolation in `tests/conftest.py`.

**Frontend — `frontend/src/features/vulnbox/` (new):** `index.ts`, `types.ts`, `api.ts`, `VulnboxPage.tsx`, `components/{Card,KeyCard,PreflightCard,ReconCard,BackupCard}.tsx`.

**Frontend — modified:**
- `App.tsx` (route) and `Header.tsx` (nav).
- `pages/Config.tsx` + `GameConfig` in `api.ts` (the new settings).

**Infra/docs — modified:**
- compose ×2, `install.sh`, `.gitignore`, `Dockerfile-api` (asserts git + ssh);
- `scripts/backup.sh`;
- `CLAUDE.md`, `CHANGELOG.md`, `README.md`.

## Tasks

Each task follows the same cycle: write the test(s) → run red → implement → run
green → commit.

| # | Task | Key tests |
|---|---|---|
| T1 | config + `app_config` keys | `resolve_host` (ip, IPv6, hostname, unset, junk); port-range parse/normalize/match; `coerce_scalar` for each key; env-driven paths |
| T2 | keys | 0600 private key; public key only in `status()`; refuse to overwrite without rotate; fingerprint equals `ssh-keygen -lf` |
| T3 | ssh + remote scripts | hardening options present; never `StrictHostKeyChecking=no`; unknown script refused before spawning; hostile args single-quoted |
| T4 | preflight | no key → no socket; unreachable vs auth fail vs missing path; real `preflight.sh` run locally |
| T5 | recon | compose `working_dir` mapping; hostile names dropped; service-port ranges (and "no ranges = all ports"); range-expansion cap; upsert without delete; real `recon.sh` |
| T6 | backup | baseline in a bare repo outside the service dir; unchanged / updated; size cap; unsafe name; real `backup.sh` + real local clone/pull; IPv6 URL |
| T7 | jobs | 409 while running; per-kind results; dead worker → interrupted (by lock) |
| T8 | routes + wiring | role matrix; private key never in JSON; no-store download; 409; audit; import; presets with a test-only preset; clear 400/503 |
| T9 | frontend feature folder | `tsc --noEmit` clean; `vite build`; rendered in a real browser against the real api |
| T10 | infra + docs | compose YAML parses with the mount in both files; `bash -n`; docs free of game-specific text |
| T11 | review + push | full suite, `tsc`, final diff review |

## Self-review (writing-plans checklist)

- **Spec coverage:** every route, job, security item and setting in the spec has an
  owning task. ✓
- **Steps decide something:** each step starts from a failing test. ✓
- **Types consistent:** `Target`, port ranges, result dicts and the services shape
  are shared across tasks. ✓
- **Review focus:** every high-risk input above has a test. ✓
- **Proportion:** 11 tasks for a 10-section spec. ✓

## Execution notes

Executed in task order with a red/green cycle per module. The decisions made along
the way are recorded in the spec, §10.

Verification:
- the full api suite is green;
- `tsc --noEmit` is clean and `vite build` succeeds;
- the page renders in a real browser against the real api.

Still to verify: a run against a real vulnbox over ssh, in a game's practice or
test slot.
