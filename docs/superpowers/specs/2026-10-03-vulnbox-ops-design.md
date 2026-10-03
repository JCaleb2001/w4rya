# Vulnbox ops module — design spec

- **Date:** 2026-10-03
- **Branch:** `claude/cool-johnson-t1lmoy`
- **Status:** implemented (as-built; see §10 for what changed during implementation)
- **Author:** nightwing (paired with Claude)

## 1. Goal

Give the team one place in w4rya — a `/vulnbox` page — to get **our own
vulnbox** ready and protected for an Attack/Defense game: generate the SSH
key to paste into the A/D platform, verify the box is reachable, discover the
running services (and import them into `/config`), and take a git **baseline +
snapshots** of the service code. One button per action, nothing scheduled.

This is preparation + defense tooling for *our* box. It never touches another
team's host, and it runs no AI at runtime (CLAUDE.md hard constraint; ECSC
handbook §6.11 bans LLMs during the game, but explicitly allows using them to
*prepare tooling beforehand* — which is what building this is).

## 2. Platform context (ECSC 2026, from the handbook + A/D wiki)

Facts the module depends on, with their consequences:

| Fact | Consequence for the module |
|---|---|
| Vulnbox is at `10.60.<TEAM>.2` (team subnet `10.60.<TEAM>.0/24`). | Derive the host from `team_id`; allow a manual override for demo slots. |
| VM access = **submit your SSH public key to the platform**; organizers provision `/root/.ssh/authorized_keys`. | Generate a keypair, show the **public** half to paste in. Never touch `authorized_keys`. |
| Access is over WireGuard, reachable only when the host VPN is up. | Preflight must distinguish "VPN/host down" from "SSH key rejected". |
| Services live on ports **9000–9999**. | Recon highlights that range; anything else is our own tooling. |
| Round = 60s, flags valid 4 rounds, flag regex `^ECSC\{[A-Za-z0-9_-]{32}\}$`, game starts 2026-10-15 11:00 CEST. | "ECSC 2026 defaults" button seeds these into `/config`. |
| Screen recording is mandatory during the game (§6.12). | The **private** key is only ever downloaded as a file, never rendered on screen. |
| Keys must be submitted before 10:30 (organizers boot the boxes then). | Key card is first; the page is ordered by the game-day timeline. |
| §6.7.1 bans excessive load on the infrastructure. | One job at a time, by button only, service-by-service, with size caps. |

## 3. Architecture

Follows the existing w4rya patterns exactly; adds no new runtime dependency, no
DB schema change, no new container.

- **Backend:** a self-contained package `services/api/vulnbox/` exposing a Flask
  **Blueprint** (`bp`). `webservice.py` registers it with one line. This is the
  first Blueprint in the API; it is documented in CLAUDE.md as the convention
  for new feature modules. The app-wide `before_request` auth guard already
  covers Blueprint routes, so auth/roles work unchanged.
- **Frontend:** a feature folder `frontend/src/features/vulnbox/`. Its endpoints
  are added to the single shared `w4ryaApi` slice via `injectEndpoints` (RTK
  Query code-splitting), not a second API. The feature declares its own
  `"Vulnbox"` tag via `enhanceEndpoints({addTagTypes})`, so the base `api.ts` is
  untouched.
- **Dependency direction (one way):** `routes → jobs → {recon, backup, preflight} → ssh → keys → config`.
  `config.py` holds paths, timeouts and validators used by all of them.

### 3.1 Data on disk

A single git-ignored host directory, bind-mounted into the api container at
`/app/vulnbox-data` (same bind-mount style as `./auth`, `./suricata-rules`):

```
vulnbox-data/
  keys/
    id_ed25519        # private, 0600, download-only, never rendered
    id_ed25519.pub    # public, shown with a Copy button
    known_hosts       # pinned vulnbox host key (TOFU)
  backups/<service>/  # local working clones of each service
  job.json            # last/current job status (shared across gunicorn workers)
  job.lock            # flock — one job at a time
```

Every file we create mirrors `user_store._write_atomic`: written atomically,
`chmod` to the right mode, then `chown` to the bind-mount directory's owner so
the root-running container never leaves root-owned files on the host.

### 3.2 On the vulnbox

Backups never create a `.git` inside a service directory (that would expose
source via `/.git/` scraping). Instead a **bare** repo per service lives at
`~/.w4rya-backups/<service>.git` (`/root/...` for root), committed with
`--git-dir`/`--work-tree`.
Recon and preflight run a single piped shell script over SSH
(`ssh … bash -s < remote/<name>.sh`), the same technique as
`scripts/vulnbox/remote_capture.sh`. Scripts emit tab-separated text so the
vulnbox needs no Python.

### 3.3 Config keys (new rows in the existing `app_config` table — not a schema change)

| key | default | meaning |
|---|---|---|
| `vulnbox_ip` | `""` (empty ⇒ derive `10.60.<team_id>.2`) | manual host override |
| `vulnbox_user` | `root` | SSH user |
| `vulnbox_ssh_port` | `22` | SSH port |
| `vulnbox_services_path` | `/root/services` | where service dirs live |

Added to `SCALAR_KEYS` with validators in `app_config.coerce_scalar`
(IP/host, username charset, port range, absolute path). The derivation helper
`vulnbox.config.resolve_host()` reads `vulnbox_ip` else computes from `team_id`;
`team_id` 0 (the unconfigured default) is rejected rather than derived.

## 4. Behavior per card

### 4.1 Key (admin)
- `GET /vulnbox` (any role) → overview `{target, key, jobs, defaults}`; `key` is `{exists, public_key, fingerprint, created_at}` — never the private key.
- `POST /vulnbox/key` → generate ed25519 via `ssh-keygen`; refuses if one exists unless `{rotate:true}` (rotating invalidates the old one). Audited `vulnbox.key_generate` / `vulnbox.key_rotate`.
- `GET /vulnbox/key/private` → `text/plain` attachment download. Audited `vulnbox.key_download`.
- `DELETE /vulnbox/known-host` → forget the pinned host key (box re-provisioned). Audited.

### 4.2 Preflight (operator) — read-only, creates nothing
- `POST /vulnbox/preflight` runs a background job returning a checklist, each item `{ok, detail}`:
  key present · host reachable (TCP connect to ssh port) · SSH auth works · `vulnbox_services_path` exists · `git` present · `docker` present.
- Distinguishes host-unreachable (VPN down) from auth-failure from path-missing, each with a one-line hint.

### 4.3 Recon (operator; import is admin)
- `POST /vulnbox/recon` (background): lists dirs under `vulnbox_services_path`, maps containers→published ports via `docker ps`, flags the 9000–9999 range. Result: `[{service, dir, ports[], image}]`.
- `POST /vulnbox/import-services` (admin): maps recon rows into `/config → services` (name, derived vulnbox ip, port), merged with existing by (ip,port). Audited.

### 4.4 Backup (operator)
- `POST /vulnbox/backup` (background): for each service, ensure the bare repo exists (`git init --bare` on first run = baseline), commit the current tree, then clone/pull into `vulnbox-data/backups/<service>/`. Files over a size cap are skipped and reported. Result per service: `{service, status: created|updated|skipped|error, commit, files, skipped[], detail}`.
- `GET /vulnbox/backup/last` → the last backup job result.

### 4.5 Defaults button (admin)
- `POST /vulnbox/seed-defaults` → writes the ECSC 2026 values into `app_config` (tick 60000, flag_lifetime **5** — w4rya counts the current tick, and a flag is valid in its round + 4 — the official flag regex *unanchored* so it matches inside traffic, start_date 2026-10-15T09:00:00Z). Returns the applied values plus the matching `.env` lines (the assembler reads those at boot). Audited `vulnbox.seed_defaults`. (Reuses `app_config.coerce_scalar` + `set`.)

## 5. Jobs (background, shared across 3 gunicorn workers)

`jobs.py`: a job is a `{id, kind, state: running|done|error, started_at, finished_at, result, error}` record written to `job.json` atomically, guarded by a `job.lock` flock so only one runs at a time. A second request while one runs returns `409 {error, running: <kind>}`. The worker runs the job in a `threading.Thread`; the route returns the job id immediately and the frontend polls `GET /vulnbox/job`. If the holding worker dies, the lock releases, and a `running` record whose lock nobody holds reads as `error: interrupted` — decided exactly by probing the lock, not by a timestamp timeout. The last result of each kind is kept, so one card's job doesn't wipe another's result.

## 6. Security decisions

1. Private key: 0600, download-only, never in a JSON body or on screen (§6.12).
2. Host key pinned on first connect (TOFU) in our own `known_hosts`; SSH runs `BatchMode=yes`, `IdentitiesOnly=yes`, `StrictHostKeyChecking=accept-new`, `ConnectTimeout`. Not `-o StrictHostKeyChecking=no` / `/dev/null` (the pasted script's approach — it accepts any MITM).
3. Service names validated `^[A-Za-z0-9._-]+$` before use in any path/command; all SSH/git args passed as argv lists (`subprocess` without `shell=True`) or `shlex.quote`d inside remote scripts. No string-interpolated shell.
4. Never writes to `authorized_keys`; the organizer key stays.
5. Every mutating route audited via `audit.log`.
6. All new routes behind the existing session + role guards.

## 7. Out of scope (roadmap — documented in the module README, not built)

Baseline diff; our-service SLA monitor from the scoreboard; quiet-window
countdown; game-API ingest (`/api/attack.json`, teams list); official flag
submitter; sharing this key with the capture scripts; restore-from-snapshot
(writes to the vulnbox — needs its own design).

## 8. Testing (offline, same harness as the existing suite)

Unit: key gen/read/fingerprint (ssh-keygen mocked), host derivation, config
validators, recon output parser, service-name rejection, SSH argv construction,
backup result shaping, job lock + stale-interrupted detection. Routes: role
matrix rows (added to `test_routes_roles.py`) + audit calls, 409-on-concurrent,
private-key-never-in-JSON. No DB, no network, no real SSH — subprocess and the
pool are faked, exactly as `conftest.py` sets up.

## 9. Global constraints (verbatim, for the plan)

- No AI/LLM at runtime. Deterministic SSH/git/sockets only.
- No DB schema change; new settings are `app_config` rows.
- No new runtime dependency; `git`/`openssh-client` already in `python:3.10`.
- Do not touch `authorized_keys`; do not render the private key.
- One job at a time, button-triggered, service-by-service (no excessive load).
- Host from `team_id` (`10.60.<id>.2`) unless `vulnbox_ip` overrides.
- Mount `./vulnbox-data` in BOTH compose files (kept in sync, per CLAUDE.md).
- Backend = Blueprint package; frontend = feature folder + `injectEndpoints`.
- Match existing style: `hax-*` classes, `font-mono`, `▎` headers, `useCanRole` gating + read-only banner.

## 10. Changes made during implementation

Each came out of verifying against the real code or tools, not a change of scope:

- `GET /vulnbox/key` became the `GET /vulnbox` overview, a single poll for the whole page.
- `flag_lifetime` is 5, not 4 (w4rya counts the current tick; see `Corrie.tsx`).
- Job liveness is decided by the `flock`, not by a stale-age timeout. That's exact, and a slow job never gets a false "interrupted".
- `team_id` 0 is rejected instead of deriving `10.60.0.2`.
- The fingerprint is computed in-process (the overview is polled), pinned by a test to `ssh-keygen -lf`.
- Local git uses `-c safe.directory=*` (verified: plain git refuses a host-owned bind mount when it runs as root).
- The base `api.ts` is untouched (`enhanceEndpoints({addTagTypes})`).
- `scripts/backup.sh` also saves `vulnbox-data/keys/`.
