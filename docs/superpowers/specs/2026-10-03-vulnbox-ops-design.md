# Vulnbox ops module — design

- **Status:** implemented (this document describes the module as built)
- **Code:** `services/api/vulnbox/` (backend) · `frontend/src/features/vulnbox/` (frontend)

## 1. Goal

Give the team one place in w4rya — the `/vulnbox` page — to get **our own
vulnbox** ready and protected for an Attack/Defense game:

- generate the SSH key to submit to the A/D platform;
- verify the box is reachable;
- discover the running services and import them into `/config`;
- take a git **baseline**, then snapshots, of the service code.

There is one button per action and nothing is scheduled.

This is preparation and defense tooling for *our* box. It never touches another
team's host, and it runs no AI at runtime (CLAUDE.md hard constraint).

The module is **game-agnostic**. Whatever differs between games is a `/config`
setting, and a named bundle of settings for one game is a **preset**: data, not
code (§4.5).

## 2. Assumptions about the game

These hold for typical A/D games. Anything a specific game does differently is a
setting.

| Assumption | How the module handles it |
|---|---|
| Each team gets a vulnbox. We know its address. | `vm_ip` in `/config` is the ssh target. |
| Access is by ssh with a key the A/D platform installs. | Generate a keypair and show the **public** half to submit. Never touch `authorized_keys`. |
| The box is reachable only over the game VPN. | Preflight distinguishes "VPN/host down" from "ssh refused our key". |
| Services run as docker compose projects, one directory per service. | Recon ties containers to directories through compose's `working_dir` label. |
| Only some published ports are game services; the rest are our tooling. | `vulnbox_service_ports` ranges (empty = every published port). |
| Round length, flag format, flag validity and start time differ per game. | Presets (§4.5). |
| Players' screens may be recorded or shared. | The **private** key is only ever downloaded as a file, never rendered. |
| Game rules commonly forbid excessive load on the infrastructure. | One job at a time, by button only, service by service, with size caps. |
| There is a window before other teams can reach the box. | The first backup is the baseline: the original code. |

## 3. Architecture

It follows the existing w4rya patterns. It adds no new runtime dependency, no DB
schema change and no new container.

- **Backend:** a self-contained package `services/api/vulnbox/` exposing a Flask
  **Blueprint** (`bp`). `webservice.py` registers it with one line. This is the first
  Blueprint in the API, and it is documented in CLAUDE.md as the convention for new
  feature modules. The app-wide `before_request` auth guard already covers Blueprint
  routes, so auth and roles work unchanged.
- **Frontend:** a feature folder `frontend/src/features/vulnbox/`. Its endpoints are
  added to the single shared `w4ryaApi` slice via `injectEndpoints` (RTK Query
  code-splitting), not a second API. The feature declares its own `"Vulnbox"` tag via
  `enhanceEndpoints({addTagTypes})`, so the base `api.ts` needs no new endpoints or
  tags.
- **Dependency direction (one way):**
  `routes → jobs → {preflight, recon, backup} → ssh → keys → config`. `config.py` holds
  the paths, timeouts and validators used by all of them; `presets.py` holds game data.

### 3.1 Data on disk

A single git-ignored host directory, bind-mounted into the api container at
`/app/vulnbox-data` (the same bind-mount style as `./auth` and `./suricata-rules`):

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

Every file we create follows `user_store._write_atomic`: written atomically and
`chmod`ed to the right mode. One helper, `config.own()`, then hands it to the data
directory's owner, and the same goes for the directories `ensure_dir` creates and for
the backup clones. That way the root-running container never leaves root-owned files
on the host.

### 3.2 On the vulnbox

Backups never create a `.git` inside a service directory, because a statically
served `.git` leaks source. Instead, a **bare** repo per service lives at
`~/.w4rya-backups/<service>.git` and is committed with `--git-dir`/`--work-tree`.

Preflight, recon and backup each pipe one shell script over ssh
(`ssh … bash -s < remote/<name>.sh`), the same technique as
`scripts/vulnbox/remote_capture.sh`. The scripts emit tab-separated text, so the
vulnbox needs no Python.

### 3.3 Settings (`app_config` rows — not a schema change)

| key | default | meaning |
|---|---|---|
| `vm_ip` (existing) | — | our vulnbox's address: the ssh target |
| `vulnbox_user` | `root` | SSH user |
| `vulnbox_ssh_port` | `22` | SSH port |
| `vulnbox_services_path` | `/root/services` | where the service directories live |
| `vulnbox_service_ports` | `""` | game-service port ranges, e.g. `9000-9999,31337`; empty = all |

The new keys are added to `SCALAR_KEYS`, with write-time validators in
`app_config.coerce_scalar`. If `vm_ip` is unset or invalid, the routes answer 400 with
the fix.

## 4. Behavior per card

### 4.1 Key (admin)

- `GET /vulnbox` (any role) returns the overview `{target, key, jobs, presets}`. Its
  `key` field is `{exists, public_key, fingerprint, created_at}`, never the private
  key.
- `POST /vulnbox/key` generates an ed25519 key with `ssh-keygen`. It refuses if a key
  already exists, unless the body is `{rotate:true}`; rotating invalidates the old
  key. Audited.
- `GET /vulnbox/key/private` downloads the key as a `no-store` attachment. Audited.
- `DELETE /vulnbox/known-host` forgets the pinned host key, for when the box is
  re-provisioned. Audited.

### 4.2 Preflight (operator) — read-only, creates nothing

`POST /vulnbox/preflight` runs a background job that returns a checklist. Each item
is `{name, status: ok|fail|skipped, detail}`:

1. key present
2. host reachable (TCP connect to the ssh port)
3. ssh login works
4. `vulnbox_services_path` exists
5. `git` is present
6. `docker` is present

The run stops at the first broken link, and every later check is reported as
skipped.

### 4.3 Recon (operator; import is admin)

- `POST /vulnbox/recon` (background) lists the directories under
  `vulnbox_services_path` and maps containers to their published ports. Each result
  row is `{name, ports, service_ports, containers}`.
- `POST /vulnbox/import-services` (admin) adds the service ports to
  `/config → services`, one entry per port. It is add-only by (ip, port): an address
  already there keeps its hand-edited name and notes, and nothing is deleted. Names
  stay unique (`<service>/<port>` for a multi-port service, then `-2`, `-3`…), because
  the `/query` services filter looks entries up by name. The target must be an ip,
  because that filter matches flows by ip. Audited; responds
  `{services, added, kept}`.

### 4.4 Backup (operator)

`POST /vulnbox/backup` (background) handles each service in turn:

1. Ensure the bare repo exists. Creating it on the first run makes that run the
   baseline.
2. Commit the current tree: every file, including those the service's own
   `.gitignore` hides. Files over the size cap and nested git checkouts are left out
   and reported, with the reason.
3. Clone or fast-forward pull into `vulnbox-data/backups/<service>/`, until the clone's
   HEAD is the box's commit.

Each result row is `{name, status: created|updated|unchanged|error, commit, files,
skipped: [{path, bytes, reason}], local}`, where `commit` is the full hash.

### 4.5 Game presets (admin)

`presets.py` holds `Preset(id, name, values)` entries: the `/config` values one game
needs (round length, flag format, flag lifetime, start time, service ports).

`POST /vulnbox/presets/<id>` writes a preset's values through the same
`coerce_scalar` validation as `PUT /config`. It returns the applied values plus the
matching `.env` lines (`ASSEMBLER_ENV`), because the assembler reads some of these
settings from `.env` at boot. Audited.

Supporting another game means adding one entry. A test validates every entry, so a
preset can never hold a value `/config` would reject.

## 5. Jobs (background, shared across gunicorn workers)

- **Record:** `jobs.py` writes `{id, kind, state: running|done|error, started_by,
  started_at, finished_at, result, error}` to `job.json` atomically.
- **One at a time:** a `job.lock` flock, held for the whole job, enforces it. A second
  request gets `409 {error, running: <kind>}`.
- **Background run:** the job runs in a daemon thread. The route returns at once and
  the page polls `GET /vulnbox`.
- **Dead workers:** if the holding worker dies, the lock is released, and a `running`
  record whose lock nobody holds reads as interrupted. This is decided by probing the
  lock, not by timestamps.
- **Per-kind results:** the last result of each kind is kept.

## 6. Security decisions

1. The private key is 0600, download-only, and never in a JSON body or on screen.
2. The host key is pinned on first connect (TOFU) in our own `known_hosts`. ssh runs
   with `BatchMode`, `IdentitiesOnly`, `StrictHostKeyChecking=accept-new` and
   `ConnectTimeout` — never `StrictHostKeyChecking=no`.
3. Service names are validated against `^[A-Za-z0-9._-]+$` before use in any path or
   command. SSH/git args are argv lists (no `shell=True`), and remote args are
   `shlex.quote`d. ssh ends its options with `--`, and an ssh user or hostname can't
   start with `-` or `.`, so neither can be read as an option.
4. `authorized_keys` is never written; keys the organizers installed stay.
5. Every mutating route is audited, and every route sits behind the existing session
   and role guards.
6. No key means no socket: without a key, no job opens a connection.

## 7. Out of scope (roadmap)

Not built; tracked in the module README:

- a diff against the baseline;
- an SLA monitor for our own services;
- a countdown to a checker-free window, for games that have one;
- ingesting the game API (attack info, team list);
- flag submission;
- sharing this key with the capture scripts;
- restoring a service from a snapshot (it writes to the vulnbox, so it needs its own
  design).

## 8. Testing (offline, same harness as the existing suite)

- **Units:**
  - config validators and port ranges;
  - presets (every entry validated);
  - keys, including the fingerprint checked against the real `ssh-keygen`;
  - ssh argv and quoting;
  - preflight, recon and backup, running the real remote scripts with bash and a
    real local git clone (only the ssh hop is faked);
  - jobs (lock, interrupted).
- **Routes:**
  - role-matrix rows;
  - audit calls;
  - 409 on concurrent jobs;
  - the private key never appears in JSON;
  - a test-only preset.
- **Fixtures:** test data uses RFC 5737 documentation addresses.

## 9. Constraints

- No AI/LLM at runtime. Deterministic SSH/git/sockets only.
- No DB schema change; new settings are `app_config` rows.
- No new runtime dependency; `git`/`openssh-client` ship in `python:3.10`.
- Do not touch `authorized_keys`; do not render the private key.
- One job at a time, button-triggered, service by service.
- Game-agnostic code: anything specific to one game is a setting or a preset entry.
- Mount `./vulnbox-data` in BOTH compose files (kept in sync, per CLAUDE.md).
- Backend = Blueprint package; frontend = feature folder + `injectEndpoints`.
- Match the existing style: `hax-*` classes, `font-mono`, `▎` headers, `useCanRole`
  gating plus the read-only banner.

## 10. Decisions made during implementation

Each one came out of checking against the real code or tools:

- **One overview endpoint.** `GET /vulnbox` is the only read endpoint: one poll for
  the whole page.
- **Liveness from the lock.** Job liveness is decided by the `flock`, not by a timeout,
  so a slow job never reads as falsely interrupted.
- **Fingerprint in-process.** The fingerprint is computed in Python because the
  overview is polled. A test pins it to `ssh-keygen -lf`.
- **`safe.directory` on the command line.** Local git uses `-c safe.directory=*`;
  without it, git running as root refuses a host-owned bind mount.
- **Settings editable in `/config`.** `GameConfig` gains the optional `vulnbox_*`
  fields so the Config page can edit them.
- **Clear 503 for an unusable data dir.** Jobs and key generation answer 503 with a
  message when `./vulnbox-data` is missing or read-only.
- **Backups save the key.** `scripts/backup.sh` also saves `vulnbox-data/keys/`.
- **What a snapshot holds.** `add -f` plus `:(exclude,literal)` pathspecs for the files
  over the cap and for nested checkouts, which are also unstaged in case an earlier
  snapshot holds them. `info/exclude` was dropped: it never applies to tracked files,
  so a file that grew past the cap kept being committed in full.
- **The mirror compares HEADs.** It pulls whenever its HEAD differs from the box's
  commit, so a pull that failed once is retried. It re-points `origin` at the current
  target first, and clones into a temporary directory that is renamed into place.
- **A longer limit for backups.** `BACKUP_TIMEOUT` (15 min) for the remote script and
  for git; quick checks keep `RUN_TIMEOUT` (2 min).
- **Remote scripts end with `exit 0`.** Records carry the outcome; a non-zero exit
  means the ssh hop failed.
- **No placeholder `vm_ip`.** `VM_IP` is empty in `.env.example` and the default is
  `""`, so an unset address reads as unset.
- **Imported services are read fresh.** The import reads `services` with
  `app_config.get_fresh`, so it never writes back another worker's stale copy.
- **Game-agnostic by construction:**
  - the ssh target is the existing `vm_ip` (no host derivation);
  - service ports are a setting;
  - per-game values are presets;
  - the UI names game phases, not clock times;
  - IPv6 hosts are bracketed in git's scp-style URL.
