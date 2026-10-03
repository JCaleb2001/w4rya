# vulnbox — prepare and defend our own vulnbox

Backend for the `/vulnbox` page. One button per action, nothing scheduled, no
AI at runtime (deterministic `ssh` / `git` / `ssh-keygen` only). Design:
`docs/superpowers/specs/2026-10-03-vulnbox-ops-design.md`.

## Game-day flow (ECSC 2026 timeline)

| when (CEST) | card | what it does |
|---|---|---|
| before 10:30 | **Key** | generate an ed25519 key, paste the public half into the platform (organizers boot the boxes with the submitted keys at 10:30) |
| 10:30–11:00 | **Preflight** | read-only checklist: key → host reachable (VPN) → ssh auth → services path / git / docker |
| 11:00 | **Recon** | services + published ports; import the 9000–9999 ones into `/config → services` |
| 11:00–12:00 | **Backup** | git **baseline** of every service while only our team can reach the box; later clicks add snapshots |

The "ECSC 2026 defaults" button (on the Preflight card) sets tick 60 s,
`flag_lifetime` 5, the flag regex and the start time in `/config`, and returns
the matching `.env` lines — the assembler reads those from `.env` at boot.

## Files

| file | responsibility |
|---|---|
| `config.py` | paths (`W4RYA_VULNBOX_DIR`), limits, validators, `resolve_host`, ECSC values |
| `keys.py` | keypair: generate / rotate / status / forget host key |
| `ssh.py` | argv-only ssh, allow-listed remote scripts, failure → one readable sentence |
| `preflight.py` · `recon.py` · `backup.py` | the three operations; each takes a `config.Target` |
| `jobs.py` | one background job at a time across workers; results kept per kind |
| `routes.py` | the Blueprint: validate → call → audit |
| `remote/*.sh` | piped into `bash -s` on the box; tab-separated output; nothing installed |

Dependencies point one way: `routes → jobs → {preflight, recon, backup} → ssh → keys → config`.

## Data

`./vulnbox-data` on the host (git-ignored), mounted at `/app/vulnbox-data`:
`keys/` (private key 0600, public key, pinned `known_hosts`), `backups/<service>/`
(local clones), `job.json` + `job.lock`. Files are chowned to the directory's
owner, like `auth/` and `suricata-rules/`. On the vulnbox: one bare repo per
service in `~/.w4rya-backups/<service>.git`.

## Security decisions

- **Private key**: written 0600, never in a JSON body, served only as a
  `no-store` attachment (admin, audited). The A/D game is screen-recorded.
- **Host key pinned** (`accept-new` into our own `known_hosts`); never
  `StrictHostKeyChecking=no`. After a legitimate re-provision, "forget host key".
- **No `.git` inside a service directory** — a statically served `.git` leaks
  our source. Backups use `--git-dir`/`--work-tree` against a bare repo.
- **No injection surface**: `subprocess` argv lists only; remote args are
  `shlex.quote`d; service names must match `^[A-Za-z0-9._-]+$` on both sides.
- **Never touches `authorized_keys`** — the organizer key stays.
- **No key, no socket**: without a key no job opens a connection.
- One job at a time, button-triggered only (handbook §6.7.1: no excessive load).

## Troubleshooting

| message | cause | fix |
|---|---|---|
| set your team id in /config | `team_id` unset (0) | set it in `/config`, or set `vulnbox_ip` |
| cannot reach … is the game VPN up? | no route / timeout | bring WireGuard up on the host |
| ssh refused our key | key not submitted, or box booted before it was | submit the public key on the platform; the box must be (re)started with it |
| host key changed | box re-provisioned | "forget host key", retry |
| interrupted — the api restarted | worker died mid-job | run it again |

## Roadmap (not built)

Diff against the baseline · our-service SLA monitor from the scoreboard ·
quiet-window countdown (last 5 s of a round) · game API ingest (attack info,
team list) · official flag submission · share this key with
`scripts/vulnbox_capture.sh` · restore a service from a snapshot (writes to
the box — needs its own design).
