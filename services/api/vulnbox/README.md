# vulnbox — prepare and defend our own vulnbox

Backend for the `/vulnbox` page. One button per action, nothing scheduled, no
AI at runtime (deterministic `ssh` / `git` / `ssh-keygen` only). Nothing here
is specific to one A/D game: what differs per game is configuration in
`/config`, and named bundles of it are presets (see below).

## Flow

The page orders the cards by the phase of a game they belong to:

| phase | card | what it does |
|---|---|---|
| before the game | **Key** | generate an ed25519 key; submit the public half to the A/D platform, which provisions the vulnbox with it |
| once the box is up | **Preflight** | read-only checklist: key → host reachable (VPN) → ssh login → services path / git / docker |
| at game start | **Recon** | services + their published ports; import the service ports into `/config → services` |
| before the network opens | **Backup** | git **baseline** of every service while only our team can reach the box; later runs add snapshots |

## Settings (`/config → game`)

| key | meaning |
|---|---|
| `vm_ip` | our vulnbox's address — the ssh target |
| `vulnbox_user` | ssh user (default `root`) |
| `vulnbox_ssh_port` | ssh port (default `22`) |
| `vulnbox_services_path` | where the service directories live (default `/root/services`) |
| `vulnbox_service_ports` | which published ports are game services, e.g. `9000-9999,31337`; empty = every published port |

## Game presets

`presets.py` holds named bundles of `/config` values for one game (round
length, flag format, start time, service ports, ...). Applying one (admin, on
the Preflight card) writes its values and returns the matching `.env` lines,
because the assembler reads some of those settings from `.env` at boot.

To support another game, add an entry:

```python
Preset(
    id="some-game",          # url-safe, unique
    name="Some Game",
    values={"tick_length": 120000, "flag_regex": r"FLAG\{[a-f0-9]{32}\}", ...},
),
```

`tests/vulnbox/test_presets.py` checks every entry against the same
write-time validation as `PUT /config`, so a bad value fails the test suite,
not the operator mid-game.

## Files

| file | responsibility |
|---|---|
| `config.py` | paths (`W4RYA_VULNBOX_DIR`), limits, validators, `resolve_host`, port ranges |
| `presets.py` | game presets (data) and the `/config` → `.env` name map |
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
  `no-store` attachment (admin, audited). A/D games may record or share
  players' screens.
- **Host key pinned** (`accept-new` into our own `known_hosts`); never
  `StrictHostKeyChecking=no`. After a legitimate re-provision, "forget host key".
- **No `.git` inside a service directory** — a statically served `.git` leaks
  our source. Backups use `--git-dir`/`--work-tree` against a bare repo.
- **No injection surface**: `subprocess` argv lists only; remote args are
  `shlex.quote`d; service names must match `^[A-Za-z0-9._-]+$` on both sides.
- **Never touches `authorized_keys`** — keys the organizers installed stay.
- **No key, no socket**: without a key no job opens a connection.
- **One job at a time, button-triggered only** — game rules commonly forbid
  putting excessive load on the infrastructure.

## Troubleshooting

| message | cause | fix |
|---|---|---|
| set our team's vulnbox address (vm_ip) | `vm_ip` unset | set it in `/config` |
| cannot reach … is the game VPN up? | no route / timeout | bring the game VPN up on the host |
| ssh refused our key | key not submitted, or the box was provisioned before it was | submit the public key on the platform; the box must be (re)provisioned with it |
| host key changed | box re-provisioned | "forget host key", retry |
| interrupted — the api restarted | worker died mid-job | run it again |

## Roadmap (not built)

Diff against the baseline · our-service SLA monitor from the scoreboard ·
countdown to a checker-free window, for games that have one · game API ingest
(attack info, team list) · flag submission · share this key with
`scripts/vulnbox_capture.sh` · restore a service from a snapshot (writes to the
box — needs its own design).
