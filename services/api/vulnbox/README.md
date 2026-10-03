# vulnbox — prepare and defend our own vulnbox

Backend for the `/vulnbox` page. It does four things for **our own** vulnbox, one
button each, nothing scheduled:

- generates the SSH key to submit to the A/D platform;
- checks the box is reachable and ready;
- finds the running services and their ports;
- keeps a git baseline and snapshots of the service code.

There is no AI at runtime (deterministic `ssh` / `git` / `ssh-keygen` only). Nothing
here is specific to one A/D game: what differs per game is configuration in
`/config`, and named bundles of it are [presets](#game-presets).

## Requirements

- **The machine running w4rya must be on the game VPN.** The api container reaches
  the vulnbox through the host's network; if the host can't ping the box, neither
  can the module.
- **`./vulnbox-data` exists and is owned by you.** `./install.sh` creates it (mode
  0700). If Docker creates it instead, it comes out root-owned — see
  [Troubleshooting](#troubleshooting).
- **An api image that includes this module.** After pulling, re-run `./install.sh`
  or rebuild the api image.
- **On the vulnbox:** `bash`; `git` for backups; `docker` for recon. Preflight checks
  all three for you.
- **Roles:**

  | role | can |
  |---|---|
  | viewer | see the page |
  | operator | run preflight, recon and backup |
  | admin | manage the key, apply presets, import services into `/config` |

## Setup (once per game)

1. **Point it at the vulnbox.** In `/config → game`, set **our team vm ip** (`vm_ip`)
   to the vulnbox's address.
   > Out of the box this is the `VM_IP` placeholder from `.env`, not a real
   > address. Until you change it, the module happily targets the wrong host.

   If the game differs from the defaults, also set the **ssh user**, **ssh port**,
   **services path** and **service ports**. See [Settings](#settings).
2. **Apply a game preset**, if one exists for this game (`/vulnbox` → Preflight card
   → *game preset* → *apply*). It sets the round length, flag format, start time and
   service ports in one step, and then shows `.env` lines:
   - the assembler reads those settings from `.env` at boot;
   - copy them into `.env` (`./install.sh` asks for the flag regex and the tick
     length; edit `TICK_START` and `FLAG_LIFETIME` by hand);
   - apply them: `docker compose -f <your compose file> up -d` recreates every
     container whose settings changed (the assembler and flagids read them).

   No preset for this game? Set those values in `/config → game` instead, or
   [add a preset](#adding-a-preset).
3. **Create the key** (`/vulnbox` → SSH key card → *generate key*). Copy the public
   key and submit it to the A/D platform **before the vulnbox is provisioned**; a box
   provisioned earlier won't have it.

## During the game

The cards are ordered by the phase of the game they belong to:

| phase | card | what to do |
|---|---|---|
| before the game | **SSH key** | generate the key and submit the public half (setup step 3) |
| once the box is up | **Preflight** | run it. Read-only, in dependency order: key → host reachable (VPN) → ssh login → services path / git / docker. It stops at the first broken link and says why |
| at game start | **Recon** | run it, check the table, then *import into /config* (admin): the service ports become `/config → services` entries (upsert by ip + port; nothing is deleted) |
| before the network opens | **Backup** | run it **while only our team can reach the box** — the first run is the **baseline**, the original code. Run it again after each patch; later runs commit only what changed |

Only one job runs at a time. The buttons are disabled while one runs, and a second
start from elsewhere is refused with "a <kind> job is already running". Each card
keeps its last result.

## Settings

All in `/config → game`, stored in the database:

| setting | default | format / meaning |
|---|---|---|
| our team vm ip (`vm_ip`) | `VM_IP` from `.env` | ip (v4 or v6) or hostname — the ssh target |
| `vulnbox_user` | `root` | ssh user |
| `vulnbox_ssh_port` | `22` | 1–65535 |
| `vulnbox_services_path` | `/root/services` | absolute path; one directory per service under it |
| `vulnbox_service_ports` | empty | the ports other teams reach, e.g. `9000-9999,31337`. Empty = every published port counts as a service port |

## Game presets

A preset is a named bundle of `/config` values for one game, defined in
`presets.py`. Applying one writes its values through the same validation as
`PUT /config`.

### Adding a preset

Add an entry to `PRESETS` in `presets.py`:

```python
Preset(
    id="some-game",               # url-safe, unique
    name="Some Game",             # shown in the picker
    values={
        "tick_length": 120000,
        "flag_lifetime": 6,
        "flag_regex": r"FLAG\{[a-f0-9]{32}\}",
        "start_date": "2000-01-01T10:00:00Z",
        "vulnbox_service_ports": "8000-8999",
    },
),
```

| key | unit / rule |
|---|---|
| `tick_length` | round length in **milliseconds** |
| `flag_lifetime` | rounds a flag stays valid, **counting the round it was placed in** — a flag valid for N rounds after its own round needs N + 1 |
| `flag_regex` | the game's flag format **without** `^`/`$`: w4rya searches for flags *inside* traffic |
| `start_date` | game start, ISO-8601 in **UTC** (tick 0) |
| `vulnbox_service_ports` | port ranges, as in [Settings](#settings) |

Any other `/config → game` key may appear too. `tests/vulnbox/test_presets.py` runs
every entry through the `/config` validation, so a bad value fails the test suite
rather than the operator mid-game.

## Using the key outside w4rya

An admin can download the private key from the SSH key card (*↓ private key*). It is
never shown on screen. To log in by hand:

```sh
chmod 600 w4rya_vulnbox_ed25519
ssh -i w4rya_vulnbox_ed25519 <vulnbox_user>@<vm_ip>
```

Notes:
- **Rotating** replaces the key here right away. w4rya can't log in again until the
  platform installs the new public key on the box.
- The old public key stays authorized on the box, because the module never touches
  `authorized_keys`. So anyone holding the old private key keeps access until it is
  removed there.
- `scripts/backup.sh` saves `vulnbox-data/keys/` with the rest of w4rya's state.

## Working with the backups

Local clones live in `./vulnbox-data/backups/<service>/`, and the first commit is
the baseline. To read them:

```sh
git -C vulnbox-data/backups/<service> log --oneline         # snapshots, oldest = baseline
git -C vulnbox-data/backups/<service> diff <baseline>..HEAD  # everything changed since the baseline
```

On the vulnbox, every service has a bare repo in `~/.w4rya-backups/<service>.git`.
To see what changed since the last snapshot:

```sh
git --git-dir ~/.w4rya-backups/<service>.git --work-tree <services_path>/<service> status
git --git-dir ~/.w4rya-backups/<service>.git --work-tree <services_path>/<service> diff
```

To put a file back as it was in a snapshot (for example, to undo a patch that broke
the service):

```sh
git --git-dir ~/.w4rya-backups/<service>.git --work-tree <services_path>/<service> \
    checkout <commit> -- <path/in/service>
```

That overwrites the file on the box. Restart the service afterwards, at a moment
when the checker isn't running if the game has one.

Files larger than 25 MiB are left out of backups. The Backup card shows them as
"+N skipped", with the list on hover.

## Troubleshooting

| message | cause | fix |
|---|---|---|
| set our team's vulnbox address (vm_ip) | `vm_ip` empty | set it in `/config → game` |
| cannot reach `<ip>`:`<port>` — is the game VPN up? | VPN down on the host, wrong `vm_ip` (still the placeholder?) or wrong port | bring the VPN up; check `vm_ip` / `vulnbox_ssh_port` |
| ssh refused our key | key not submitted, or the box was provisioned before it was | submit the public key on the platform; the box must be (re)provisioned with it |
| host key changed | the box was re-provisioned | SSH key card → *forget host key*, then retry |
| vulnbox data dir unavailable | `./vulnbox-data` missing, root-owned or read-only | `mkdir -m 700 vulnbox-data` (or `sudo chown -R $USER:$USER vulnbox-data`), then recreate the api container |
| recon found no published service port | `vulnbox_service_ports` excludes every published port | widen it, or empty it to count every port |
| git is not installed on the vulnbox | backups need git on the box | install `git` on the vulnbox |
| docker ps failed / docker is not installed | recon can't map ports | start or install docker; directories are still listed |
| interrupted — the api restarted | the api worker died mid-job | run it again |

## How it works

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

**Data:** `./vulnbox-data` on the host (git-ignored) is mounted at
`/app/vulnbox-data`. It holds:
- `keys/`: the private key (0600), the public key and the pinned `known_hosts`;
- `backups/<service>/`: the local clones;
- `job.json` and `job.lock`.

Files are chowned to the directory's owner, like `auth/` and `suricata-rules/`.

## Security decisions

- **Private key**: written 0600, never in a JSON body, served only as a `no-store`
  attachment (admin, audited). A/D games may record or share players' screens.
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

## Roadmap (not built)

- a diff against the baseline in the UI;
- an SLA monitor for our own services, from the scoreboard;
- a countdown to a checker-free window, for games that have one;
- game API ingest (attack info, team list);
- flag submission;
- sharing this key with `scripts/vulnbox_capture.sh`;
- one-click restore from a snapshot. It writes to the box, so it needs its own
  design; [Working with the backups](#working-with-the-backups) covers it by hand.
