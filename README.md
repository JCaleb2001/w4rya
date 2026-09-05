<img width="1024" height="1024" alt="logo" src="https://github.com/user-attachments/assets/5fa1d042-1b34-48e3-b57a-bce8755b43ec" />

# w4rya

`w4rya` is a hard fork of [Tulip](https://github.com/OpenAttackDefenseTools/tulip) — a network flow analyzer for Attack / Defense CTF competitions — adapted for internal team use.

It captures pcap traffic, ingests it into TimescaleDB, surfaces flows in a React UI, and (optionally) correlates Suricata alerts with the flows for tagging.

## What differs from upstream Tulip

- **One-command install** — `./install.sh` handles the whole setup, including creating your first admin account.
- **Accounts and roles** — session auth with `viewer` / `operator` / `admin` tiers, a first-run wizard, and an admin Users page so each teammate signs in as themselves.
- **Suricata rules from the UI** — create, edit, enable/disable and delete rules at `/rules`, with a quick "block this IP" button on any flow.
- **Runtime config** — services, teams, flag format and tick length are edited at `/config` during the game; no rebuild.
- **Exploit testing** — replay a captured flow against every configured team from the UI, and download a standalone farm script.
- **Attack timeline, per-service stats, flag-leak alarm, per-flow notes, audit log, and a fullscreen war-room view.**

## No-AI policy

**This tool must not call any AI / LLM service at runtime.** The Attack / Defense CTF competitions this fork is built for prohibit the use of AI during the game. All in-tool classification, tagging, and decision-making stays deterministic — regex, Suricata signatures, statistical heuristics, etc. AI is fine for *developing* this tool; it must not be embedded in *running* it.

Pull requests that add LLM API calls, embedded model inference, or AI-driven flow tagging will not be accepted.

## Roadmap

- [x] Basic auth (user/password, bcrypt + session) for team-internal use during CTFs
- [x] Suricata rules CRUD from the UI, with syntax validation and container reload
- [x] One-command installer
- [ ] Loss attribution — link a "lost flag at tick N" scoreboard event to the flow that caused it
- [ ] Replay with per-team tokenized flagids

## Quickstart

```bash
git clone https://github.com/JCaleb2001/w4rya.git
cd w4rya
./install.sh
```

It asks four questions (where your pcaps are, your flag format, the tick length,
and the admin username + password), checks your machine can run the stack,
generates the session secret, builds, starts everything, and prints the URL —
**http://localhost:3001** by default.

The installer is idempotent: re-run it any time to change settings. It will not
overwrite your `.env`, rotate your session secret, or touch existing accounts.

```bash
./install.sh --check      # diagnose an existing install
./scripts/smoke.sh        # verify a running stack over HTTP
./scripts/test.sh         # run the api test suite (no database needed)
```

### Accounts

The installer creates the first account as `admin`. From there, add the rest of
the team at **/users** in the UI — each teammate gets their own login, so when
they connect to your instance they sign in as themselves.

| Role | Can do |
|---|---|
| `viewer` | browse flows, read and write notes |
| `operator` | + Suricata rules, block IPs, star flows, replay exploits |
| `admin` | + `/config`, `/audit`, and user management |

If you ever install without a terminal, the UI shows a first-run wizard instead.
The CLI escape hatch, for a locked-out install or a password reset:

```bash
docker compose run --rm api python /app/auth/add_user.py <name> --role admin
```

### Game configuration

Services, teams, flag format, tick length and the rest are edited at **/config**
in the UI while the game runs — no rebuild.

> One caveat: the Go assembler reads `FLAG_REGEX` and `BPF` from the environment
> at boot, so changing those in the UI reaches the API immediately but not the
> assembler. Run `docker compose restart assembler` after changing them.

## Manual start

If you would rather not use the installer:

```
cp .env.example .env
# set W4RYA_SECRET_KEY (openssl rand -hex 32) — the api refuses to start without it
docker compose up -d --build
```

To ingest traffic, create a shared bind mount with the docker compose. One convenient setup:

1. On the vulnbox, start a rotating packet sniffer (e.g. tcpdump, suricata, …):
```bash
tcpdump -i eth0 -G 180 -w "traffic_%H:%M:%S.pcap" port 8080
```
2. Using rsync, copy complete captures to the machine running w4rya (e.g. to `/traffic`):
```bash
rsync -avz -e ssh --progress root@10.0.0.2:/pcaps ./pcaps
```
3. Add a bind to the assembler service so it can read `/traffic` — just change `TRAFFIC_DIR_HOST` in `.env`.

The ingestor uses inotify to watch for new pcaps and Suricata logs; no cron needed.

> [!IMPORTANT]
> Only files whose **last** extension starts with `.pcap` are ingested. A rotating
> sniffer that produces `traffic.pcap.1779154618` will be **silently ignored** —
> rename to `traffic-1779154618.pcap`. `./install.sh --check` flags these for you.
>
> Capture **both directions**. A filter like `dst host <vulnbox>` yields a
> one-sided capture, and w4rya builds no flows at all from it — you need the
> request and the response. Filter by `port` instead.

## Suricata synchronization

### Run in Docker

Configure `SURICATA_DIR_HOST` in `.env`.

Create some rules (404 for testing):
```bash
. .env
mkdir -p ${SURICATA_DIR_HOST}/{etc,lib/rules,log}
echo 'alert tcp any any -> any any (msg: "404 Not Found"; http.stat_code; content:"404"; metadata: tag notfound; sid:4; rev: 1;)' >> ${SURICATA_DIR_HOST}/lib/rules/suricata.rules
```

Then run (the default `eve.json` logging config is good enough):

```bash
docker compose -f docker-compose-suricata.yml up -d --build
```

### Metadata
Tags are read from the metadata field of a rule. For example, here's a simple rule to detect a path traversal:
```
alert tcp any any -> any any (msg: "Path Traversal-../"; flow:to_server; content: "../"; metadata: tag path_traversal; sid:1; rev: 1;)
```
Once this rule is seen in traffic, the `path_traversal` tag will automatically be added to the filters in w4rya.

> [!NOTE]
>
> After editing Suricata rules (renaming or id change) please:
>
> Remove old logs: `rm ${SURICATA_DIR_HOST}/log/*` (otherwise old signatures will be repopulated).
>
> Restart Docker containers.
>
> If the database was only restarted (not dropped), try cleaning tags / signatures manually.

### eve.json
Suricata alerts are read directly from the `eve.json` file. Because this file can get quite verbose when all extensions are enabled, it is recommended to strip the config down. For example:
```yaml
# ...
  - eve-log:
      enabled: yes
      filetype: regular #regular|syslog|unix_dgram|unix_stream|redis
      filename: eve.json
      pcap-file: false
      community-id: false
      community-id-seed: 0
      types:
        - alert:
            metadata: yes
            # Enable the logging of tagged packets for rules using the
            # "tag" keyword.
            tagged-packets: yes
# ...
```

Sessions with matched alerts are highlighted in the front-end and include which rule was matched.

## Security

Your `w4rya` instance will likely contain sensitive CTF information — flags stolen from your machines, attack payloads, internal IPs. Do not expose it to the internet. Run it on an internal network (e.g. behind a VPN) or behind authentication.

## Contributing

This is an internal team fork. External contributions are not expected, but if you've found a bug or have an improvement that respects the no-AI policy, feel free to open an issue or PR.

## License

GPL-3.0 — inherited from upstream Tulip. See [LICENSE](./LICENSE).

## Based on

This is a hard fork of [Tulip](https://github.com/OpenAttackDefenseTools/tulip), which is itself a fork of [flower](https://github.com/secgroup/flower).

Tulip was written by [@RickdeJager](https://github.com/rickdejager) and [@Bazumo](https://github.com/bazumo), with additional help from [@Sijisu](https://github.com/sijisu). Tulip was developed by Team Europe for use in the first International Cyber Security Challenge. Thanks also to the team behind [flower](https://github.com/secgroup/flower) for open-sourcing their tooling.

All credit for the original architecture, ingestor, and frontend goes to the upstream Tulip authors and contributors listed above. This fork's changes are limited to branding and the roadmap items listed earlier in this README.
