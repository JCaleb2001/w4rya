# Changelog

Notable changes per release. Format follows [Keep a Changelog](https://keepachangelog.com/);
versions follow [semver](https://semver.org/), where "breaking" means an operator has to
change `.env`, the schema, or a script invocation.

Releases before 0.7.0 predate this file — see `git log` and the release tags.

## [0.8.0] — 2026-09-17

Exploit isolation, incident packets, and the exploit-intel workflow — turning
a matched Suricata rule into exactly the request that fired it, a report the
patching team can act on, and a replayable proof of exploitation.

### Added

- **Buffer-scoped exploit isolation.** "Copy Exploit" used to hand back the
  whole client+server session behind a `flow_id` (up to ~93 KB for a
  multi-request session), most of it irrelevant to the rule that actually
  fired. `attack.find_exploit_item()` re-checks the firing rule's own content
  clauses against each client item, respecting Suricata's buffer scoping
  (`http.uri` / `http_client_body` / `http_cookie` / ...) instead of a naive
  whole-item substring match. Returns a single matching item, a short list of
  genuinely distinct matches (a two-stage attack, e.g. MSSQL's "enable
  xp_cmdshell" then "run xp_cmdshell"), or the full flow when it can't be
  narrowed — with duplicate/near-duplicate matches (a scanner retrying the
  same template) collapsed to one representative.
- **Incident Packet** (`GET /attack/incident/<flow_id>`): tells the patching
  team the exact endpoint, query param / body field / header, and MITRE
  ATT&CK technique/tactic/severity/remediation for a matched flow, instead of
  a raw byte dump.
- **Saved exploit library** (`services/api/exploits.py`, `/exploits`): save a
  flow's isolated payload, replay it later against any ad-hoc IP:port, edit
  the payload/port before replaying.
- **Checker IP detection** (`services/api/checker_detect.py`,
  `/checker/candidates`): ranks IPs by how checker-like their traffic looks
  (regularity, coverage, clean rate) so an operator can confirm the checker's
  own SLA traffic before it's mistaken for an attacker's — confirmed IPs feed
  both the attack timeline exclusion and the flow-list noise filter.
- **Recursive payload decoder** (`services/api/decode.py`): base64 / hex /
  url / gzip / deflate, nested, shown in a new decoded-payloads panel.
- **Kill Chain view**: a tick-windowed view of attacker activity across the
  game, plus live toasts when a new attack fires.
- **`pcap_name` flow-query filter**: bypasses the tick/time window — useful
  for a historical/test pcap whose capture timestamp is outside the game's
  tick-0 anchor.
- ~13 new Suricata rule templates, plus ET Open ruleset scaffolding and
  refresh docs (`suricata-rules/README.md`).

### Changed

- **`reload_rules()` no longer blocks a gunicorn worker for the full ~20s ET
  Open reload on every rule save.** The high-frequency auto-reload path
  (`_maybe_autoreload`, fired on rule CRUD) now takes the reload lock
  non-blocking and returns `PENDING` immediately if another worker already
  has it; the manual "reload now" button keeps the old blocking wait, since
  that's a deliberate, infrequent, user-initiated action. Coalescing compares
  the rules file's mtime instead of wall-clock arrival order, so an edit
  written just before another reload completes can't be silently absorbed
  into a reload that predates it.
- **`hide_noise` also excludes confirmed `checker_ips`**, not just the
  separate `noise_ips` field — confirming a checker in the Checker tab is
  enough, no need to also type the same IP into the noise-ips config.
- "Copy Exploit"'s isolation caption now reports position among client items
  only, not raw position in the interleaved client+server array.

### Fixed

- The buffer-scope lookahead stopped at the first unrecognized token, so a
  rule written `content:"..."; nocase; http_uri;` (a common ET ordering)
  never got scoped to the URI and silently fell back to whole-item substring
  matching — reintroducing the false-positive isolation this release's whole
  buffer-scoping mechanism exists to fix. Now skips safe bare modifiers
  (`nocase`, etc.) to keep looking for the buffer keyword.
- A malformed `|hex|` run in a rule's content clause crashed
  `/attack/incident` and `/attack/exploit-code` with an uncaught
  `ValueError` instead of degrading to `basis=full_flow`.
- `attack_timeline` excluded checker IPs in Python *after* the SQL
  `LIMIT`, so a busy checker could push real attacker events out of the
  already-limited result set. Excluded in SQL, before `LIMIT`, now.
- `locate_vulnerable_input` decoded a rule's content pattern as latin-1 but
  the URI/body/cookie haystack as utf-8 — the same multi-byte sequence could
  decode to two different strings, silently missing the real vulnerable
  field on non-ASCII payloads.
- `_MAX_MATCHED_ITEMS` collapsed *any* set of more than 5 distinct matches to
  one representative, the same code path used for actual scanner-retry
  noise — a real 6+-stage attack chain lost 5+ of its real steps with no
  signal that it happened for "too many matches" rather than "duplicates".
- `GET /flow/<id>/decode` 500'd on a malformed flow id instead of returning
  400 like every other flow-id route.
- `AttackAlertWatcher` could double-toast the same alert if it appeared
  twice within one poll window.
- `SendExploitControls`' target picker could silently re-select every
  configured team right after an operator explicitly deselected all of them,
  if the teams list happened to refetch in between.
- Suricata's real reload timeout (1.5s) was far under the ~8.5s a reload
  against the full ~40k-rule ET Open set actually takes, so "reload now" and
  auto-reload-on-save always reported "failed" even though the reload had
  completed — raised to 20s. A Windows Docker Desktop bind-mount issue that
  silently kept the Suricata command socket from ever appearing is fixed
  with a named volume shared between the api and suricata containers.
- The recursive decoder's gzip/deflate step had no output size limit — a
  small, highly-compressible blob in captured traffic (a decompression bomb)
  could force unbounded memory/CPU. Capped at 8 MiB.
- SSH command construction in the vulnbox capture/pull scripts is now safely
  quoted end to end (`printf %q`), closing a command-injection-adjacent gap
  if a `.env` value contained a single quote.

### Security

- Exploit replay (`/attack/replay`, `/exploits/<id>/replay`) does not
  restrict target IPs to exclude loopback/RFC1918/link-local ranges — this
  is intentional, the tool has to be able to target arbitrary hosts on the
  CTF network, but it means any `operator`-role account can use it to reach
  internal infrastructure (other containers, the api itself). Not currently
  restricted; noted here rather than fixed silently.

## [0.7.0] — 2026-09-08

Ingest reliability, an answer to "why am I not seeing traffic", and a rule set
that is useful before the game rather than after it.

### Added

- **Ready-made Suricata rule packs** (`services/api/rulepacks.py`). 39 rules in five
  packs — `web-injection`, `web-rce`, `web-traversal`, `recon`, `exfil` — covering the
  well-known web attack shapes. Every rule carries `metadata: tag <x>`, so alerts land as
  flow tags and become filter chips on their own. Install from `/rules` → **rule packs**,
  or `POST /rules/packs/<id>` (operator). Idempotent: every rule pins a sid in a reserved
  2,1xx,xxx block, so installing twice adds nothing. All rules are `alert`, never `drop`.
- **`GET /pipeline/health`** — one call that says whether traffic is actually reaching the
  flow table, and which half of the pipeline to look at when it isn't (`lagging` = the
  vulnbox, `stalled` = the assembler). Shown in the war room as an ingest-lag counter,
  plus a banner that only appears when something is wrong.
- **`hide_noise` on `POST /query`** and a matching sidebar toggle: drops the checker and
  our own tooling, resolved server-side from the new `noise_ips` config key. Excluded in
  SQL, so the row limit is spent on real traffic.
- **Capture volume check** in `install.sh --check`: captured MB against free GB where the
  pcaps actually live. Warns under 10 GB, fails under 2.
- **Vulnbox capture pipeline** (`scripts/vulnbox_capture.sh`, `scripts/pull_vulnbox_pcaps.sh`)
  and two operator scripts (`scripts/show_attacker_flows.sh`, and the now-deprecated
  Windows assembler watchdog).

### Changed

- **The assembler rescans its watch dir** on an interval (`WATCH_POLL_INTERVAL`, default
  `10s`) instead of trusting fsnotify alone. Docker Desktop's Windows bind mounts drop
  inotify events, so the assembler could sit idle for a whole game while pcaps piled up.
  Re-offering a file is cheap and safe: already-ingested packets are skipped by position.
- **`install.sh` knows about the bind interface**, upserts `W4RYA_BIND_IP`, and its final
  summary prints an `ssh -L` line instead of a LAN URL that cannot work under loopback.
  `--check` asks Docker what the port is really bound to rather than trusting `.env`.
- **The UI version string comes from `package.json`** via a build-time define. It was
  hardcoded in `Login.tsx`, which is how the UI showed v0.3.0 while the repo was on 0.6.1.

### Fixed

- **The UI is bound to `127.0.0.1` by default.** Both compose files published
  `${W4RYA_UI_PORT}:3000` with no interface prefix, so Docker bound `0.0.0.0` — and since
  the frontend proxies `/api`, that published the entire API to whatever network the host
  was on, which during a game is the network every other team is on. Set `W4RYA_BIND_IP`
  to expose it deliberately.
  **Action required:** existing installs stay on `0.0.0.0` until the frontend container is
  recreated (`docker compose up -d frontend`).
- The vulnbox and operator scripts are marked executable; they had been committed `100644`
  from Windows, which made them `Permission denied` on a Linux clone.
- `flow_item` query results are ordered chronologically.

### Deprecated

- `scripts/windows_assembler_watchdog.sh` — superseded by the assembler's own rescan. It
  restarted the container every 120s, which also discarded whatever was mid-assembly.
