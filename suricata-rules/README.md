# Detection stack — how it's built, how to extend it

This documents the Suricata detection work layered on top of w4rya for
Team Costa Rica's A/D play: custom rules, the ET Open integration, tuning,
and how it was validated. See `CLAUDE.md` (repo root) for how the rules
pipeline plugs into the API/UI — this file is about the rules themselves.

## File layout

| File | Managed by | Purpose |
|---|---|---|
| `suricata-rules/suricata.rules` | `/rules` UI (via `services/api/rules.py`) | Our own rules: service-specific IDOR/leak detectors + the exploit-technique and brute-force rules below. Sids `1000000+`. |
| `suricata-rules/et-open/suricata.rules` | `suricata-update` (not the UI) | Emerging Threats Open ruleset, merged output. Sids in ET's own `2xxxxxx` range — no collision with ours. |
| `suricata-rules/et-open-disable.conf` | hand-edited | Tuning filters applied on every ET Open refresh (see below). |
| `suricata/etc/suricata.yaml` | hand-edited | `rule-files:` lists both files above. Suricata loads them as one merged signature set at startup. |

The UI only shows/edits `suricata.rules` — ET Open stays invisible to the
`/rules` page by design, so 40k+ community signatures don't swamp the
custom-rule list operators actually work with day-to-day.

## Custom rules (`suricata.rules`)

Exploit-technique signatures, all validated against real payload bytes from
a 133-pcap real-world exploit collection (see "How this was tested"):

| sid | Detects |
|---|---|
| 1000009 | Log4Shell (`${jndi:ldap/rmi/dns/...}` in URI, incl. one layer of %-encoding) |
| 1000010 | ThinkPHP 5 `invokefunction` RCE |
| 1000011 | WebLogic CVE-2020-14882/14883 console traversal |
| 1000012 | Fastjson autoType RCE (`JdbcRowSetImpl` gadget) |
| 1000013 | Tomcat CVE-2017-12615 (PUT + trailing-slash JSP upload bypass) |
| 1000014 | Apache Shiro CVE-2016-4437 (`rememberMe=deleteMe` cookie-reset tell) |
| 1000015 | SQLi via error/blind functions (`extractvalue`/`updatexml`/`benchmark`) |
| 1000016 | SQLi → webshell via `INTO OUTFILE`/`DUMPFILE` |
| 1000017 | XXL-Job `glueSource` reverse-shell payload |
| 1000018 | MSSQL `xp_cmdshell` over raw TDS (UTF-16LE-encoded match) |
| 1000019 | Nacos unauthenticated `/nacos/v1/cs/ops/data/removal` |
| 1000020–1000032 | Generic brute-force (SSH/FTP/Telnet/SMB×2/MSSQL/MySQL/Postgres/Oracle/Redis/MongoDB/RDP) + NetBIOS name-service scan — all `threshold`-based on repeated SYNs (or queries) from one source, not tool-specific content, so they catch any tool hitting that port, not just the one that happened to get tested |

Two rules had to be fixed after the first pass **because the real byte-level
match failed even though the logic looked right on paper** — worth knowing
before writing the next one:
- A `pcre` after an old-style `content:"x"; http_uri;` modifier does **not**
  inherit that buffer — it silently falls back to the raw packet. Always
  append `/U` (or use the new dot-style sticky buffer, which *does*
  persist across a following bare `pcre`) — this bit both the Log4Shell and
  WebLogic rules on the first pass.
- Suricata's libhtp only undoes **one layer** of `%`-encoding in the
  normalized `http_uri` buffer. A double-encoded payload (`%252e` →
  WebLogic's traversal bypass) shows up as `%2e` in the buffer Suricata
  actually matches against, not as a literal `.`.
- `http.request_body` content doesn't get form-urlencoding decoded either —
  `extractvalue(` in a URL-encoded POST body arrives as `extractvalue%28`.
  Drop the trailing-char requirement rather than guess at encoding state.

sid 1000004 is intentionally disabled (`#`-prefixed) — an earlier "shell
metachars in body" rule false-positived on ordinary binary file uploads.
Left as a documented dead end rather than deleted.

## ET Open integration

Pulled via `suricata-update` (ships inside `jasonish/suricata:7.0`, no
separate install needed):

```
# one-time / whenever refreshing the feed:
docker run --rm \
  -v "$(pwd)/suricata/etc:/etc/suricata:ro" \
  -v "$(pwd)/suricata/update-data:/var/lib/suricata" \
  -v "$(pwd)/suricata-rules/et-open:/etout" \
  -v "$(pwd)/suricata-rules:/rulesdir:ro" \
  --entrypoint /bin/sh jasonish/suricata:7.0 -c \
  "suricata-update update-sources && suricata-update enable-source et/open && \
   suricata-update -o /etout --no-test -f --disable-conf /rulesdir/et-open-disable.conf"

docker compose -f docker-compose-suricata.yml restart suricata
```

ET Open updates roughly daily upstream; re-run the above to pick up new
signatures (`--offline` skips the network fetch and reuses the cached
tarball in `suricata/update-data/update/cache/` if you just want to
re-apply filter changes).

### Tuning (`et-open-disable.conf`)

Raw ET Open is ~68.6k rules / 52.6k enabled. Two rounds of tuning got that
to **40,158 active, zero measured false positives** against 3 pcaps of real
captured game traffic from this team's own A/D matches:

1. **Decoder checksum noise** (sids `2200073`–`2200079`, "SURICATA
   TCPv4/IPv4/... invalid checksum") — disabled. These fired on ~97% of all
   alert volume in the exploit-collection test batch and are a pcap-capture
   artifact (crafted/replayed pcaps rarely carry correct hardware
   checksums), not attack signal.
2. **External-reputation and consumer-malware categories** — disabled via
   `group:` filters: `botcc*`, `compromised`, `drop`, `dshield`, `ciarmy`,
   `tor` (all reputation lists keyed on real-internet IPs — meaningless
   inside an isolated game VPN), plus `adware_pup`, `mobile_malware`,
   `games`, `p2p`, `file_sharing`, `inappropriate`, `phishing`, `worm`,
   `dyn_dns`, `chat`, `scada`, `voip` (consumer/real-internet threat classes
   a CTF vulnbox essentially never generates or receives). ~12.5k rules
   removed this way.

**Left enabled, not yet pruned**: `emerging-{ftp,telnet,tftp,pop3,imap,smtp,
snmp,rpc,activex,icmp,netbios}.rules`. These are protocol-specific — worth
disabling per-competition based on which protocols the fielded services
actually speak (check `app_config`'s `services` list first).

## How this was tested

No live A/D match traffic contains a rich enough mix of known exploit
techniques to validate detection breadth, so validation used two pcap
sources instead of made-up traffic:

1. **[safest-place/ExploitPcapCollection](https://github.com/safest-place/ExploitPcapCollection)**
   (public, MIT-ish, ~387MB, 133 real exploit pcaps organized by ATT&CK
   tactic) — used to measure detection *breadth*. One-shot Suricata runs
   (`suricata -r <file> -k none --runmode single`) per pcap, `eve.json`
   alert counts aggregated. Went from 1/132 detected (pre-existing 7-rule
   set) → 11/132 (+ custom exploit rules) → 99/132 (+ ET Open) →
   unchanged-but-cleaner after tuning (removed rules weren't carrying any of
   the 99 hits).
2. **This team's own captured A/D pcaps** (`services/test_pcap/2026-09-05_*.pcap`)
   — used to measure false-positive rate against real, mostly-benign game
   traffic. Zero ET Open false positives across all three; only the
   pre-existing service-specific rules (IDOR/redact, both real detections
   from that match) fired.

Re-running the full 133-pcap batch takes ~2–3 min with only the custom
ruleset, but **25–30 min once ET Open's 40k+ rules are loaded** (Suricata
recompiles the full signature set on every one-shot invocation — there's no
persistent-process shortcut for this kind of batch replay). Budget for that
if re-validating after a rule change.

## Known gaps (deliberately not attempted, or attempted and shelved)

- **Encrypted webshells (Behinder, Godzilla, etc.)** — AES/XOR-encrypted
  C2, no static byte signature is possible by design. Would need a
  behavioral heuristic (repeated POSTs to one URI, high-entropy/binary
  body, missing standard headers) — real engineering effort, and prone to
  false-positiving on legitimate binary uploads. Shelved as lower ROI than
  broader static coverage.
- **Niche non-Western tooling** (h3c/dbappsecurity/360skylar-specific
  webshells, reGeorg/Venom/NPS/FastTunnel tunnels) — ET Open has a Western/
  APT bias and doesn't carry signatures for these. Worth building if this
  team's opponents are known to use them.
