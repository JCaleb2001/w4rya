#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Ready-made Suricata rules for the attack shapes worth catching in a game.

A rule you write at 03:00 while a service is being farmed is a rule you write
badly. These are the well-known web attack shapes, already tagged, so the flow
list is filterable from the first tick instead of after someone finds the time.

Four deliberate choices:

* **Everything is `alert`, never `drop`.** A drop rule that misfires takes down
  your own service, and if it catches the checker you bleed SLA points for as
  long as nobody notices. Blocking is a per-rule, per-game decision to make
  from /rules once you have seen what a rule actually matches.
* **No `$HOME_NET` / `$HTTP_PORTS`.** The stack ships Suricata's stock
  variables: HOME_NET is the RFC1918 default and HTTP_PORTS is only 80. CTF
  services live on odd ports, so these say `any any -> any any` and rely on the
  http parser's protocol probing to find the traffic.
* **Every rule carries `metadata: tag <x>`.** That is the one metadata key the
  enricher reads, and it is what turns an alert into a flow tag -- which then
  auto-registers in the `tag` table within ~5s and shows up as a filter chip.
  Without it a rule only ever produces the generic `suricata` tag.
* **`pcre` over plain `content` in most rules.** Attack payloads arrive
  url-encoded, case-flipped and padded; a fixed string misses all of that. The
  cost is speed, which is affordable here because the stack reads pcaps
  offline rather than at line rate.

sids live in a dedicated 2,1xx,xxx block so a pack can tell what it already
installed and installing twice is a no-op. That sits above the 1,000,000
auto-assign floor, so `next_sid()` keeps handing out numbers past them for
hand-written rules.

A rule marked `noisy` matches a shape legitimate traffic also has. They are
still worth having -- a false positive costs a glance, a missed exploit costs
the flag -- but the UI says so before you install the pack.
"""

from __future__ import annotations


PACKS: list[dict] = [
    {
        "id": "web-injection",
        "name": "Web injection",
        "description": "SQL / NoSQL injection, XSS, template injection, XXE.",
        "rules": [
            {
                "sid": 2100001,
                "name": "SQLi: UNION SELECT",
                "tag": "sqli",
                "raw": 'alert http any any -> any any (msg:"W4RYA SQLi union select"; flow:to_server; content:"union"; nocase; pcre:"/union\\s+(all\\s+)?select/i"; metadata: tag sqli; classtype:web-application-attack; sid:2100001; rev:1;)',
            },
            {
                "sid": 2100002,
                "name": "SQLi: boolean tautology (or 1=1)",
                "tag": "sqli",
                "raw": 'alert http any any -> any any (msg:"W4RYA SQLi boolean tautology"; flow:to_server; pcre:"/(\\x27|%27|\\x22)?\\s*(or|and)\\s+(\\d+|\\x27[^\\x27]*\\x27)\\s*=\\s*(\\d+|\\x27[^\\x27]*\\x27)/i"; metadata: tag sqli; classtype:web-application-attack; sid:2100002; rev:1;)',
            },
            {
                "sid": 2100003,
                "name": "SQLi: time-based blind",
                "tag": "sqli",
                "raw": 'alert http any any -> any any (msg:"W4RYA SQLi time-based"; flow:to_server; pcre:"/(sleep\\s*\\(|benchmark\\s*\\(|pg_sleep\\s*\\(|waitfor\\s+delay)/i"; metadata: tag sqli; classtype:web-application-attack; sid:2100003; rev:1;)',
            },
            {
                "sid": 2100004,
                "name": "SQLi: schema enumeration",
                "tag": "sqli",
                "raw": 'alert http any any -> any any (msg:"W4RYA SQLi schema enumeration"; flow:to_server; pcre:"/(information_schema|sqlite_master|pg_catalog\\.|sysobjects)/i"; metadata: tag sqli; classtype:web-application-attack; sid:2100004; rev:1;)',
            },
            {
                "sid": 2100005,
                "name": "SQLi: stacked query or inline comment",
                "tag": "sqli",
                "noisy": True,
                # A literal ';' has to be escaped inside pcre: Suricata splits
                # rule options on it, so an unescaped one truncates the regex
                # and the whole rule fails to load.
                "raw": 'alert http any any -> any any (msg:"W4RYA SQLi stacked query or comment"; flow:to_server; pcre:"/(\\;\\s*(drop|insert|update|delete)\\s|\\/\\*!|--\\s|%2d%2d)/i"; metadata: tag sqli; classtype:web-application-attack; sid:2100005; rev:1;)',
            },
            {
                "sid": 2100006,
                "name": "NoSQL injection operator ($ne / $gt / $where)",
                "tag": "nosqli",
                "raw": 'alert http any any -> any any (msg:"W4RYA NoSQL injection operator"; flow:to_server; pcre:"/(\\x22|%22|\\x27)\\$(ne|gt|gte|lt|lte|where|regex|expr|in)(\\x22|%22|\\x27)?\\s*:/i"; metadata: tag nosqli; classtype:web-application-attack; sid:2100006; rev:1;)',
            },
            {
                "sid": 2100007,
                "name": "XSS: script tag",
                "tag": "xss",
                "raw": 'alert http any any -> any any (msg:"W4RYA XSS script tag"; flow:to_server; pcre:"/(<|%3c)\\s*script/i"; metadata: tag xss; classtype:web-application-attack; sid:2100007; rev:1;)',
            },
            {
                "sid": 2100008,
                "name": "XSS: inline event handler",
                "tag": "xss",
                "raw": 'alert http any any -> any any (msg:"W4RYA XSS event handler"; flow:to_server; pcre:"/on(error|load|mouseover|focus|click|toggle)\\s*(=|%3d)/i"; metadata: tag xss; classtype:web-application-attack; sid:2100008; rev:1;)',
            },
            {
                "sid": 2100009,
                "name": "SSTI: template expression",
                "tag": "ssti",
                "raw": 'alert http any any -> any any (msg:"W4RYA SSTI template expression"; flow:to_server; pcre:"/(\\{\\{|%7b%7b|\\$\\{|<%=|\\{%)[^\\r\\n]{0,60}(\\}\\}|%7d%7d|\\}|%>)/i"; metadata: tag ssti; classtype:web-application-attack; sid:2100009; rev:1;)',
            },
            {
                "sid": 2100010,
                "name": "SSTI: python object traversal",
                "tag": "ssti",
                "raw": 'alert http any any -> any any (msg:"W4RYA SSTI python object traversal"; flow:to_server; pcre:"/(__class__|__mro__|__subclasses__|__globals__|__builtins__)/"; metadata: tag ssti; classtype:web-application-attack; sid:2100010; rev:1;)',
            },
            {
                "sid": 2100011,
                "name": "XXE: external entity",
                "tag": "xxe",
                "raw": 'alert http any any -> any any (msg:"W4RYA XXE external entity"; flow:to_server; content:"<!ENTITY"; nocase; pcre:"/<!ENTITY\\s+\\S+\\s+(SYSTEM|PUBLIC)/i"; metadata: tag xxe; classtype:web-application-attack; sid:2100011; rev:1;)',
            },
            {
                "sid": 2100012,
                "name": "Prototype pollution (__proto__)",
                "tag": "proto_pollution",
                "raw": 'alert http any any -> any any (msg:"W4RYA prototype pollution"; flow:to_server; pcre:"/(__proto__|constructor\\s*(\\.|\\[)\\s*[\\x22\\x27]?prototype)/"; metadata: tag proto_pollution; classtype:web-application-attack; sid:2100012; rev:1;)',
            },
        ],
    },
    {
        "id": "web-rce",
        "name": "Remote code execution",
        "description": "Command injection, deserialization, webshells, reverse shells.",
        "rules": [
            {
                "sid": 2100101,
                "name": "Command injection: shell metachar plus command",
                "tag": "rce",
                "raw": 'alert http any any -> any any (msg:"W4RYA command injection"; flow:to_server; pcre:"/(\\;|\\||&|%3b|%7c|%26)\\s*(id|whoami|uname|cat|ls|pwd|curl|wget|nc|bash|sh|python[23]?)\\b/i"; metadata: tag rce; classtype:web-application-attack; sid:2100101; rev:1;)',
            },
            {
                "sid": 2100102,
                "name": "Command injection: command substitution",
                "tag": "rce",
                "raw": 'alert http any any -> any any (msg:"W4RYA command substitution"; flow:to_server; pcre:"/(\\$\\(|%24%28|\\x60|%60)\\s*(id|whoami|uname|cat|curl|wget|nc|bash|sh)\\b/i"; metadata: tag rce; classtype:web-application-attack; sid:2100102; rev:1;)',
            },
            {
                "sid": 2100103,
                "name": "Reverse shell payload",
                "tag": "reverse_shell",
                "raw": 'alert http any any -> any any (msg:"W4RYA reverse shell payload"; flow:to_server; pcre:"/(\\/dev\\/tcp\\/|%2fdev%2ftcp|bash\\s+-i|nc\\s+(-[a-z]*e\\b|--exec)|socat\\s+[^\\r\\n]{0,40}exec|python[23]?\\s+-c[^\\r\\n]{0,60}socket)/i"; metadata: tag reverse_shell; classtype:web-application-attack; sid:2100103; rev:1;)',
            },
            {
                "sid": 2100104,
                "name": "Pipe-to-shell download",
                "tag": "rce",
                "raw": 'alert http any any -> any any (msg:"W4RYA pipe to shell"; flow:to_server; pcre:"/(curl|wget)\\s[^\\;&\\r\\n]{0,120}(\\||%7c)\\s*(bash|sh|zsh|python[23]?)\\b/i"; metadata: tag rce; classtype:web-application-attack; sid:2100104; rev:1;)',
            },
            {
                "sid": 2100105,
                "name": "PHP object injection (serialized payload)",
                "tag": "deserialization",
                "raw": 'alert http any any -> any any (msg:"W4RYA PHP object injection"; flow:to_server; pcre:"/O:\\d+:(\\x22|%22)[A-Za-z_][A-Za-z0-9_]*(\\x22|%22):\\d+:(\\{|%7b)/"; metadata: tag deserialization; classtype:web-application-attack; sid:2100105; rev:1;)',
            },
            {
                "sid": 2100106,
                "name": "Java deserialization (serialized stream header)",
                "tag": "deserialization",
                "raw": 'alert http any any -> any any (msg:"W4RYA java deserialization"; flow:to_server; pcre:"/(rO0AB|\\xac\\xed\\x00\\x05)/"; metadata: tag deserialization; classtype:web-application-attack; sid:2100106; rev:1;)',
            },
            {
                "sid": 2100107,
                "name": "Python pickle payload",
                "tag": "deserialization",
                "raw": 'alert http any any -> any any (msg:"W4RYA python pickle payload"; flow:to_server; pcre:"/(cos\\nsystem|cposix\\nsystem|c__builtin__\\neval|__reduce__)/"; metadata: tag deserialization; classtype:web-application-attack; sid:2100107; rev:1;)',
            },
            {
                "sid": 2100108,
                "name": "JNDI lookup (Log4Shell shape)",
                "tag": "jndi",
                "raw": 'alert http any any -> any any (msg:"W4RYA JNDI lookup"; flow:to_server; pcre:"/(\\$\\{|%24%7b)\\s*(jndi|\\$\\{|lower:|upper:)/i"; metadata: tag jndi; classtype:web-application-attack; sid:2100108; rev:1;)',
            },
            {
                "sid": 2100109,
                "name": "Webshell upload (script extension in multipart)",
                "tag": "webshell_upload",
                "raw": 'alert http any any -> any any (msg:"W4RYA webshell upload"; flow:to_server; content:"filename="; nocase; http_client_body; pcre:"/filename=\\x22?[^\\x22\\r\\n]{1,80}\\.(php[0-9st]?|phtml|phar|jspx?|jspf|aspx?|cgi|pl|py|sh)\\b/i"; metadata: tag webshell_upload; classtype:web-application-attack; sid:2100109; rev:1;)',
            },
            {
                "sid": 2100110,
                "name": "Webshell code in body (eval/system on request data)",
                "tag": "webshell",
                "raw": 'alert http any any -> any any (msg:"W4RYA webshell code in body"; flow:to_server; pcre:"/(eval|assert|system|passthru|shell_exec|popen|proc_open)\\s*\\(\\s*\\$?_(GET|POST|REQUEST|COOKIE|SERVER)/i"; metadata: tag webshell; classtype:web-application-attack; sid:2100110; rev:1;)',
            },
            {
                "sid": 2100111,
                "name": "Python exec / import injection",
                "tag": "rce",
                "raw": 'alert http any any -> any any (msg:"W4RYA python exec injection"; flow:to_server; pcre:"/(__import__\\s*\\(|os\\.(system|popen)\\s*\\(|subprocess\\.(run|call|Popen|check_output))/"; metadata: tag rce; classtype:web-application-attack; sid:2100111; rev:1;)',
            },
        ],
    },
    {
        "id": "web-traversal",
        "name": "Traversal, file inclusion and SSRF",
        "description": "Path traversal, LFI/RFI wrappers, server-side request forgery.",
        "rules": [
            {
                "sid": 2100201,
                "name": "Path traversal (raw and encoded)",
                "tag": "path_traversal",
                "raw": 'alert http any any -> any any (msg:"W4RYA path traversal"; flow:to_server; pcre:"/(\\.\\.(\\/|\\\\|%2f|%5c)|%2e%2e(%2f|%5c|\\/)|\\.\\.%c0%af|%252e%252e)/i"; metadata: tag path_traversal; classtype:web-application-attack; sid:2100201; rev:1;)',
            },
            {
                "sid": 2100202,
                "name": "Sensitive unix path requested",
                "tag": "lfi",
                "raw": 'alert http any any -> any any (msg:"W4RYA sensitive unix path"; flow:to_server; pcre:"/(\\/etc\\/(passwd|shadow|hosts)|%2fetc%2fpasswd|\\/proc\\/self\\/(environ|cmdline)|\\/root\\/\\.[a-z])/i"; metadata: tag lfi; classtype:web-application-attack; sid:2100202; rev:1;)',
            },
            {
                "sid": 2100203,
                "name": "PHP stream wrapper (php:// data:// expect://)",
                "tag": "lfi",
                "raw": 'alert http any any -> any any (msg:"W4RYA php stream wrapper"; flow:to_server; pcre:"/(php:(\\/\\/|%2f%2f)(filter|input)|data:(\\/\\/|%2f%2f)|expect:(\\/\\/|%2f%2f)|zip:(\\/\\/|%2f%2f)|phar:(\\/\\/|%2f%2f))/i"; metadata: tag lfi; classtype:web-application-attack; sid:2100203; rev:1;)',
            },
            {
                "sid": 2100204,
                "name": "Remote file inclusion (url as parameter value)",
                "tag": "rfi",
                "noisy": True,
                # Sticky buffer BEFORE the pcre. The classic `http_uri`
                # modifier only attaches to a preceding `content`, so trailing
                # it after a pcre is a load error, not a silent no-op.
                "raw": 'alert http any any -> any any (msg:"W4RYA remote file inclusion"; flow:to_server; http.uri; pcre:"/[?&][a-z_]{1,20}=(https?|ftp)(:\\/\\/|%3a%2f%2f)/i"; metadata: tag rfi; classtype:web-application-attack; sid:2100204; rev:1;)',
            },
            {
                "sid": 2100205,
                "name": "SSRF: cloud metadata endpoint",
                "tag": "ssrf",
                "raw": 'alert http any any -> any any (msg:"W4RYA SSRF cloud metadata"; flow:to_server; pcre:"/(169\\.254\\.169\\.254|metadata\\.google\\.internal)/"; metadata: tag ssrf; classtype:web-application-attack; sid:2100205; rev:1;)',
            },
            {
                "sid": 2100206,
                "name": "SSRF: loopback or exotic scheme in parameter",
                "tag": "ssrf",
                "noisy": True,
                "raw": 'alert http any any -> any any (msg:"W4RYA SSRF loopback or exotic scheme"; flow:to_server; pcre:"/[?&][a-z_]{1,20}=(file|gopher|dict|ftp):(\\/\\/|%2f%2f)|[?&][a-z_]{1,20}=https?:(\\/\\/|%3a%2f%2f)(127\\.0\\.0\\.1|localhost|0\\.0\\.0\\.0)/i"; metadata: tag ssrf; classtype:web-application-attack; sid:2100206; rev:1;)',
            },
            {
                "sid": 2100207,
                "name": "VCS or dotfile probe (.git /.env)",
                "tag": "recon",
                "raw": 'alert http any any -> any any (msg:"W4RYA vcs or dotfile probe"; flow:to_server; http.uri; pcre:"/\\/(\\.git\\/|\\.svn\\/|\\.env\\b|\\.htpasswd|\\.aws\\/|\\.ssh\\/|\\.DS_Store)/i"; metadata: tag recon; classtype:web-application-attack; sid:2100207; rev:1;)',
            },
        ],
    },
    {
        "id": "recon",
        "name": "Recon and tooling",
        "description": "Scanner fingerprints and the traffic that precedes an exploit.",
        "rules": [
            {
                "sid": 2100301,
                "name": "Scanner user-agent",
                "tag": "scanner",
                "raw": 'alert http any any -> any any (msg:"W4RYA scanner user-agent"; flow:to_server; http.user_agent; pcre:"/(sqlmap|nikto|nmap|masscan|dirb|dirbuster|gobuster|feroxbuster|wfuzz|ffuf|hydra|nuclei|zgrab|acunetix|nessus)/i"; metadata: tag scanner; classtype:attempted-recon; sid:2100301; rev:1;)',
            },
            {
                "sid": 2100302,
                "name": "Empty or scripted user-agent",
                "tag": "scripted_client",
                "noisy": True,
                "raw": 'alert http any any -> any any (msg:"W4RYA scripted http client"; flow:to_server; http.user_agent; pcre:"/^(python-requests|Go-http-client|curl|Wget|libwww-perl|okhttp|axios|node-fetch|PostmanRuntime)/i"; metadata: tag scripted_client; classtype:attempted-recon; sid:2100302; rev:1;)',
            },
            {
                "sid": 2100303,
                "name": "HTTP method rarely used by a real client",
                "tag": "odd_method",
                "raw": 'alert http any any -> any any (msg:"W4RYA unusual http method"; flow:to_server; http.method; pcre:"/^(PUT|DELETE|TRACE|TRACK|CONNECT|PATCH|MOVE|COPY|PROPFIND)$/"; metadata: tag odd_method; classtype:attempted-recon; sid:2100303; rev:1;)',
            },
            {
                "sid": 2100304,
                "name": "Admin or backup path probe",
                "tag": "recon",
                "raw": 'alert http any any -> any any (msg:"W4RYA admin or backup path probe"; flow:to_server; http.uri; pcre:"/\\/(admin|phpmyadmin|wp-admin|actuator|console|debug|backup|dump|\\w+\\.(bak|old|swp|sql|tar|zip))(\\/|\\?|$)/i"; metadata: tag recon; classtype:attempted-recon; sid:2100304; rev:1;)',
            },
        ],
    },
    {
        "id": "exfil",
        "name": "Leaks in responses",
        "description": "What a successful exploit looks like on the way back out.",
        "rules": [
            {
                "sid": 2100401,
                "name": "Response contains /etc/passwd content",
                "tag": "data_leak",
                "raw": 'alert http any any -> any any (msg:"W4RYA passwd content in response"; flow:to_client; pcre:"/root:[x*!]?:0:0:/"; metadata: tag data_leak; classtype:successful-recon-limited; sid:2100401; rev:1;)',
            },
            {
                "sid": 2100402,
                "name": "Response contains a directory listing",
                "tag": "data_leak",
                "raw": 'alert http any any -> any any (msg:"W4RYA directory listing in response"; flow:to_client; pcre:"/<title>Index of \\/|Directory listing for \\//i"; metadata: tag data_leak; classtype:successful-recon-limited; sid:2100402; rev:1;)',
            },
            {
                "sid": 2100403,
                "name": "Response contains a stack trace",
                "tag": "app_error",
                "raw": 'alert http any any -> any any (msg:"W4RYA stack trace in response"; flow:to_client; pcre:"/(Traceback \\(most recent call last\\)|Fatal error:|Warning: \\w+\\(\\)|java\\.lang\\.\\w+Exception|at [a-z]+\\.[a-z]+\\.\\w+\\(\\w+\\.java:)/"; metadata: tag app_error; classtype:web-application-activity; sid:2100403; rev:1;)',
            },
            {
                "sid": 2100404,
                "name": "Response contains command output (uid= gid=)",
                "tag": "rce_confirmed",
                "raw": 'alert http any any -> any any (msg:"W4RYA command output in response"; flow:to_client; pcre:"/uid=\\d+\\([a-z_][a-z0-9_-]*\\)\\s+gid=\\d+\\(/"; metadata: tag rce_confirmed; classtype:successful-admin; sid:2100404; rev:1;)',
            },
            {
                "sid": 2100405,
                "name": "Response contains an sql error",
                "tag": "sqli",
                "raw": 'alert http any any -> any any (msg:"W4RYA sql error in response"; flow:to_client; pcre:"/(You have an error in your SQL syntax|Unclosed quotation mark|PG::SyntaxError|SQLITE_ERROR|ORA-0[0-9]{4}|psycopg2\\.\\w+Error|sqlalchemy\\.exc)/i"; metadata: tag sqli; classtype:web-application-activity; sid:2100405; rev:1;)',
            },
        ],
    },
]


# Every sid this module owns. Used to tell an installed pack rule apart from a
# hand-written one, so re-installing is a no-op instead of a duplicate.
PACK_SID_MIN = 2_100_000
PACK_SID_MAX = 2_199_999


def all_rules() -> list[dict]:
    return [rule for pack in PACKS for rule in pack["rules"]]


def find_pack(pack_id: str) -> dict | None:
    for pack in PACKS:
        if pack["id"] == pack_id:
            return pack
    return None


def catalog(existing_sids: set[int]) -> list[dict]:
    """The packs, annotated with what is already in the rules file.

    `installed` counts rules present by sid, so a pack the operator has partly
    installed (or partly deleted) reports honestly rather than as all-or-nothing.
    """
    out = []
    for pack in PACKS:
        rules = [
            {**rule, "installed": rule["sid"] in existing_sids}
            for rule in pack["rules"]
        ]
        out.append({
            "id": pack["id"],
            "name": pack["name"],
            "description": pack["description"],
            "rules": rules,
            "installed": sum(1 for r in rules if r["installed"]),
            "total": len(rules),
        })
    return out
