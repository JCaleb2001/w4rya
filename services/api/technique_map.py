"""Deterministic technique classification for Suricata signature hits.

NO AI: this is a plain dict lookup keyed by the exact `msg` string each rule
in rules.py declares, plus a couple of prefix rules for dynamically-named
signatures (e.g. rules drafted by attack.suggest_rule(), or the ~40k
Emerging Threats Open signatures, which follow a stable "ET <CATEGORY> ..."
naming convention we can classify by prefix without enumerating each one).
Every entry is a judgment call made by whoever wrote the rule, encoded once
here instead of re-derived per alert.

Purpose: turn "rule 1000004 fired" into "this is Execution / Command and
Scripting Interpreter (T1059)" so the monitoring team can hand attack/patching
a technique name instead of a signature id, and so alerts from different
rules with the same underlying technique group together on a kill-chain view.

Each record also carries a `remediation` string: one sentence of generic,
technique-level fix advice (not payload-specific) for whoever picks up the
incident packet built from this alert (see webservice.attack_incident).
"""

from __future__ import annotations

# tactic follows the MITRE ATT&CK kill-chain ordering (used to sort a
# per-attacker chain chronologically-then-by-stage). Lower = earlier stage.
TACTIC_ORDER = {
    "Reconnaissance": 0,
    "Initial Access": 1,
    "Execution": 2,
    "Command and Control": 3,
    "Privilege Escalation": 4,
    "Credential Access": 5,
    "Discovery": 6,
    "Collection": 7,
    "Exfiltration": 8,
    "Impact": 9,
    "Unknown": 99,
}

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# --- Shared remediation text, reused across entries that share a root cause.
_HINT_SQLI = (
    "Use parameterized queries / prepared statements for every code path this "
    "input reaches. Never string-concatenate user input into SQL, including "
    "for things that feel like 'just a filter or sort column'."
)
_HINT_TRAVERSAL = (
    "Canonicalize the resolved path (follow '..' and symlinks) and verify it "
    "is still inside an explicit allow-listed base directory before opening. "
    "Stripping '../' textually is not enough — encoded and double-encoded "
    "variants bypass naive filters."
)
_HINT_LFI = (
    "Never open a file path built from user input directly. Map user-facing "
    "identifiers to file paths through a server-side allow-list/lookup table "
    "instead of trusting the client's path segment."
)
_HINT_CMDI = (
    "Never pass user input to a shell (system()/exec()/Runtime.exec with "
    "shell interpretation or naive string concatenation). Use an argv-array "
    "API that skips shell parsing entirely, and allow-list the specific "
    "command/arguments if one must still be built dynamically."
)
_HINT_DESERIALIZATION = (
    "Stop deserializing untrusted bytes with a general-purpose deserializer "
    "(Java ObjectInputStream, PHP unserialize, Python pickle/yaml.load, .NET "
    "BinaryFormatter). Switch to a data-only format (JSON) or add strict "
    "class allow-listing at the deserializer."
)
_HINT_XXE = (
    "Disable external entity resolution in the XML parser at the source "
    "(e.g. Java: disable DOCTYPE declarations; libxml2: turn off entity "
    "substitution) rather than trying to sanitize the XML text first."
)
_HINT_SSRF = (
    "Allow-list destination hosts/IPs for any server-side outbound request "
    "built from user input, and explicitly block link-local/metadata ranges "
    "(169.254.0.0/16 and friends) at the HTTP client layer, not just in app code."
)
_HINT_AUTHZ = (
    "Re-check that every object/resource lookup verifies the requesting user "
    "actually owns or is authorized for that specific ID — an unguessable ID "
    "is not an access control."
)
_HINT_RECON = (
    "No code fix applies — this is reconnaissance, not exploitation. Useful "
    "as an early-warning signal: watch this source for a follow-up attack."
)
_HINT_BRUTEFORCE = (
    "Add rate-limiting/lockout after N failed attempts from one source, and "
    "make sure this service's credential is unique and not a shared default "
    "across your other services."
)
_HINT_PROTOTYPE_POLLUTION = (
    "Freeze objects built from user input (or construct them with "
    "Object.create(null)); most prototype-pollution reports trace back to one "
    "specific merge/extend/clone utility function — patch or replace that one."
)
_HINT_OPEN_REDIRECT = (
    "Validate the redirect target against an allow-list of known-good "
    "paths/hosts; never redirect straight to a user-supplied URL."
)
_HINT_RCE_GENERIC = (
    "Treat this as confirmed or attempted remote code execution. Identify "
    "the specific deserialization/eval/template-injection sink this payload "
    "reached and remove or sandbox it — patching the exact string in the "
    "payload will not stop the next variant of the same exploit."
)
_HINT_C2 = (
    "This indicates outbound command-and-control traffic, not an inbound "
    "exploit — the host is already compromised. Isolate/rebuild the box "
    "rather than patch code; then work backward through earlier alerts from "
    "the same src_ip to find the actual entry point."
)
_HINT_GENERIC = (
    "Review the decoded payload for this alert to identify the exact input "
    "the rule matched, then add server-side validation for that input — this "
    "signature's category has no single universal one-line fix."
)

_BY_MESSAGE: dict[str, dict] = {
    "path traversal": {
        "tactic": "Discovery", "technique": "File and Directory Discovery",
        "mitre": "T1083", "severity": "medium", "remediation": _HINT_TRAVERSAL,
    },
    "/etc/passwd in URI": {
        "tactic": "Collection", "technique": "Local File Inclusion",
        "mitre": "T1005", "severity": "high", "remediation": _HINT_LFI,
    },
    "SQLi union select": {
        "tactic": "Initial Access", "technique": "Exploit Public-Facing Application (SQL Injection)",
        "mitre": "T1190", "severity": "critical", "remediation": _HINT_SQLI,
    },
    "command injection pattern in body": {
        "tactic": "Execution", "technique": "Command and Scripting Interpreter",
        "mitre": "T1059", "severity": "critical", "remediation": _HINT_CMDI,
    },
    "command substitution syntax in body": {
        "tactic": "Execution", "technique": "Command and Scripting Interpreter",
        "mitre": "T1059", "severity": "critical", "remediation": _HINT_CMDI,
    },
    "bad UA: sqlmap": {
        "tactic": "Reconnaissance", "technique": "Active Scanning (automated tool)",
        "mitre": "T1595", "severity": "low", "remediation": _HINT_RECON,
    },
    "recon tool UA detected": {
        "tactic": "Reconnaissance", "technique": "Active Scanning (automated tool)",
        "mitre": "T1595", "severity": "low", "remediation": _HINT_RECON,
    },
    "NoSQL injection operator in JSON body": {
        "tactic": "Initial Access", "technique": "Exploit Public-Facing Application (NoSQL Injection)",
        "mitre": "T1190", "severity": "critical", "remediation": _HINT_SQLI,
    },
    "possible XXE (DOCTYPE/ENTITY in body)": {
        "tactic": "Initial Access", "technique": "Exploit Public-Facing Application (XXE)",
        "mitre": "T1190", "severity": "high", "remediation": _HINT_XXE,
    },
    "SSRF to cloud metadata endpoint": {
        "tactic": "Credential Access", "technique": "Cloud Instance Metadata API",
        "mitre": "T1552.005", "severity": "critical", "remediation": _HINT_SSRF,
    },
    "prototype pollution attempt (__proto__ in body)": {
        "tactic": "Privilege Escalation", "technique": "Prototype Pollution",
        "mitre": "T1190", "severity": "high", "remediation": _HINT_PROTOTYPE_POLLUTION,
    },
    "Java deserialization magic bytes": {
        "tactic": "Execution", "technique": "Deserialization of Untrusted Data",
        "mitre": "T1190", "severity": "critical", "remediation": _HINT_DESERIALIZATION,
    },
    "possible open redirect param": {
        "tactic": "Initial Access", "technique": "Open Redirect (phishing enabler)",
        "mitre": "T1204", "severity": "low", "remediation": _HINT_OPEN_REDIRECT,
    },
    "Log4Shell JNDI lookup attempt": {
        "tactic": "Initial Access", "technique": "Exploit Public-Facing Application (Log4Shell)",
        "mitre": "T1190", "severity": "critical", "remediation": _HINT_DESERIALIZATION,
    },
    # --- exploit-technique rules added after ExploitPcapCollection testing ---
    "Log4Shell JNDI lookup in URI": {
        "tactic": "Initial Access", "technique": "Exploit Public-Facing Application (Log4Shell)",
        "mitre": "T1190", "severity": "critical", "remediation": _HINT_DESERIALIZATION,
    },
    "ThinkPHP 5 RCE via invokefunction": {
        "tactic": "Initial Access", "technique": "Exploit Public-Facing Application (RCE)",
        "mitre": "T1190", "severity": "critical", "remediation": _HINT_RCE_GENERIC,
    },
    "WebLogic console double-encoded traversal (CVE-2020-14882/14883)": {
        "tactic": "Initial Access", "technique": "Exploit Public-Facing Application (Auth Bypass)",
        "mitre": "T1190", "severity": "critical", "remediation": _HINT_TRAVERSAL,
    },
    "Fastjson autoType RCE (JdbcRowSetImpl gadget)": {
        "tactic": "Execution", "technique": "Deserialization of Untrusted Data",
        "mitre": "T1190", "severity": "critical", "remediation": _HINT_DESERIALIZATION,
    },
    "Tomcat PUT JSP upload bypass (CVE-2017-12615)": {
        "tactic": "Initial Access", "technique": "Exploit Public-Facing Application (Arbitrary File Upload)",
        "mitre": "T1190", "severity": "critical", "remediation": (
            "Disable the PUT/DELETE HTTP methods on the default servlet unless "
            "actually needed, and never let an uploaded file's extension "
            "alone decide whether it gets executed server-side."
        ),
    },
    "Apache Shiro rememberMe deserialization failure (CVE-2016-4437 indicator)": {
        "tactic": "Execution", "technique": "Deserialization of Untrusted Data",
        "mitre": "T1190", "severity": "critical", "remediation": (
            "Rotate Shiro's `rememberMe` AES cipher key away from the "
            "well-known default (`kPH+bIxk5D2deZiIxcaaaA==`) and upgrade past "
            "1.2.4 — the cookie value is a straight AES-CBC-encrypted Java "
            "serialized object with no other integrity check."
        ),
    },
    "SQLi error/blind injection function (extractvalue/updatexml/benchmark)": {
        "tactic": "Initial Access", "technique": "Exploit Public-Facing Application (SQL Injection)",
        "mitre": "T1190", "severity": "critical", "remediation": _HINT_SQLI,
    },
    "SQLi INTO OUTFILE/DUMPFILE (webshell write via SQL)": {
        "tactic": "Execution", "technique": "Exploit Public-Facing Application (SQL Injection to RCE)",
        "mitre": "T1190", "severity": "critical", "remediation": (
            _HINT_SQLI + " Additionally, run the DB user with FILE privilege "
            "revoked (or `--secure-file-priv` set) so even a successful "
            "injection can't write a webshell to the document root."
        ),
    },
    "XXL-Job glueSource reverse shell payload": {
        "tactic": "Execution", "technique": "Command and Scripting Interpreter",
        "mitre": "T1059", "severity": "critical", "remediation": (
            "Require auth on the job-admin API and restrict who can create/"
            "edit GLUE (script-mode) jobs — that feature is designed to run "
            "arbitrary code by anyone who can reach it."
        ),
    },
    "MSSQL xp_cmdshell execution attempt (TDS)": {
        "tactic": "Execution", "technique": "Command and Scripting Interpreter",
        "mitre": "T1059", "severity": "critical", "remediation": (
            "Disable the `xp_cmdshell` extended stored procedure "
            "(`sp_configure 'xp_cmdshell', 0`) unless a specific feature "
            "requires it, and don't run the SQL service account as sysadmin."
        ),
    },
    "Nacos unauthenticated config removal (ops/data/removal)": {
        "tactic": "Impact", "technique": "Broken Access Control (unauthenticated admin API)",
        "mitre": "T1499", "severity": "high", "remediation": (
            "Enable Nacos auth (`nacos.core.auth.enabled=true`) — several "
            "config-management endpoints ship with no authentication by "
            "default in vulnerable versions."
        ),
    },
    "Possible NetBIOS name service scan (nbtscan-style recon)": {
        "tactic": "Reconnaissance", "technique": "Network Service Discovery",
        "mitre": "T1046", "severity": "low", "remediation": _HINT_RECON,
    },
}

# Prefix rules for messages that vary per-flow (can't be exact-matched).
_BY_PREFIX: list[tuple[str, dict]] = [
    ("suggested: raw payload match on port", {
        "tactic": "Unknown", "technique": "Custom signature (drafted from a captured flow)",
        "mitre": None, "severity": "medium", "remediation": _HINT_GENERIC,
    }),
    ("suggested:", {
        "tactic": "Initial Access", "technique": "Custom signature (drafted from a captured flow)",
        "mitre": None, "severity": "medium", "remediation": _HINT_GENERIC,
    }),
    ("IDOR:", {
        "tactic": "Collection", "technique": "Broken Access Control (IDOR)",
        "mitre": "T1213", "severity": "high", "remediation": _HINT_AUTHZ,
    }),
    ("Possible IDOR:", {
        "tactic": "Collection", "technique": "Broken Access Control (IDOR)",
        "mitre": "T1213", "severity": "high", "remediation": _HINT_AUTHZ,
    }),
    ("Possible brute force:", {
        "tactic": "Credential Access", "technique": "Brute Force",
        "mitre": "T1110", "severity": "medium", "remediation": _HINT_BRUTEFORCE,
    }),
    ("Redact-service:", {
        "tactic": "Collection", "technique": "Broken Access Control (sensitive-action probing)",
        "mitre": "T1213", "severity": "medium", "remediation": _HINT_AUTHZ,
    }),
    ("WS-service:", {
        "tactic": "Exfiltration", "technique": "Exfiltration Over Alternative Protocol (WebSocket)",
        "mitre": "T1048", "severity": "high", "remediation": (
            "Don't echo secret state (flags, tokens) over a channel "
            "(WebSocket banners, connection metadata) that isn't covered by "
            "the same access checks as the main API."
        ),
    }),
    ("shell metachars", {
        "tactic": "Execution", "technique": "Command and Scripting Interpreter",
        "mitre": "T1059", "severity": "medium", "remediation": _HINT_CMDI,
    }),
    # --- Emerging Threats Open naming convention: "ET <CATEGORY> ...". ET
    # ships ~40k signatures post-tuning; enumerating each is infeasible, so
    # classify by category prefix instead. Order matters: more specific
    # categories first so e.g. "ET EXPLOIT_KIT" doesn't fall into "ET EXPLOIT".
    ("ET ATTACK_RESPONSE", {
        "tactic": "Execution", "technique": "Confirmed exploitation indicator (seen in response)",
        "mitre": "T1190", "severity": "critical", "remediation": _HINT_RCE_GENERIC,
    }),
    ("ET EXPLOIT_KIT", {
        "tactic": "Initial Access", "technique": "Drive-by Compromise (exploit kit)",
        "mitre": "T1189", "severity": "high", "remediation": _HINT_GENERIC,
    }),
    ("ET EXPLOIT", {
        "tactic": "Initial Access", "technique": "Exploit Public-Facing Application",
        "mitre": "T1190", "severity": "high", "remediation": _HINT_RCE_GENERIC,
    }),
    ("ET WEB_SPECIFIC_APPS", {
        "tactic": "Initial Access", "technique": "Exploit Public-Facing Application (known CVE)",
        "mitre": "T1190", "severity": "high", "remediation": _HINT_RCE_GENERIC,
    }),
    ("ET WEB_SERVER", {
        "tactic": "Initial Access", "technique": "Exploit Public-Facing Application (web server)",
        "mitre": "T1190", "severity": "high", "remediation": _HINT_GENERIC,
    }),
    ("ET WEB_CLIENT", {
        "tactic": "Initial Access", "technique": "Malicious response to a client request",
        "mitre": "T1189", "severity": "medium", "remediation": _HINT_GENERIC,
    }),
    ("ET SQL", {
        "tactic": "Initial Access", "technique": "Exploit Public-Facing Application (SQL Injection)",
        "mitre": "T1190", "severity": "critical", "remediation": _HINT_SQLI,
    }),
    ("ET CURRENT_EVENTS", {
        "tactic": "Initial Access", "technique": "Known active-campaign indicator",
        "mitre": "T1190", "severity": "high", "remediation": _HINT_GENERIC,
    }),
    ("ET MALWARE", {
        "tactic": "Command and Control", "technique": "Malware / C2 traffic indicator",
        "mitre": "T1071", "severity": "high", "remediation": _HINT_C2,
    }),
    ("ET TROJAN", {
        "tactic": "Command and Control", "technique": "Malware / C2 traffic indicator",
        "mitre": "T1071", "severity": "high", "remediation": _HINT_C2,
    }),
    ("ET SHELLCODE", {
        "tactic": "Execution", "technique": "Shellcode in network traffic",
        "mitre": "T1059", "severity": "critical", "remediation": _HINT_RCE_GENERIC,
    }),
    ("ET SCAN", {
        "tactic": "Reconnaissance", "technique": "Active Scanning",
        "mitre": "T1595", "severity": "low", "remediation": _HINT_RECON,
    }),
    ("ET HUNTING", {
        "tactic": "Discovery", "technique": "Heuristic/low-confidence indicator",
        "mitre": None, "severity": "low", "remediation": _HINT_GENERIC,
    }),
    ("ET INFO", {
        "tactic": "Discovery", "technique": "Informational fingerprint (tool/protocol identification)",
        "mitre": None, "severity": "low", "remediation": (
            "Not an attack by itself — a fingerprint (client library, tool "
            "User-Agent, TLS fingerprint). Useful for attributing other "
            "alerts from the same source, not for patching."
        ),
    }),
    ("ET USER_AGENTS", {
        "tactic": "Reconnaissance", "technique": "Known scanning/exploitation tool identified by User-Agent",
        "mitre": "T1595", "severity": "low", "remediation": _HINT_RECON,
    }),
    ("ET DNS", {
        "tactic": "Command and Control", "technique": "DNS-based C2 or exfiltration indicator",
        "mitre": "T1071.004", "severity": "high", "remediation": _HINT_C2,
    }),
    ("ET DOS", {
        "tactic": "Impact", "technique": "Denial of Service",
        "mitre": "T1499", "severity": "high", "remediation": (
            "Add request rate-limiting / connection caps in front of the "
            "affected service; this class of finding is availability, not a "
            "code-level vulnerability to patch."
        ),
    }),
    ("ET JA3", {
        "tactic": "Discovery", "technique": "TLS client fingerprint match (known tool)",
        "mitre": None, "severity": "low", "remediation": (
            "Fingerprint identification only — cross-reference with other "
            "alerts from the same src_ip for attribution."
        ),
    }),
]

_DEFAULT = {
    "tactic": "Unknown", "technique": "Unclassified signature",
    "mitre": None, "severity": "medium", "remediation": _HINT_GENERIC,
}


def summarize(classified_rules: list[dict], has_flag_only: bool = False) -> tuple[str, str]:
    """Pick the headline (tactic, severity) for a timeline event from its
    already-classified rule hits (each a dict from `classify()`).

    `has_flag_only`: the flow leaked a flag but matched no named signature —
    still worth surfacing as Exfiltration/high rather than falling through
    to the generic Unknown/medium default.
    """
    if not classified_rules:
        return ("Exfiltration", "high") if has_flag_only else ("Unknown", "medium")
    best = max(classified_rules, key=lambda r: SEVERITY_ORDER.get(r["severity"], 0))
    return best["tactic"], best["severity"]


def classify(message: str | None) -> dict:
    """Map a signature's `msg` text to a tactic/technique record.

    Always returns a dict with tactic/technique/mitre/severity/remediation —
    falls back to `_DEFAULT` for anything not in the table (e.g. a rule
    someone wrote by hand in the UI) rather than raising, since this runs on
    every alert in a hot path (the /attacks timeline).
    """
    if not message:
        return dict(_DEFAULT)
    hit = _BY_MESSAGE.get(message)
    if hit:
        return dict(hit)
    for prefix, rec in _BY_PREFIX:
        if message.startswith(prefix):
            return dict(rec)
    return dict(_DEFAULT)
