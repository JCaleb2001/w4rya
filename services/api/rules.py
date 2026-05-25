"""Suricata rules CRUD for w4rya.

Storage is the canonical Suricata text format on disk (one rule per line).
We parse each line into a structured record for the UI, then write the file
back as raw lines on every save (with `# ` prefix on disabled rules — the
Suricata convention).

NO AI: parsing is regex-only; if a line doesn't match it's surfaced as
'raw' and kept verbatim.
"""

from __future__ import annotations

import os
import re
import tempfile
import time
from dataclasses import dataclass, field
from typing import Optional

RULES_FILE = os.environ.get("W4RYA_RULES_FILE", "/app/suricata-rules/suricata.rules")
AUTO_SID_START = 1_000_000

# Pattern: action proto src_ip src_port -> dst_ip dst_port (...)
_RULE_RE = re.compile(
    r"^\s*"
    r"(?P<action>alert|drop|reject|pass|log|rejectsrc|rejectdst|rejectboth)\s+"
    r"(?P<proto>[A-Za-z0-9_-]+)\s+"
    r"(?P<src>\S+)\s+(?P<sport>\S+)\s+"
    r"(?P<dir>->|<-|<>)\s+"
    r"(?P<dst>\S+)\s+(?P<dport>\S+)\s+"
    r"\((?P<body>.*)\)\s*$"
)
_SID_RE = re.compile(r"sid\s*:\s*(\d+)")
_MSG_RE = re.compile(r'msg\s*:\s*"((?:[^"\\]|\\.)*)"')
_REV_RE = re.compile(r"rev\s*:\s*(\d+)")


@dataclass
class Rule:
    sid: int
    enabled: bool
    raw: str
    line_no: int = 0
    action: Optional[str] = None
    proto: Optional[str] = None
    src: Optional[str] = None
    sport: Optional[str] = None
    direction: Optional[str] = None
    dst: Optional[str] = None
    dport: Optional[str] = None
    msg: Optional[str] = None
    rev: Optional[int] = None
    parsed: bool = False

    def to_dict(self) -> dict:
        return {
            "sid": self.sid,
            "enabled": self.enabled,
            "raw": self.raw,
            "line_no": self.line_no,
            "action": self.action,
            "proto": self.proto,
            "src": self.src,
            "sport": self.sport,
            "direction": self.direction,
            "dst": self.dst,
            "dport": self.dport,
            "msg": self.msg,
            "rev": self.rev,
            "parsed": self.parsed,
        }


def parse_one(line: str, fallback_sid: int = 0) -> Optional[Rule]:
    """Parse a single rule line. Returns None for blank/comment-only lines."""
    stripped = line.strip()
    if not stripped:
        return None

    enabled = True
    body = stripped
    if stripped.startswith("#"):
        # Treat '# alert ...' as a disabled rule. Skip pure-comment '# foo bar'
        # that doesn't look like a Suricata rule.
        rest = stripped.lstrip("#").lstrip()
        if not _looks_like_rule(rest):
            return None
        enabled = False
        body = rest

    m = _RULE_RE.match(body)
    if not m:
        # Could be a real rule with exotic syntax we don't parse. Keep it as
        # raw + try to grab the sid so it has a stable id; otherwise assign
        # a fallback sid for the UI.
        sid_match = _SID_RE.search(body)
        sid = int(sid_match.group(1)) if sid_match else fallback_sid
        return Rule(sid=sid, enabled=enabled, raw=line.rstrip("\n"), parsed=False)

    sid_match = _SID_RE.search(m.group("body"))
    msg_match = _MSG_RE.search(m.group("body"))
    rev_match = _REV_RE.search(m.group("body"))
    sid = int(sid_match.group(1)) if sid_match else fallback_sid

    return Rule(
        sid=sid,
        enabled=enabled,
        raw=line.rstrip("\n"),
        action=m.group("action"),
        proto=m.group("proto"),
        src=m.group("src"),
        sport=m.group("sport"),
        direction=m.group("dir"),
        dst=m.group("dst"),
        dport=m.group("dport"),
        msg=msg_match.group(1) if msg_match else None,
        rev=int(rev_match.group(1)) if rev_match else None,
        parsed=True,
    )


def _looks_like_rule(text: str) -> bool:
    return bool(re.match(r"^(alert|drop|reject|pass|log)\s+\S+\s+\S+", text))


def load() -> list[Rule]:
    """Parse the rules file into a list of Rules. Missing file = empty list."""
    path = RULES_FILE
    if not os.path.exists(path):
        return []
    rules: list[Rule] = []
    fallback = -1
    with open(path) as f:
        for i, line in enumerate(f, start=1):
            r = parse_one(line, fallback_sid=fallback)
            if r is None:
                continue
            r.line_no = i
            if r.sid == fallback:
                fallback -= 1  # negative pseudo-sids for unparseable lines
            rules.append(r)
    return rules


def _atomic_write(path: str, content: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".rules.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def save(rules: list[Rule]) -> None:
    """Persist rules to disk in order, prepending '# ' on disabled ones."""
    lines: list[str] = []
    for r in rules:
        raw = r.raw.lstrip()
        if raw.startswith("#"):
            raw = raw.lstrip("#").lstrip()
        if r.enabled:
            lines.append(raw)
        else:
            lines.append("# " + raw)
    _atomic_write(RULES_FILE, "\n".join(lines) + ("\n" if lines else ""))


def next_sid(rules: list[Rule]) -> int:
    sids = [r.sid for r in rules if r.sid >= AUTO_SID_START]
    return (max(sids) + 1) if sids else AUTO_SID_START


def add(raw_text: str, enabled: bool = True, sid: Optional[int] = None) -> Rule:
    """Append a rule. If `raw_text` doesn't include a sid, one is auto-assigned."""
    current = load()
    if sid is None:
        sid_match = _SID_RE.search(raw_text)
        if sid_match:
            sid = int(sid_match.group(1))
        else:
            sid = next_sid(current)
            raw_text = _inject_sid(raw_text, sid)
    rule = parse_one(raw_text, fallback_sid=sid)
    if rule is None:
        raise ValueError("could not parse rule")
    rule.enabled = enabled
    rule.sid = sid
    current.append(rule)
    save(current)
    return rule


def update_one(sid: int, *, enabled: Optional[bool] = None, raw: Optional[str] = None) -> Optional[Rule]:
    """Patch a single rule by sid. Returns the updated rule or None if absent."""
    current = load()
    found: Optional[Rule] = None
    for i, r in enumerate(current):
        if r.sid == sid:
            if raw is not None:
                # Re-parse to refresh derived fields. Preserve enabled if not set.
                new_enabled = r.enabled if enabled is None else enabled
                new_rule = parse_one(raw, fallback_sid=sid)
                if new_rule is None:
                    raise ValueError("could not parse rule")
                new_rule.enabled = new_enabled
                new_rule.sid = sid
                current[i] = new_rule
                found = new_rule
            else:
                if enabled is not None:
                    r.enabled = enabled
                found = r
            break
    if found:
        save(current)
    return found


def delete(sid: int) -> bool:
    current = load()
    new = [r for r in current if r.sid != sid]
    if len(new) == len(current):
        return False
    save(new)
    return True


def block_ip(src_ip: str) -> Rule:
    """Quick-block: create a 'drop ip <src> any -> any any' rule."""
    src = src_ip.strip()
    if not src or any(c in src for c in '"();'):
        raise ValueError("invalid ip")
    current = load()
    sid = next_sid(current)
    msg = f"w4rya:block:{src}@{int(time.time())}"
    raw = (
        f'drop ip {src} any -> any any '
        f'(msg:"{msg}"; metadata: tag blocked; sid:{sid}; rev:1;)'
    )
    rule = parse_one(raw, fallback_sid=sid)
    if rule is None:
        raise ValueError("internal: generated rule did not parse")
    rule.enabled = True
    rule.sid = sid
    current.append(rule)
    save(current)
    return rule


def _inject_sid(raw: str, sid: int) -> str:
    """Ensure the raw text carries a sid directive. Inserts before final ')'.

    Only injects sid (and rev if missing) to avoid duplicating directives that
    were already present.

    D1: refuse to inject when parens look unbalanced. We do a naive count of
    raw `(` vs `)` which fails on edge cases (e.g. a literal `)` inside a
    content:"...)..." string with balanced quoting), but the cost is having
    the user paste a sid: themselves, not silently shifting rule semantics.
    """
    if _SID_RE.search(raw):
        return raw
    if raw.count("(") != raw.count(")"):
        raise ValueError(
            "rule has unbalanced parens; please include 'sid:N;' explicitly"
        )
    needs_rev = not _REV_RE.search(raw)
    extra = f" sid:{sid};" + (" rev:1;" if needs_rev else "")
    idx = raw.rfind(")")
    if idx == -1:
        # no body parens; append a minimal body
        return raw.rstrip() + f' ({extra.strip()})'
    body = raw[:idx].rstrip()
    if not body.endswith(";"):
        body += ";"
    return body + extra + raw[idx:]


# --- Templates -------------------------------------------------------------

TEMPLATES: list[dict] = [
    {
        "name": "alert: HTTP path traversal (../)",
        "raw": 'alert http any any -> any any (msg:"path traversal"; flow:to_server; content:"../"; http_uri; metadata: tag path_traversal; rev:1;)',
    },
    {
        "name": "alert: HTTP /etc/passwd in URI",
        "raw": 'alert http any any -> any any (msg:"/etc/passwd in URI"; flow:to_server; content:"/etc/passwd"; nocase; http_uri; metadata: tag passwd_leak; rev:1;)',
    },
    {
        "name": "alert: SQLi UNION SELECT",
        "raw": 'alert http any any -> any any (msg:"SQLi union select"; flow:to_server; content:"union"; nocase; content:"select"; nocase; pcre:"/union\\s+(all\\s+)?select/i"; metadata: tag sqli; rev:1;)',
    },
    {
        "name": "alert: shell metachar in body (potential RCE)",
        "raw": 'alert http any any -> any any (msg:"shell metachars in body"; flow:to_server; pcre:"/[;|&`$]/"; http_client_body; metadata: tag rce_candidate; rev:1;)',
    },
    {
        "name": "drop: known bad UA",
        "raw": 'drop http any any -> any any (msg:"bad UA: sqlmap"; flow:to_server; content:"sqlmap"; nocase; http_user_agent; metadata: tag blocked; rev:1;)',
    },
]
