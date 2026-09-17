"""Exploit replay for w4rya.

Given a captured flow, build the client-side payload (all `c` direction items
concatenated) and replay it against a set of enemy team IPs on the original
destination port. Capture responses, regex-match the configured flag pattern,
return a per-target summary.

Also exposes a script generator that emits a standalone Python replayer
(payload embedded as hex) for use in the team's exploit farm.

NO AI: matching is plain `re.findall` against the user-configured flag_regex.
"""

from __future__ import annotations

import copy
import json
import os
import re
import socket
import time
import urllib.parse
import uuid
from concurrent.futures import ThreadPoolExecutor, wait, ALL_COMPLETED
from dataclasses import dataclass
from typing import Optional

import app_config
import rules

DEFAULT_TIMEOUT = 3.0
MAX_TIMEOUT = 15.0
MAX_RECV_BYTES = 256 * 1024
EXCERPT_BYTES = 1024
MAX_TARGETS = 64
# Hard ceiling for the whole replay call. Must stay well under gunicorn's -t
# (currently 60s in Dockerfile-api) so worker doesn't get killed mid-replay.
OVERALL_DEADLINE_SEC = 45.0


@dataclass
class ReplayResult:
    team_name: str
    target_ip: str
    ok: bool
    latency_ms: int = 0
    response_size: int = 0
    response_excerpt: str = ""
    flags: Optional[list[str]] = None
    error: Optional[str] = None

    def to_dict(self) -> dict:
        d = {
            "team_name": self.team_name,
            "target_ip": self.target_ip,
            "ok": self.ok,
            "latency_ms": self.latency_ms,
            "response_size": self.response_size,
            "response_excerpt": self.response_excerpt,
        }
        if self.flags is not None:
            d["flags"] = self.flags
            d["flag_count"] = len(self.flags)
        if self.error:
            d["error"] = self.error
        return d


def build_payload(flow) -> bytes:
    """Concatenate every client→server raw item from a flow."""
    if not flow or not flow.items:
        return b""
    return b"".join(
        item.data
        for item in flow.items
        if item.direction == "c" and item.kind == "raw"
    )


_HOST_HEADER_RE = re.compile(rb"(?im)^Host:[ \t]*[^\r\n]*\r?\n")


def rewrite_host_header(payload: bytes, ip: str, port: int) -> bytes:
    """Point an HTTP request's Host header at the actual replay target
    instead of whatever host it was originally captured against.

    Without this, replaying a captured request byte-for-byte against a
    different team sends the ORIGINAL capture's Host header — harmless
    against a bare IP:port test service, but a silent failure against
    anything that routes by vhost (nginx `server_name`, most real web
    stacks). No-op if the payload has no Host header (non-HTTP, or a
    request line-less payload) — never invents one.
    """
    if not _HOST_HEADER_RE.search(payload):
        return payload
    host_value = f"{ip}:{port}" if port not in (80, 443) else ip
    return _HOST_HEADER_RE.sub(f"Host: {host_value}\r\n".encode(), payload, count=1)


def _replay_one(team_name: str, ip: str, port: int, payload: bytes,
                timeout: float, flag_re: re.Pattern[bytes],
                rewrite_host: bool = False) -> ReplayResult:
    start = time.monotonic()
    if rewrite_host:
        payload = rewrite_host_header(payload, ip, port)
    try:
        sock = socket.create_connection((ip, port), timeout=timeout)
        sock.settimeout(timeout)
        try:
            sock.sendall(payload)
        except OSError as e:
            return ReplayResult(team_name, ip, ok=False, error=f"send: {e!s}")

        chunks: list[bytes] = []
        total = 0
        try:
            while True:
                buf = sock.recv(8192)
                if not buf:
                    break
                chunks.append(buf)
                total += len(buf)
                if total >= MAX_RECV_BYTES:
                    break
        except socket.timeout:
            pass  # timeout is the expected end-of-stream signal for many protocols
        except OSError as e:
            return ReplayResult(team_name, ip, ok=False, error=f"recv: {e!s}")
        finally:
            try:
                sock.close()
            except OSError:
                pass

        body = b"".join(chunks)
        elapsed_ms = int((time.monotonic() - start) * 1000)
        flags = [
            m.decode("latin-1", errors="replace") for m in flag_re.findall(body)
        ]
        excerpt_bytes = body[:EXCERPT_BYTES]
        return ReplayResult(
            team_name=team_name,
            target_ip=ip,
            ok=True,
            latency_ms=elapsed_ms,
            response_size=len(body),
            response_excerpt=excerpt_bytes.decode("latin-1", errors="replace"),
            flags=flags,
        )
    except (socket.gaierror, OSError) as e:
        return ReplayResult(team_name, ip, ok=False, error=f"{type(e).__name__}: {e!s}")


def replay(flow, targets: list[dict], timeout: float = DEFAULT_TIMEOUT,
           rewrite_host: bool = False) -> dict:
    """Replay `flow`'s client payload against each target.

    `targets`: list of {"name": str, "ip": str}
    """
    return replay_payload(
        build_payload(flow), int(flow.port_dst), targets, timeout=timeout,
        result_id=str(flow.id), rewrite_host=rewrite_host,
    )


def replay_payload(
    payload: bytes, port: int, targets: list[dict],
    timeout: float = DEFAULT_TIMEOUT, result_id: str | None = None,
    rewrite_host: bool = False,
) -> dict:
    """Same replay loop as `replay()`, taking raw bytes + port directly
    instead of a live Flow — what a saved exploit-library entry replays
    against, since it has no Flow object of its own (the payload was
    snapshotted at save time).

    `rewrite_host`: point each target connection's Host header (if any) at
    that target's own ip:port rather than the byte-for-byte captured one —
    see `rewrite_host_header`. Callers pass False when the caller (or an
    operator's manual edit) already controls the exact bytes to send.
    """
    targets = targets[:MAX_TARGETS]
    timeout = max(0.5, min(MAX_TIMEOUT, timeout))

    flag_pattern = app_config.get("flag_regex") or ""
    try:
        flag_re = re.compile(flag_pattern.encode())
    except re.error:
        flag_re = re.compile(rb"$.^")  # never matches

    if not payload or not targets:
        return {
            "flow_id": result_id,
            "port": port,
            "payload_size": len(payload),
            "results": [],
        }

    workers = min(16, len(targets))
    # D1: overall deadline so a few slow targets can't pin a gunicorn worker
    # for longer than the worker timeout (-t in Dockerfile-api).
    deadline = min(
        OVERALL_DEADLINE_SEC,
        max(timeout * 3, timeout + 5),
    )
    deadline_at = time.monotonic() + deadline
    with ThreadPoolExecutor(max_workers=workers) as ex:
        fut_map: dict = {}
        for t in targets:
            if not t.get("ip"):
                continue
            name = str(t.get("name") or t["ip"])
            ip = str(t["ip"])
            f = ex.submit(_replay_one, name, ip, port, payload, timeout, flag_re, rewrite_host)
            fut_map[f] = (name, ip)

        remaining = max(0.5, deadline_at - time.monotonic())
        done, undone = wait(fut_map.keys(), timeout=remaining, return_when=ALL_COMPLETED)
        results: list[ReplayResult] = [f.result() for f in done]
        for f in undone:
            f.cancel()
            name, ip = fut_map[f]
            results.append(ReplayResult(
                team_name=name,
                target_ip=ip,
                ok=False,
                error="deadline exceeded — overall replay budget hit",
            ))

    return {
        "flow_id": result_id,
        "port": port,
        "payload_size": len(payload),
        "timeout_s": timeout,
        "overall_deadline_s": deadline,
        "results": [r.to_dict() for r in results],
    }


_ET_OPEN_RULES_FILE = os.path.join(os.path.dirname(rules.RULES_FILE), "et-open", "suricata.rules")

_CONTENT_TOKEN_RE = re.compile(r'^content\s*:\s*(!)?\s*"((?:[^"\\]|\\.)*)"\s*$')
_REQUEST_LINE_RE = re.compile(rb"^([A-Z]{3,10}) (\S+) HTTP/\d\.\d")
_HEADER_LINE_RE = re.compile(rb"(?im)^([A-Za-z0-9-]+):[ \t]*([^\r\n]*)")

# Suricata "sticky buffer" keywords (new dot-style, set the active buffer for
# every content: that follows) mapped to the buffer names _clause_matches
# knows how to extract from a raw item's bytes. Anything not in this map
# (http.header, http.cookie's less-common siblings, file.data, dns.query,
# tls.*, ...) is a buffer we can't safely re-derive per-item — encountering
# one bails the whole rule out of isolation (see the bail-out comment below).
_DOT_BUFFER_MAP = {
    "http.uri": "uri",
    "http.uri.raw": "uri",
    "http.method": "method",
    "http.request_body": "request_body",
    "http.user_agent": "user_agent",
    "http.host": "host",
    "http.cookie": "cookie",
}
# Old-style postfix modifiers (apply BACKWARD to the content immediately
# preceding them) — same buffer coverage as above, same reasoning.
_POSTFIX_BUFFER_MAP = {
    "http_uri": "uri",
    "http_raw_uri": "uri",
    "http_method": "method",
    "http_client_body": "request_body",
    "http_user_agent": "user_agent",
    "http_host": "host",
    "http_cookie": "cookie",
}
# Bare (argument-less) rule-option keywords safe to see without changing the
# active buffer or forcing a bail — anything else bare and unrecognized is
# assumed to be a buffer-scoping keyword we don't understand.
_SAFE_BARE_MODIFIERS = {"nocase", "endswith", "startswith", "fast_pattern", "rawbytes"}


def _decode_suricata_content_value(value: str) -> bytes:
    """Suricata content strings mix literal text with `|hex bytes|` runs
    (e.g. `x|00|p|00|_|00|cmdshell` from the MSSQL rule) and backslash
    escapes. Decode to the actual byte sequence Suricata would match."""
    out = bytearray()
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "|":
            end = value.index("|", i + 1)
            out += bytes.fromhex(value[i + 1:end].replace(" ", ""))
            i = end + 1
        elif ch == "\\" and i + 1 < len(value):
            out += value[i + 1].encode("latin-1", errors="replace")
            i += 2
        else:
            out += ch.encode("latin-1", errors="replace")
            i += 1
    return bytes(out)


def _tokenize_rule_options(body: str) -> list[str]:
    """Split a rule's parenthesized option body on ';', respecting quoted
    strings — a content pattern can itself contain characters (including
    literal `;`) that would otherwise look like option syntax."""
    tokens: list[str] = []
    current: list[str] = []
    in_quotes = False
    i = 0
    while i < len(body):
        ch = body[i]
        if ch == "\\" and i + 1 < len(body):
            current.append(ch)
            current.append(body[i + 1])
            i += 2
            continue
        if ch == '"':
            in_quotes = not in_quotes
            current.append(ch)
            i += 1
            continue
        if ch == ";" and not in_quotes:
            tok = "".join(current).strip()
            if tok:
                tokens.append(tok)
            current = []
            i += 1
            continue
        current.append(ch)
        i += 1
    tok = "".join(current).strip()
    if tok:
        tokens.append(tok)
    return tokens


def _parse_rule_content_clauses(line: str) -> Optional[list[tuple[bytes, str, str]]]:
    """Walk a rule's option list token by token, tracking which HTTP buffer
    (uri/method/request_body/user_agent/host/cookie/"pkt" for the raw
    packet — Suricata's default with no sticky buffer active) is active for
    each `content:"..."` clause, exactly as Suricata's own parser would.

    This is the part that makes isolation trustworthy: a rule can require
    a pattern to appear specifically in the URI (`http.uri`/`http_uri`)
    while other rule text — headers, cookies, the body — is irrelevant to
    that clause. Matching the pattern against an item's *entire* raw bytes
    instead (the naive approach) produces false matches whenever the
    pattern also happens to appear somewhere else, e.g. a session where
    every authenticated request carries a `Cookie: auth-token=...` header
    — a clause meant to check the URI for `token=` would then spuriously
    match every authenticated request, not just the one whose *URI*
    actually contains a token parameter.

    Bails (returns None) the moment it sees ANY buffer-scoping keyword this
    function doesn't know how to re-derive from a raw item's bytes —
    guessing wrong would silently score the wrong item as "the" match,
    which is worse than not isolating at all.
    """
    paren_start = line.find("(")
    paren_end = line.rfind(")")
    if paren_start == -1 or paren_end == -1 or paren_end <= paren_start:
        return None
    tokens = _tokenize_rule_options(line[paren_start + 1:paren_end])

    clauses: list[tuple[bytes, str, str]] = []
    current_buffer = "pkt"
    i, n = 0, len(tokens)
    while i < n:
        tok = tokens[i]

        if tok in _DOT_BUFFER_MAP:
            current_buffer = _DOT_BUFFER_MAP[tok]
            i += 1
            continue

        m = _CONTENT_TOKEN_RE.match(tok)
        if m:
            negated, value = m.group(1), m.group(2)
            if negated:
                return None  # a "must NOT contain" clause has nothing to positively isolate on
            pattern = _decode_suricata_content_value(value).lower()
            buffer = current_buffer
            mode = "contains"
            j = i + 1
            while j < n:
                nxt = tokens[j]
                if nxt in _POSTFIX_BUFFER_MAP:
                    buffer = _POSTFIX_BUFFER_MAP[nxt]
                elif nxt == "endswith":
                    mode = "endswith"
                elif nxt == "startswith":
                    mode = "startswith"
                else:
                    break
                j += 1
            clauses.append((pattern, mode, buffer))
            i = j
            continue

        if tok in _SAFE_BARE_MODIFIERS or tok in _POSTFIX_BUFFER_MAP or ":" in tok:
            i += 1
            continue

        # Bare and unrecognized: likely a buffer-scoping keyword we don't
        # support (http.header, file.data, dns.query, ...). Bail rather
        # than assume it's harmless.
        return None

    return clauses or None


def rule_content_clauses(sid: int) -> Optional[list[tuple[bytes, str, str]]]:
    """Best-effort extraction of a rule's literal `content:"..."` clauses by
    sid, as (pattern_bytes, mode, buffer) triples — checked against both our
    own rules and the ET Open file. `mode` is "endswith"/"startswith"/
    "contains"; `buffer` is which part of the request the pattern must
    appear in (see `_parse_rule_content_clauses`). Returns None if the sid
    isn't found, the rule has no plain content match (pcre-only/
    flowbit-only rules aren't something we can cheaply re-evaluate in
    Python), or any clause is scoped to a buffer we can't re-derive —
    callers treat all of that as "can't isolate"."""
    needle = f"sid:{sid};"
    for path in (rules.RULES_FILE, _ET_OPEN_RULES_FILE):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if needle not in line or line.lstrip().startswith("#"):
                        continue
                    return _parse_rule_content_clauses(line)
        except OSError:
            continue
    return None


def _item_uri(data: bytes) -> Optional[bytes]:
    """Full request-target (path + `?query`, if any) — matches what
    Suricata's `http.uri`/`http_uri` buffer covers. Must NOT strip the
    query string: a clause like `content:"token="; http_uri;` only ever
    matches via the query part."""
    m = _REQUEST_LINE_RE.match(data)
    return m.group(2) if m else None


def _item_method(data: bytes) -> Optional[bytes]:
    m = _REQUEST_LINE_RE.match(data)
    return m.group(1) if m else None


def _split_request_headers(data: bytes) -> tuple[bytes, bytes]:
    """(header_block_including_request_line, body) split on the first blank
    line. Returns (data, b"") if there's no blank-line terminator."""
    idx = data.find(b"\r\n\r\n")
    sep_len = 4
    if idx == -1:
        idx = data.find(b"\n\n")
        sep_len = 2
    if idx == -1:
        return data, b""
    return data[:idx], data[idx + sep_len:]


def _item_body(data: bytes) -> Optional[bytes]:
    _, body = _split_request_headers(data)
    return body


def _item_header(data: bytes, name: bytes) -> Optional[bytes]:
    header_block, _ = _split_request_headers(data)
    name_lower = name.lower()
    for m in _HEADER_LINE_RE.finditer(header_block):
        if m.group(1).lower() == name_lower:
            return m.group(2)
    return None


_BUFFER_EXTRACTORS = {
    "uri": _item_uri,
    "method": _item_method,
    "request_body": _item_body,
    "user_agent": lambda d: _item_header(d, b"user-agent"),
    "host": lambda d: _item_header(d, b"host"),
    "cookie": lambda d: _item_header(d, b"cookie"),
}


def _clause_matches(data: bytes, pattern: bytes, mode: str, buffer: str) -> bool:
    if buffer == "pkt":
        haystack = data.lower()
    else:
        value = _BUFFER_EXTRACTORS[buffer](data)
        if value is None:
            return False
        haystack = value.lower()
    if mode == "endswith":
        return haystack.endswith(pattern)
    if mode == "startswith":
        return haystack.startswith(pattern)
    return pattern in haystack


# Past this many genuinely-distinct matches, listing every one of them in
# the generated script stops being "the exploit, isolated" and starts being
# "most of the session again" — collapse to a single representative instead
# (see find_exploit_item's docstring).
_MAX_MATCHED_ITEMS = 5


def find_exploit_item(
    flow, sid: Optional[int]
) -> tuple[Optional[int] | list[int], str]:
    """Which client item(s) in `flow` are *the* malicious request(s), if we
    can tell. Returns (item_index, basis):

    - "single_item": `item_index` is a single int. Either exactly one
      client item matched (or a flow with only one client item counts as
      trivially isolated too); or every item that matched is byte-identical
      to the others (a replayed/brute-forced request fired the rule N
      times — there is no meaningful difference between "request 3 of 40"
      and "request 37 of 40", so the first occurrence stands in for all of
      them); or MORE than `_MAX_MATCHED_ITEMS` items matched and they're
      NOT all identical (e.g. a scanner retrying the same exploit template
      with a fresh random identifier each attempt, 100 times over) — past
      that count, listing every distinct variant stops being useful, so
      the first occurrence stands in as a representative the same way a
      dedup does.
    - "matched_items": `item_index` is a list of ints (bounded to at most
      `_MAX_MATCHED_ITEMS`) — more than one client item matched and they
      are NOT all identical, i.e. genuinely distinct requests that
      both/all satisfied the rule (e.g. a two-stage attack like MSSQL's
      "enable xp_cmdshell" followed by "run xp_cmdshell" — both packets
      legitimately contain the rule's content match, and dropping either
      one would silently lose part of the actual attack).
    - "full_flow": `item_index` is None — couldn't isolate at all (no sid,
      no content clauses, or genuinely zero matches).

    Closes the loop for the "just give me the one request that matters"
    button: a w4rya flow can bundle a whole multi-request session (signup,
    signin, the actual exploit, cleanup...) under one flow_id, and
    build_payload()/the exploit-script generators use ALL of it by default.
    This re-checks the firing rule's own content clauses against each
    client item — matched against the SAME buffer Suricata itself scoped
    the check to (URI, method, body, a specific header, ...), not just
    "anywhere in the raw bytes". That scoping is load-bearing: on a real
    captured session, "URI contains /api/sheets/ AND URI contains token="
    (rule 1000008) needs to stay scoped to the URI, because unscoped every
    authenticated request also carries `Cookie: auth-token=...` — which
    contains the substring "token=" too, and would falsely match requests
    that have nothing to do with the actual IDOR.
    """
    client_indices = [
        i for i, item in enumerate(flow.items)
        if item.direction == "c" and item.kind == "raw"
    ]
    if len(client_indices) <= 1:
        return (client_indices[0], "single_item") if client_indices else (None, "full_flow")
    if sid is None:
        return (None, "full_flow")
    clauses = rule_content_clauses(sid)
    if not clauses:
        return (None, "full_flow")
    matches = [
        i for i in client_indices
        if all(_clause_matches(flow.items[i].data, pattern, mode, buffer) for pattern, mode, buffer in clauses)
    ]
    if not matches:
        return (None, "full_flow")
    if len(matches) == 1:
        return (matches[0], "single_item")
    unique_payloads = {flow.items[i].data for i in matches}
    if len(unique_payloads) == 1 or len(matches) > _MAX_MATCHED_ITEMS:
        return (matches[0], "single_item")
    return (matches, "matched_items")


def narrow_flow_to_items(flow, indices: list[int]):
    """A shallow copy of `flow` whose `.items` is restricted to just
    `indices` (client items only, in order) — for the "matched_items" case,
    so the existing flow-wide code generators (`convert_flow_to_http_requests`,
    `flow2pwn`, both of which only look at `direction == "c"` items) emit
    code for just the isolated attack steps instead of the whole session.
    Deliberately drops server items rather than including the ones that
    originally followed each matched request: those generators use a
    server item only to `recvuntil` its last bytes as a sync marker before
    the *next* write, which would try to sync against a response to a
    request we already excluded. Writing the matched requests back-to-back
    with no synchronization is the right behavior for an isolated replay.

    Uses `copy.copy` rather than `dataclasses.replace` so this works on any
    flow-shaped object (production's slotted `FlowDetail` dataclass, but
    also the plain test doubles in tests/), not just a "real" dataclass
    instance."""
    narrowed = copy.copy(flow)
    narrowed.items = [flow.items[i] for i in indices]
    return narrowed


def describe_endpoint(data: bytes) -> Optional[str]:
    """"METHOD /path" (query string stripped) for a client item, or None if
    it doesn't look like an HTTP request. What the patching team actually
    needs first: not a payload dump, a specific route to go look at."""
    method = _item_method(data)
    uri = _item_uri(data)
    if method is None or uri is None:
        return None
    path = uri.split(b"?", 1)[0]
    return f"{method.decode('latin-1', errors='replace')} {path.decode('latin-1', errors='replace')}"


def _truncate(s: str, limit: int = 300) -> str:
    return s if len(s) <= limit else s[:limit] + "…"


def _find_pair_containing(pairs: list[tuple[str, str]], pattern_lower: str) -> Optional[tuple[str, str]]:
    """Match `pattern_lower` against a (key, value) pair's value alone, OR
    its "key=value" form — a Suricata content clause for a query
    parameter/form field/cookie is often written to include the key itself
    (e.g. `content:"token="`, matching the parameter's presence, not just
    its value), which wouldn't appear as a substring of the value alone."""
    for key, value in pairs:
        if pattern_lower in value.lower() or pattern_lower in f"{key}={value}".lower():
            return key, value
    return None


def _find_in_query(uri: bytes, pattern: bytes) -> Optional[tuple[str, str]]:
    if b"?" not in uri:
        return None
    query = uri.split(b"?", 1)[1].decode("utf-8", errors="replace")
    try:
        pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    except ValueError:
        return None
    return _find_pair_containing(pairs, pattern.decode("latin-1", errors="replace").lower())


def _flatten_json(obj, prefix: str = "") -> list[tuple[str, str]]:
    """Depth-first (key-path, stringified-value) pairs out of a parsed JSON
    body — deep enough to find a field nested inside a request "shape"
    (e.g. {"user": {"role": "admin"}}) without trying to be a general
    JSON-path implementation."""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            out.extend(_flatten_json(value, f"{prefix}{key}."))
    elif isinstance(obj, list):
        for idx, item in enumerate(obj):
            out.extend(_flatten_json(item, f"{prefix}{idx}."))
    elif obj is not None:
        out.append((prefix.rstrip("."), str(obj)))
    return out


def _find_in_body(body: bytes, pattern: bytes) -> Optional[tuple[str, str]]:
    pattern_lower = pattern.decode("latin-1", errors="replace").lower()
    text = body.decode("utf-8", errors="replace")
    try:
        parsed_json = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        parsed_json = None
    if parsed_json is not None:
        found = _find_pair_containing(_flatten_json(parsed_json), pattern_lower)
        if found:
            return found
    try:
        pairs = urllib.parse.parse_qsl(text, keep_blank_values=True, strict_parsing=True)
    except ValueError:
        pairs = []
    return _find_pair_containing(pairs, pattern_lower)


def _find_in_cookie(cookie_header: bytes, pattern: bytes) -> Optional[tuple[str, str]]:
    pattern_lower = pattern.decode("latin-1", errors="replace").lower()
    text = cookie_header.decode("utf-8", errors="replace")
    pairs = []
    for part in text.split(";"):
        if "=" not in part:
            continue
        name, _, value = part.strip().partition("=")
        pairs.append((name, value))
    return _find_pair_containing(pairs, pattern_lower)


def locate_vulnerable_input(data: bytes, clauses: list[tuple[bytes, str, str]]) -> list[dict]:
    """Best-effort: for each of the firing rule's content clauses, pinpoint
    WHERE in this item the pattern actually landed — a query parameter
    name, a JSON/form body field, a specific cookie — not just "the URI"
    or "the body" in the abstract. This is what turns an alert into
    something a patching team can act on without any source-code mapping:
    "the exploit rides in the `token` query parameter" tells them exactly
    which input handler to go audit.

    Returns a list of {"buffer", "location", "value"} dicts, deduplicated
    by location, in clause order. A clause whose buffer we can extract but
    can't narrow further than "the whole URI"/"the whole body" still gets
    a generic location rather than being dropped — the patching team is
    never left with nothing to go on. `method` clauses are skipped (they
    confirm the HTTP verb, not an input worth flagging).
    """
    seen: set[str] = set()
    results: list[dict] = []
    for pattern, _mode, buffer in clauses:
        location: Optional[str] = None
        value: Optional[str] = None

        if buffer == "method":
            continue
        elif buffer == "uri":
            uri = _item_uri(data)
            if uri is not None:
                found = _find_in_query(uri, pattern)
                if found:
                    location, value = f'query parameter "{found[0]}"', found[1]
                else:
                    path = uri.split(b"?", 1)[0]
                    if pattern in path.lower():
                        location = "URI path"
                        value = path.decode("utf-8", errors="replace")
                    else:
                        location = "URI"
                        value = uri.decode("utf-8", errors="replace")
        elif buffer == "request_body":
            body = _item_body(data)
            if body is not None:
                found = _find_in_body(body, pattern)
                if found:
                    location, value = f'body field "{found[0]}"', found[1]
                else:
                    location = "request body"
                    value = body.decode("utf-8", errors="replace")
        elif buffer == "cookie":
            header_val = _item_header(data, b"cookie")
            if header_val is not None:
                found = _find_in_cookie(header_val, pattern)
                if found:
                    location, value = f'cookie "{found[0]}"', found[1]
                else:
                    location = "Cookie header"
                    value = header_val.decode("utf-8", errors="replace")
        elif buffer == "user_agent":
            header_val = _item_header(data, b"user-agent")
            if header_val is not None:
                location = "User-Agent header"
                value = header_val.decode("utf-8", errors="replace")
        elif buffer == "host":
            header_val = _item_header(data, b"host")
            if header_val is not None:
                location = "Host header"
                value = header_val.decode("utf-8", errors="replace")
        elif buffer == "pkt":
            location = "request (not narrowed to a specific field)"
            value = None

        if location is None or location in seen:
            continue
        seen.add(location)
        results.append({
            "buffer": buffer,
            "location": location,
            "value": _truncate(value) if value is not None else None,
        })
    return results


def is_http_request(data: bytes) -> bool:
    """Whether `data` looks like the start of an HTTP request — gates which
    exploit-code generator is safe to use. `data2req.py`'s HTTP converters
    (`convert_single_http_requests`/`convert_flow_to_http_requests`) assume
    every item they're handed parses as an HTTP request line; fed a raw
    non-HTTP payload (a CTF service on a bare TCP port, no HTTP framing —
    real example: a "Redact-service" rule on port 5151, matched on server
    response text, so `find_exploit_item` never isolates to a client item
    that "matches" it either) they crash (`AttributeError` from
    `.lower()`ing a `None` HTTP method) instead of degrading."""
    return _REQUEST_LINE_RE.match(data) is not None


_RAW_SOCKET_TEMPLATE = """import os
import socket

HOST = os.getenv('TARGET_IP')
PORT = {port}

sock = socket.create_connection((HOST, PORT), timeout=5)
sock.sendall({payload!r})
sock.settimeout(3)
try:
    data = sock.recv(65536)
    print(data)
except socket.timeout:
    pass
sock.close()
"""


def raw_socket_snippet(payload: bytes, port: int) -> str:
    """Fallback exploit code for a non-HTTP payload: plain socket
    connect/send/recv, no protocol assumed. Always produces something
    runnable — the safety net under `is_http_request`'s gate, so "📋 Copy
    Exploit" never hard-fails just because the target isn't speaking HTTP."""
    return _RAW_SOCKET_TEMPLATE.format(port=port, payload=payload)


def suggest_rule(flow) -> dict:
    """Draft a Suricata rule from a flow's captured client payload.

    Closes the loop the monitoring team actually wants: attack finds an
    exploit and replays it here (or just captures it live); this turns that
    same payload into a starting-point signature instead of someone
    hand-typing content/pcre syntax under match pressure. It is a DRAFT —
    the caller reviews/edits before POSTing it to /rules.

    Heuristic: an HTTP request line anchors the rule on the URI path (far
    fewer false positives than matching raw bytes, since path is usually
    stable across requests while bodies/tokens vary). Anything else falls
    back to a hex content match on the first bytes of the payload.
    """
    payload = build_payload(flow)
    port = int(flow.port_dst)
    if not payload:
        return {"raw": None, "reason": "no client payload captured on this flow"}

    m = re.match(rb"([A-Z]{3,10}) (\S+) HTTP/\d\.\d", payload[:2048])
    if m:
        method = m.group(1).decode("latin-1", errors="replace")
        uri = m.group(2).decode("latin-1", errors="replace")
        path = uri.split("?", 1)[0]
        # Quotes/backslashes would break the content string; strip rather
        # than try to escape them correctly for every downstream parser.
        path = path.replace('"', "").replace("\\", "")[:200] or "/"
        msg = f"suggested: {method} {path} on port {port}".replace('"', "")
        raw = (
            f'alert http any any -> any {port} (msg:"{msg}"; flow:to_server; '
            f'http.method; content:"{method}"; http.uri; content:"{path}"; '
            f'metadata: tag suggested_from_flow; rev:1;)'
        )
        return {"raw": raw, "basis": "http_uri", "port": port, "matched": path}

    sample = payload[:32]
    hex_bytes = " ".join(f"{b:02x}" for b in sample)
    msg = f"suggested: raw payload match on port {port}"
    raw = (
        f'alert tcp any any -> any {port} (msg:"{msg}"; flow:to_server; '
        f'content:"|{hex_bytes}|"; metadata: tag suggested_from_flow; rev:1;)'
    )
    return {"raw": raw, "basis": "raw_bytes", "port": port, "matched": sample.hex()}


# --- Script generator ------------------------------------------------------

_SCRIPT_TEMPLATE = '''\
#!/usr/bin/env python3
"""Auto-generated by w4rya from flow {flow_id}.

Replays the captured client payload against every TEAM listed below.
Prints any flag matches per team. Drop this into your exploit farm and
adapt main() to whatever submission protocol you use.

NO external dependencies — stdlib only.
"""
import re
import socket
import sys

# (name, ip) — edit / extend as needed.
TEAMS = {teams_repr}

PORT = {port}
TIMEOUT = {timeout}
MAX_RECV_BYTES = {max_recv}
FLAG_RE = re.compile(rb"{flag_regex}")

# Captured request payload (client -> server bytes).
PAYLOAD = bytes.fromhex(
{payload_hex}
)


def replay(name: str, ip: str):
    try:
        sock = socket.create_connection((ip, PORT), timeout=TIMEOUT)
        sock.settimeout(TIMEOUT)
        sock.sendall(PAYLOAD)
        chunks = []
        total = 0
        try:
            while True:
                buf = sock.recv(8192)
                if not buf:
                    break
                chunks.append(buf)
                total += len(buf)
                if total >= MAX_RECV_BYTES:
                    break
        except socket.timeout:
            pass
        sock.close()
        body = b"".join(chunks)
    except OSError as e:
        print(f"[!] {{name:20s}} {{ip:15s}}  err: {{e}}", file=sys.stderr)
        return []
    flags = [m.decode("latin-1", errors="replace") for m in FLAG_RE.findall(body)]
    if flags:
        print(f"[+] {{name:20s}} {{ip:15s}}  FLAGS={{flags!r}}")
    else:
        print(f"[ ] {{name:20s}} {{ip:15s}}  no flag in {{len(body)}}B response")
    return flags


def main():
    captured = []
    for name, ip in TEAMS:
        for f in replay(name, ip):
            captured.append((name, ip, f))
    # TODO: pipe `captured` into your farm/submitter here.
    print(f"\\n[w4rya] captured {{len(captured)}} flag(s) total", file=sys.stderr)


if __name__ == "__main__":
    main()
'''


def _hex_block(data: bytes, width: int = 32) -> str:
    """Wrap hex into nicely-indented lines for the generated script."""
    h = data.hex()
    lines: list[str] = []
    chars_per_line = width * 2
    for i in range(0, len(h), chars_per_line):
        chunk = h[i : i + chars_per_line]
        lines.append(f'    "{chunk}"')
    if not lines:
        lines.append('    ""')
    return "\n".join(lines)


def generate_script(flow, teams: list[dict], timeout: float = DEFAULT_TIMEOUT) -> str:
    return generate_script_from_payload(
        build_payload(flow), int(flow.port_dst), str(flow.id), teams, timeout=timeout,
    )


def generate_script_from_payload(
    payload: bytes, port: int, script_id: str, teams: list[dict],
    timeout: float = DEFAULT_TIMEOUT,
) -> str:
    """Same generator as `generate_script()`, taking raw bytes + port
    directly — what a saved exploit-library entry uses, since it has no
    live Flow object (the payload was snapshotted at save time)."""
    flag_pattern = app_config.get("flag_regex") or ""

    team_tuples = []
    for t in teams:
        name = str(t.get("name") or "team").replace('"', "'")
        ip = str(t.get("ip") or "")
        if not ip:
            continue
        team_tuples.append((name, ip))
    teams_repr = "[\n" + "\n".join(
        f'    ("{n}", "{ip}"),' for n, ip in team_tuples
    ) + "\n]" if team_tuples else "[]"

    flag_for_re = flag_pattern.replace('\\', '\\\\').replace('"', '\\"')

    return _SCRIPT_TEMPLATE.format(
        flow_id=script_id,
        teams_repr=teams_repr,
        port=port,
        timeout=timeout,
        max_recv=MAX_RECV_BYTES,
        flag_regex=flag_for_re,
        payload_hex=_hex_block(payload),
    )
