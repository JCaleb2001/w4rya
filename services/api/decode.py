"""Deterministic payload decoding for captured flow items.

NO AI: every decode here is a stdlib transform (base64/hex/url/gzip/zlib)
gated by a plain heuristic (does the input look like this encoding, does the
output look like text). The point is to save the monitoring team the manual
step of copy-pasting a blob into CyberChef/a Python shell to see what an
attacker actually sent — auto-decode it inline, recursively, and show every
layer.
"""

from __future__ import annotations

import base64
import gzip
import re
import urllib.parse
import zlib

MAX_DEPTH = 4
MAX_PREVIEW = 4096

_BASE64_RE = re.compile(rb"^[A-Za-z0-9+/_=\-]{8,}$")
_HEX_RE = re.compile(rb"^(?:[0-9a-fA-F]{2}){4,}$")


def _looks_texty(data: bytes, threshold: float = 0.85) -> bool:
    if not data:
        return False
    printable = sum(1 for b in data if 32 <= b < 127 or b in (9, 10, 13))
    return (printable / len(data)) >= threshold


def try_gzip(data: bytes) -> bytes | None:
    try:
        out = gzip.decompress(data)
    except Exception:
        return None
    return out if out else None


def try_deflate(data: bytes) -> bytes | None:
    for wbits in (zlib.MAX_WBITS, -zlib.MAX_WBITS):
        try:
            out = zlib.decompress(data, wbits)
            if out:
                return out
        except Exception:
            continue
    return None


def try_base64(data: bytes) -> bytes | None:
    text = data.strip()
    if not _BASE64_RE.fullmatch(text):
        return None
    for decoder in (base64.b64decode, base64.urlsafe_b64decode):
        try:
            padded = text + b"=" * (-len(text) % 4)
            out = decoder(padded, validate=False)
        except Exception:
            continue
        if out and (_looks_texty(out) or out[:2] in (b"\x1f\x8b", b"PK")):
            return out
    return None


def try_hex(data: bytes) -> bytes | None:
    text = data.strip()
    if not _HEX_RE.fullmatch(text):
        return None
    try:
        out = bytes.fromhex(text.decode("ascii"))
    except Exception:
        return None
    return out if _looks_texty(out) else None


def try_url_decode(data: bytes) -> bytes | None:
    text = data.decode("latin-1", errors="ignore")
    if "%" not in text:
        return None
    try:
        out = urllib.parse.unquote(text, errors="strict")
    except Exception:
        return None
    if out == text:
        return None
    return out.encode("latin-1", errors="replace")


# Order matters: try structural formats (compression) before text-ish
# encodings, since a base64 blob that decodes to gzip bytes should be
# reported as "base64 -> gzip", not misfire as some other transform first.
_DECODERS: list[tuple[str, "callable[[bytes], bytes | None]"]] = [
    ("gzip", try_gzip),
    ("deflate", try_deflate),
    ("base64", try_base64),
    ("hex", try_hex),
    ("url", try_url_decode),
]


_CANDIDATE_RE = re.compile(rb"[A-Za-z0-9+/_\-]{20,}={0,2}")


def find_embedded_encodings(data: bytes, min_len: int = 20) -> list[dict]:
    """Scan free-form text (a full HTTP request/response, headers and all)
    for base64/hex-looking substrings and try to decode each one.

    Exists because the common case isn't "this whole wire message is
    encoded" — it's "there's a JWT in the Authorization header" or "there's
    a base64 blob in one JSON field". `auto_decode` alone only catches the
    former; this catches the latter. Skips a candidate span already
    contained inside a larger span already reported, so a long run doesn't
    also get reported piecemeal as multiple shorter overlapping matches.
    """
    found: list[dict] = []
    reported: list[tuple[int, int]] = []
    for m in _CANDIDATE_RE.finditer(data):
        span = (m.start(), m.end())
        if span[1] - span[0] < min_len:
            continue
        if any(a <= span[0] and span[1] <= b for a, b in reported):
            continue
        layers = auto_decode(m.group(0))
        if not layers:
            continue
        reported.append(span)
        found.append({
            "match": m.group(0)[:160].decode("latin-1", errors="replace"),
            "offset": m.start(),
            "layers": layers,
        })
    return found


def decode_item(data: bytes) -> dict:
    """Combined view for one flow item: try the whole buffer as a single
    encoded blob first (the right model for a compressed body); only fall
    back to scanning for embedded tokens if that found nothing, so a
    whole-buffer hit doesn't also get re-reported piecemeal as an embedded
    match of itself."""
    whole = auto_decode(data)
    embedded = [] if whole else find_embedded_encodings(data)
    return {"whole": whole, "embedded": embedded}


def auto_decode(data: bytes, max_depth: int = MAX_DEPTH) -> list[dict]:
    """Try each decoder against `data`, then recurse into whatever
    successfully decoded (e.g. base64-of-gzip-of-json) until nothing new
    decodes or `max_depth` layers are found. Returns an ordered list of
    {"encoding": str, "preview": str} — empty if nothing decoded.
    """
    layers: list[dict] = []
    current = data
    seen = {current}
    for _ in range(max_depth):
        hit = None
        for name, fn in _DECODERS:
            out = fn(current)
            if out and out not in seen:
                hit = (name, out)
                break
        if not hit:
            break
        name, out = hit
        layers.append({
            "encoding": name,
            "preview": out[:MAX_PREVIEW].decode("latin-1", errors="replace"),
            "truncated": len(out) > MAX_PREVIEW,
        })
        seen.add(out)
        current = out
    return layers
