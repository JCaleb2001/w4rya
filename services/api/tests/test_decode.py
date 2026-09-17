"""Tests for decode.py — recursive, deterministic payload decoding."""

from __future__ import annotations

import base64
import gzip
import zlib


def test_base64_of_plain_text():
    import decode
    raw = base64.b64encode(b"whoami; cat /etc/passwd")
    layers = decode.auto_decode(raw)
    assert len(layers) == 1
    assert layers[0]["encoding"] == "base64"
    assert layers[0]["preview"] == "whoami; cat /etc/passwd"


def test_base64_of_gzip_of_text_recurses_two_layers():
    import decode
    inner = gzip.compress(b"the real payload lives in here")
    raw = base64.b64encode(inner)
    layers = decode.auto_decode(raw)
    encodings = [l["encoding"] for l in layers]
    assert encodings == ["base64", "gzip"]
    assert layers[-1]["preview"] == "the real payload lives in here"


def test_hex_decode():
    import decode
    raw = b"deadbeef" + b"68656c6c6f20776f726c64"  # "hello world" in hex
    # keep it a clean hex-only buffer for the fullmatch heuristic
    raw = "68656c6c6f20776f726c64".encode()
    layers = decode.auto_decode(raw)
    assert layers[0]["encoding"] == "hex"
    assert layers[0]["preview"] == "hello world"


def test_url_decode():
    import decode
    raw = b"cmd=cat%20%2Fetc%2Fpasswd"
    layers = decode.auto_decode(raw)
    assert layers[0]["encoding"] == "url"
    assert layers[0]["preview"] == "cmd=cat /etc/passwd"


def test_deflate_raw_and_zlib_wrapped():
    import decode
    payload = b"a" * 200 + b"deflate me please"
    zlib_wrapped = zlib.compress(payload)
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    raw_deflate = compressor.compress(payload) + compressor.flush()
    for blob in (zlib_wrapped, raw_deflate):
        layers = decode.auto_decode(blob)
        assert layers and layers[0]["encoding"] == "deflate"
        assert layers[0]["preview"] == payload.decode()


def test_plain_text_with_no_encoding_yields_no_layers():
    import decode
    layers = decode.auto_decode(b"just a normal HTTP body, nothing encoded here")
    assert layers == []


def test_gzip_decompression_bomb_is_bounded_not_exhausted():
    import decode
    # A small, highly-compressible blob that would expand far past
    # MAX_DECOMPRESSED if let run to completion — this must come back
    # capped (or rejected), never a multi-hundred-MB allocation.
    bomb = gzip.compress(b"\x00" * (decode.MAX_DECOMPRESSED * 4))
    assert len(bomb) < 1_000_000
    out = decode.try_gzip(bomb)
    assert out is None or len(out) <= decode.MAX_DECOMPRESSED


def test_deflate_decompression_bomb_is_bounded_not_exhausted():
    import decode
    bomb = zlib.compress(b"\x00" * (decode.MAX_DECOMPRESSED * 4))
    assert len(bomb) < 1_000_000
    out = decode.try_deflate(bomb)
    assert out is None or len(out) <= decode.MAX_DECOMPRESSED


def test_binary_non_texty_data_is_not_falsely_decoded():
    """Random binary bytes that happen to be valid base64 alphabet but
    decode to garbage must not be reported as a successful decode."""
    import decode
    raw = bytes(range(0, 64)) * 2  # not valid base64 chars anyway, but also
    layers = decode.auto_decode(raw)
    # whatever happens, every reported layer must actually look texty
    for l in layers:
        printable = sum(1 for c in l["preview"] if c.isprintable() or c in "\n\r\t")
        assert printable / max(1, len(l["preview"])) > 0.5


def test_stops_at_max_depth():
    import decode
    data = b"start"
    for _ in range(6):
        data = base64.b64encode(data)
    layers = decode.auto_decode(data, max_depth=2)
    assert len(layers) == 2


def test_find_embedded_encodings_locates_jwt_in_a_header():
    """The realistic case: a captured HTTP request item is headers + a JWT
    + more headers, not a standalone base64 blob. auto_decode() alone can't
    catch this (the whole buffer isn't base64) — find_embedded_encodings
    must."""
    import base64
    import decode
    payload_json = base64.urlsafe_b64encode(b'{"ID":"92","exp":1788628217}').rstrip(b"=")
    jwt = b"eyJhbGciOiJIUzI1NiJ9." + payload_json + b".sig-not-decodable-1234567890"
    request = (
        b"GET /api/me HTTP/1.1\r\n"
        b"Host: 10.100.2.1:2112\r\n"
        b"Authorization: Bearer " + jwt + b"\r\n"
        b"Connection: keep-alive\r\n\r\n"
    )
    found = decode.find_embedded_encodings(request)
    assert any(b'"ID":"92"' in f["layers"][0]["preview"].encode() for f in found)


def test_decode_item_prefers_whole_buffer_over_embedded():
    import base64
    import decode
    raw = base64.b64encode(b"this whole item is one encoded blob, nothing else")
    out = decode.decode_item(raw)
    assert out["whole"] and out["whole"][0]["encoding"] == "base64"
    assert out["embedded"] == []  # not double-reported as an embedded match


def test_decode_item_falls_back_to_embedded_for_mixed_text():
    import base64
    import decode
    token = base64.urlsafe_b64encode(b"a secret worth finding here").rstrip(b"=")
    raw = b"plain header text\r\nX-Token: " + token + b"\r\nmore plain text"
    out = decode.decode_item(raw)
    assert out["whole"] == []
    assert len(out["embedded"]) == 1
    assert "a secret worth finding here" in out["embedded"][0]["layers"][-1]["preview"]


def test_find_embedded_encodings_does_not_report_overlapping_shorter_spans():
    import base64
    import decode
    token = base64.b64encode(b"one single long token that should be reported exactly once")
    raw = b"prefix " + token + b" suffix"
    found = decode.find_embedded_encodings(raw)
    assert len(found) == 1


def test_does_not_loop_forever_on_a_fixed_point():
    """A decoder that would return input unchanged (e.g. url-decoding text
    with no % signs) must not be treated as progress."""
    import decode
    layers = decode.auto_decode(b"no-percent-signs-here-at-all")
    assert layers == []
