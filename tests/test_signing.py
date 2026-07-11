"""airlock._signing <-> the pinned reference vectors (PLAN.md 6.2, signing.md).

The `airlock-v1` HMAC scheme is the wire boundary's authentication, reused
byte-for-byte by airlock-cloud (Ruby). These tests are the Python half of the
cross-language pin: every `canonical_string` and `signature` in
`/contracts/examples/signing_vectors.json` round-trips through `_signing`
exactly, the replay window rejects stale/future timestamps, tampering with the
body / method / path / signature fails, the constant-time compare is actually
used, and the empty-body (GET) vector works.

Deterministic: the replay tests inject `now` (unix seconds); nothing sleeps or
reads the wall clock (PLAN.md 7).
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path
from typing import Any

import pytest

from airlock import _signing

VECTORS_PATH = Path(__file__).parent.parent / "contracts" / "examples" / "signing_vectors.json"
DOC: dict[str, Any] = json.loads(VECTORS_PATH.read_text())
SECRET: str = DOC["secret"]
VECTORS: list[dict[str, Any]] = DOC["vectors"]
IDS = [v["name"] for v in VECTORS]


def _raw(vector: dict[str, Any]) -> bytes:
    return str(vector["raw_body"]).encode("utf-8")


# ---------------------------------------------------------------------------
# The golden vectors round-trip byte-for-byte.
# ---------------------------------------------------------------------------


def test_there_are_at_least_three_vectors() -> None:
    """POST-with-body, empty-body GET, webhook POST — the cross-language pin."""
    assert len(VECTORS) >= 3


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_canonical_string_matches_vector(vector: dict[str, Any]) -> None:
    built = _signing.build_canonical_string(
        timestamp=vector["timestamp"],
        method=vector["method"],
        path_with_query=vector["path_with_query"],
        raw_body=_raw(vector),
    )
    assert built == vector["canonical_string"]
    # And the layout is exactly five LF-separated fields, no trailing newline.
    fields = built.split("\n")
    assert len(fields) == 5
    assert fields[0] == "airlock-v1"
    assert not built.endswith("\n")


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_body_hash_matches_vector(vector: dict[str, Any]) -> None:
    assert _signing.sha256_hex(_raw(vector)) == vector["body_sha256_hex"]


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_signature_matches_vector(vector: dict[str, Any]) -> None:
    sig = _signing.sign(
        SECRET,
        timestamp=vector["timestamp"],
        method=vector["method"],
        path_with_query=vector["path_with_query"],
        raw_body=_raw(vector),
    )
    assert sig == vector["signature"] == vector["headers"]["Airlock-Signature"]
    assert sig.startswith("v1=")


@pytest.mark.parametrize("vector", VECTORS, ids=IDS)
def test_verify_accepts_the_vector(vector: dict[str, Any]) -> None:
    ok = _signing.verify(
        SECRET,
        headers=vector["headers"],
        method=vector["method"],
        path_with_query=vector["path_with_query"],
        raw_body=_raw(vector),
        now=vector["timestamp"],  # injected — no wall clock
    )
    assert ok is True


def test_empty_body_sha256_is_the_well_known_constant() -> None:
    assert (
        _signing.empty_body_sha256_hex()
        == hashlib.sha256(b"").hexdigest()
        == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )
    # The GET vector carries an empty body and still verifies.
    get_vec = next(v for v in VECTORS if v["raw_body"] == "")
    assert get_vec["body_sha256_hex"] == _signing.empty_body_sha256_hex()


# ---------------------------------------------------------------------------
# Replay window (±300s) — deterministic via injected `now`.
# ---------------------------------------------------------------------------


@pytest.fixture
def post_vector() -> dict[str, Any]:
    return next(v for v in VECTORS if v["name"] == "create_approval_post")


def _verify(vector: dict[str, Any], **over: Any) -> bool:
    kw: dict[str, Any] = {
        "headers": dict(vector["headers"]),
        "method": vector["method"],
        "path_with_query": vector["path_with_query"],
        "raw_body": _raw(vector),
        "now": vector["timestamp"],
    }
    kw.update(over)
    return _signing.verify(SECRET, **kw)


def test_replay_window_boundaries(post_vector: dict[str, Any]) -> None:
    ts = post_vector["timestamp"]
    assert _verify(post_vector, now=ts) is True
    assert _verify(post_vector, now=ts + 300) is True  # exactly at the edge
    assert _verify(post_vector, now=ts - 300) is True
    assert _verify(post_vector, now=ts + 301) is False  # future, stale
    assert _verify(post_vector, now=ts - 301) is False  # past, stale


def test_non_integer_timestamp_header_rejected(post_vector: dict[str, Any]) -> None:
    headers = dict(post_vector["headers"])
    headers["Airlock-Timestamp"] = "not-a-number"
    assert _verify(post_vector, headers=headers) is False


def test_missing_headers_return_false_never_raise(post_vector: dict[str, Any]) -> None:
    for drop in ("Airlock-Timestamp", "Airlock-Signature"):
        headers = {k: v for k, v in post_vector["headers"].items() if k != drop}
        assert _verify(post_vector, headers=headers) is False


# ---------------------------------------------------------------------------
# Tampering — any change to a signed input fails verification.
# ---------------------------------------------------------------------------


def test_tampered_body_fails(post_vector: dict[str, Any]) -> None:
    tampered = _raw(post_vector) + b" "  # a single trailing byte
    assert _verify(post_vector, raw_body=tampered) is False


def test_tampered_method_fails(post_vector: dict[str, Any]) -> None:
    assert _verify(post_vector, method="PUT") is False


def test_tampered_path_fails(post_vector: dict[str, Any]) -> None:
    assert _verify(post_vector, path_with_query="/api/v1/approvals?x=1") is False


def test_tampered_timestamp_header_fails(post_vector: dict[str, Any]) -> None:
    # A different timestamp changes the canonical string, so even inside the
    # window (now advanced to match) the signature no longer matches.
    headers = dict(post_vector["headers"])
    new_ts = post_vector["timestamp"] + 1
    headers["Airlock-Timestamp"] = str(new_ts)
    assert _verify(post_vector, headers=headers, now=new_ts) is False


def test_tampered_signature_fails(post_vector: dict[str, Any]) -> None:
    headers = dict(post_vector["headers"])
    good = headers["Airlock-Signature"]
    # Flip the last hex nibble.
    flipped = good[:-1] + ("0" if good[-1] != "0" else "1")
    headers["Airlock-Signature"] = flipped
    assert _verify(post_vector, headers=headers) is False


def test_wrong_secret_fails(post_vector: dict[str, Any]) -> None:
    ok = _signing.verify(
        SECRET + "x",
        headers=dict(post_vector["headers"]),
        method=post_vector["method"],
        path_with_query=post_vector["path_with_query"],
        raw_body=_raw(post_vector),
        now=post_vector["timestamp"],
    )
    assert ok is False


def test_signature_without_v1_scheme_rejected(post_vector: dict[str, Any]) -> None:
    headers = dict(post_vector["headers"])
    mac = headers["Airlock-Signature"].split("=", 1)[1]
    headers["Airlock-Signature"] = f"v2={mac}"  # only a v2 token, no v1
    assert _verify(post_vector, headers=headers) is False


# ---------------------------------------------------------------------------
# Header parsing + constant-time compare.
# ---------------------------------------------------------------------------


def test_parse_signature_header_multi_scheme() -> None:
    parsed = _signing.parse_signature_header("v1=aa, v2=bb cc dd=ee")
    assert parsed["v1"] == "aa"
    assert parsed["v2"] == "bb"
    assert parsed["dd"] == "ee"
    assert _signing.parse_signature_header("garbage") == {}


def test_header_lookup_is_case_insensitive(post_vector: dict[str, Any]) -> None:
    headers = {k.lower(): v for k, v in post_vector["headers"].items()}
    assert _verify(post_vector, headers=headers) is True


def test_verify_uses_constant_time_compare(
    post_vector: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """The digest comparison must go through hmac.compare_digest (no `==`)."""
    calls: list[tuple[str, str]] = []
    real = hmac.compare_digest

    def spy(a: Any, b: Any) -> bool:
        calls.append((a, b))
        return real(a, b)

    # Patch the shared hmac module object (the same one _signing imported), so
    # _signing's `hmac.compare_digest(...)` call routes through the spy.
    monkeypatch.setattr(hmac, "compare_digest", spy)
    assert _verify(post_vector) is True
    assert len(calls) == 1, "the signature check must use exactly one compare_digest"
