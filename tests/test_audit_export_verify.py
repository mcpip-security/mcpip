"""
MCPIP V2 — offline audit-export verification suite (``mcpip export-audit --verify``).

    ◐  "The exporter is the ONLY tamper check production operators can run —
       so it must fail on everything the gateway's own verify_chain fails on."

``/v1/audit/verify`` is sandbox-gated (404 in production), so ``docs/OPERATIONS.md``
routes production operators to ``export-audit --verify`` as THE continuous tamper
check. This suite builds a REAL signed ledger — a real ``WormLogger`` + a real
``AnchorStore`` + a throwaway Ed25519 WORM key against the same local Redis the
other WORM suites use — then tampers with it exactly the way an attacker with Redis
WRITE access would, and asserts the offline verifier FAILS CLOSED on each:

  * a single flipped byte in an epoch's Ed25519 signature (forgery/mutation), which
    leaves every Merkle root recomputing correctly;
  * a removed tail epoch (rollback / truncation), caught by the out-of-tamper-domain
    anchor low-watermark;
  * a broken ``prev_epoch_hash`` link, re-signed with the real key (so signature +
    ``epoch_hash`` still verify) — only the chain linkage catches it;
  * a mutated event body (the pre-existing Merkle check, kept green);
  * a tampered super-checkpoint (the compaction anchor) — while a legitimately
    COMPACTED chain must still verify by re-anchoring on that signed checkpoint;
  * an absent public key / an absent required anchor (usage fail-closed).

Plus a mechanical DRIFT GUARD: the canonicalization rules this tool re-implements
(epoch-hash core, super-checkpoint message, anchor message) are asserted
byte-identical to the producer in ``audit/worm_logger.py`` / ``audit/anchor.py``.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import asyncio
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterator, cast

import pytest
import redis as redis_sync
import redis.asyncio as redis_async
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit.anchor import AnchorStore, _anchor_message
from audit.merkle import _DOMAIN_EPOCH
from audit.worm_logger import (
    _DOMAIN_SUPERCP,
    _header_core,
    _supercp_message,
    WormLogger,
)
from interfaces import canonical_json, sha256_hex

from mcpip_verify import cli
from mcpip_verify.audit_export import (
    CHECK_ANCHOR,
    CHECK_EPOCH_HASH,
    CHECK_LINKAGE,
    CHECK_MERKLE,
    CHECK_SIGNATURE,
    ExportResult,
    export_audit,
    resolve_anchor_path,
)
from mcpip_verify.verifier import VerificationError
import mcpip_verify.audit_export as audit_export

_TEST_REDIS_URL = "redis://localhost:63790/12"
_EPOCH_INDEX_KEY = "mcpip:worm:epoch:index"
_EVENTS_STREAM = "mcpip:worm:events"
_EPOCHS = 3
_EVENTS_PER_EPOCH = 2


@dataclass(frozen=True)
class _Ledger:
    """A real, freshly-sealed signed ledger + everything needed to re-verify it."""

    private_key: Ed25519PrivateKey
    public_pem: bytes
    anchor_path: Path
    out_path: Path


def _sync() -> Any:
    return redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)


async def _seal(ledger: _Ledger) -> None:
    """Emit real decisions and seal them into ``_EPOCHS`` signed Merkle epochs."""
    client = redis_async.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        await client.flushdb()
        anchor = AnchorStore(ledger.private_key, str(ledger.anchor_path))
        worm = WormLogger(
            client,
            ledger.private_key,
            path=str(ledger.anchor_path.with_suffix(".jsonl")),
            anchor=anchor,
        )
        for epoch in range(_EPOCHS):
            for index in range(_EVENTS_PER_EPOCH):
                await worm.emit(
                    {
                        "decision": "allow",
                        "alias": "skill_spend_summary",
                        "agent_id": f"agent-export-{epoch}-{index}",
                        "correlation_id": f"corr-{epoch}-{index}",
                    }
                )
            header = await worm.close_epoch()
            assert header is not None and header.epoch == epoch
    finally:
        await client.aclose()


@pytest.fixture()
def ledger(tmp_path: Path) -> Iterator[_Ledger]:
    private_key = Ed25519PrivateKey.generate()
    built = _Ledger(
        private_key=private_key,
        public_pem=private_key.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ),
        anchor_path=tmp_path / "mcpip_worm.jsonl.anchor",
        out_path=tmp_path / "audit_export.jsonl",
    )
    asyncio.run(_seal(built))
    try:
        yield built
    finally:
        client = _sync()
        try:
            client.flushdb()
        finally:
            client.close()


def _verify(ledger: _Ledger, **overrides: Any) -> ExportResult:
    """Run the REAL exporter over the live ledger (read-only)."""
    kwargs: dict[str, Any] = {
        "public_key_pem": ledger.public_pem,
        "anchor_path": str(ledger.anchor_path),
    }
    kwargs.update(overrides)
    return export_audit(_TEST_REDIS_URL, ledger.out_path, True, **kwargs)


def _header(epoch: int) -> dict[str, Any]:
    client = _sync()
    try:
        raw = client.hget(_EPOCH_INDEX_KEY, str(epoch))
    finally:
        client.close()
    assert raw is not None, f"epoch {epoch} header missing"
    return cast("dict[str, Any]", json.loads(raw))


def _write_header(epoch: int, header: dict[str, Any]) -> None:
    client = _sync()
    try:
        client.hset(
            _EPOCH_INDEX_KEY, str(epoch), json.dumps(header, separators=(",", ":"))
        )
    finally:
        client.close()


def _reseal(header: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Recompute epoch_hash + Ed25519 signature over a doctored header.

    This models the STRONGEST attacker for the linkage test: one who can produce a
    header whose hash and signature both verify. Only the chain linkage catches it.
    """
    core = _header_core(
        int(header["epoch"]),
        int(header["start_seq"]),
        int(header["end_seq"]),
        int(header["leaf_count"]),
        int(header["timestamp_ns"]),
        str(header["merkle_root"]),
        str(header["prev_epoch_hash"]),
        str(header["first_stream_id"]),
        str(header["last_stream_id"]),
    )
    epoch_hash = sha256_hex(_DOMAIN_EPOCH + canonical_json(core))
    resealed = dict(header)
    resealed["epoch_hash"] = epoch_hash
    resealed["signature"] = private_key.sign(bytes.fromhex(epoch_hash)).hex()
    return resealed


# ---------------------------------------------------------------------------
# 0) The untampered ledger passes — and NAMES every check it performed.
# ---------------------------------------------------------------------------


def test_untampered_ledger_is_intact_and_names_its_checks(ledger: _Ledger) -> None:
    result = _verify(ledger)
    assert result.intact is True
    assert result.failed_check is None
    assert result.first_bad_epoch is None
    assert result.events == _EPOCHS * _EVENTS_PER_EPOCH
    assert result.epochs == _EPOCHS
    assert result.verified_epochs == _EPOCHS
    assert result.signature_only_epochs == 0
    # The anchor witnessed the newest sealed epoch and it matched.
    assert result.anchor_epoch == _EPOCHS - 1
    # Every documented check actually ran — the success verdict claims nothing more.
    assert set(result.checks_performed) == {
        CHECK_LINKAGE,
        CHECK_MERKLE,
        CHECK_EPOCH_HASH,
        CHECK_SIGNATURE,
        CHECK_ANCHOR,
    }
    assert result.checks_not_performed == ()
    # The export itself is a real, parseable JSONL artifact (events then headers).
    lines = ledger.out_path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == result.events + result.epochs
    assert all(json.loads(line) for line in lines)


# ---------------------------------------------------------------------------
# 1) A single flipped signature byte FAILS (the reported hole: it used to pass).
# ---------------------------------------------------------------------------


def test_flipped_signature_byte_fails_closed(ledger: _Ledger) -> None:
    header = _header(1)
    signature = str(header["signature"])
    flipped = ("0" if signature[0] != "0" else "1") + signature[1:]
    header["signature"] = flipped
    _write_header(1, header)

    result = _verify(ledger)
    assert result.intact is False
    # Reached check 5 — i.e. linkage, the Merkle root and the epoch_hash all still
    # recomputed correctly. ONLY the Ed25519 signature caught this.
    assert result.failed_check == CHECK_SIGNATURE
    assert result.first_bad_epoch == 1


def test_signature_from_a_foreign_key_fails_closed(ledger: _Ledger) -> None:
    """A validly-SHAPED signature made by a key that is not the WORM key."""
    attacker = Ed25519PrivateKey.generate()
    header = _header(2)
    header["signature"] = attacker.sign(bytes.fromhex(str(header["epoch_hash"]))).hex()
    _write_header(2, header)

    result = _verify(ledger)
    assert result.intact is False
    assert result.failed_check == CHECK_SIGNATURE
    assert result.first_bad_epoch == 2


# ---------------------------------------------------------------------------
# 2) A removed / rolled-back epoch FAILS on the anchor low-watermark.
# ---------------------------------------------------------------------------


def test_rolled_back_tail_epoch_fails_on_anchor_watermark(ledger: _Ledger) -> None:
    """Delete the newest signed epoch: every surviving signature still verifies and
    the surviving prefix is internally consistent — only the fsync'd out-of-domain
    anchor proves the chain used to reach further."""
    client = _sync()
    try:
        assert client.hdel(_EPOCH_INDEX_KEY, str(_EPOCHS - 1)) == 1
    finally:
        client.close()

    result = _verify(ledger)
    assert result.intact is False
    assert result.failed_check == CHECK_ANCHOR
    assert result.first_bad_epoch == _EPOCHS - 1


def test_whole_chain_erasure_fails_on_anchor_watermark(ledger: _Ledger) -> None:
    """Deleting EVERY epoch header (the strongest rollback) is still tamper."""
    client = _sync()
    try:
        client.delete(_EPOCH_INDEX_KEY)
    finally:
        client.close()

    result = _verify(ledger)
    assert result.intact is False
    assert result.failed_check == CHECK_ANCHOR
    assert result.first_bad_epoch == _EPOCHS - 1


def test_dropped_middle_epoch_fails_on_linkage(ledger: _Ledger) -> None:
    """A hole in the middle of the chain is a linkage/numbering break, caught before
    the anchor ever gets a say."""
    client = _sync()
    try:
        assert client.hdel(_EPOCH_INDEX_KEY, "1") == 1
    finally:
        client.close()

    result = _verify(ledger)
    assert result.intact is False
    assert result.failed_check == CHECK_LINKAGE
    # Reported at the hole (the EXPECTED epoch), exactly like verify_chain.
    assert result.first_bad_epoch == 1


# ---------------------------------------------------------------------------
# 3) A broken prev_epoch_hash link FAILS even when it is re-signed for real.
# ---------------------------------------------------------------------------


def test_broken_prev_epoch_hash_link_fails_closed(ledger: _Ledger) -> None:
    header = _header(2)
    header["prev_epoch_hash"] = "f" * 64  # not epoch 1's epoch_hash.
    _write_header(2, _reseal(header, ledger.private_key))

    result = _verify(ledger)
    assert result.intact is False
    assert result.failed_check == CHECK_LINKAGE
    assert result.first_bad_epoch == 2


def test_broken_link_fails_without_any_anchor_too(
    ledger: _Ledger, tmp_path: Path
) -> None:
    """The linkage check stands on its own: no anchor file, same verdict — so a
    deployment that lost its anchor still catches re-signed chain surgery."""
    header = _header(2)
    header["prev_epoch_hash"] = "f" * 64
    _write_header(2, _reseal(header, ledger.private_key))

    result = _verify(ledger, anchor_path=str(tmp_path / "absent.anchor"))
    assert result.intact is False
    assert result.failed_check == CHECK_LINKAGE
    assert result.first_bad_epoch == 2


def test_epoch_hash_mutation_fails_closed(ledger: _Ledger) -> None:
    """Mutating a signed header field (here the close timestamp — a field NO other
    check looks at) breaks the recomputed epoch_hash before the signature is even
    consulted. EVERY persisted header field is covered this way."""
    header = _header(1)
    header["timestamp_ns"] = str(int(header["timestamp_ns"]) + 1)
    _write_header(1, header)

    result = _verify(ledger)
    assert result.intact is False
    assert result.failed_check == CHECK_EPOCH_HASH
    assert result.first_bad_epoch == 1


# ---------------------------------------------------------------------------
# 4) Event-body tamper still fails (the pre-existing Merkle check, unweakened).
# ---------------------------------------------------------------------------


def test_mutated_event_record_fails_on_merkle(ledger: _Ledger) -> None:
    client = _sync()
    try:
        entries: Any = client.xrange(_EVENTS_STREAM, count=1)
        stream_id, fields = entries[0]
        record = json.loads(fields["record"])
        record["event"]["decision"] = "deny"  # rewrite history.
        # A stream entry is immutable, so the attacker's move is delete + re-append
        # the doctored record under the SAME seq (the exporter keys events by seq).
        client.xadd(
            _EVENTS_STREAM,
            {
                "seq": fields["seq"],
                "event_id": fields["event_id"],
                "timestamp_ns": fields["timestamp_ns"],
                "record": json.dumps(record, separators=(",", ":")),
                "leaf_hash": fields["leaf_hash"],
            },
        )
        client.xdel(_EVENTS_STREAM, stream_id)
    finally:
        client.close()

    result = _verify(ledger)
    assert result.intact is False
    assert result.failed_check == CHECK_MERKLE
    assert result.first_bad_epoch == 0


def test_partially_deleted_epoch_fails_on_merkle(ledger: _Ledger) -> None:
    """Half an epoch's events removed is tamper, not a retention trim."""
    client = _sync()
    try:
        entries: Any = client.xrange(_EVENTS_STREAM, count=1)
        client.xdel(_EVENTS_STREAM, entries[0][0])
    finally:
        client.close()

    result = _verify(ledger)
    assert result.intact is False
    assert result.failed_check == CHECK_MERKLE
    assert result.first_bad_epoch == 0


# ---------------------------------------------------------------------------
# 5) Usage fail-closed: no key ⇒ no verdict; --require-anchor ⇒ no silent pass.
# ---------------------------------------------------------------------------


def test_verify_without_public_key_is_refused(ledger: _Ledger) -> None:
    with pytest.raises(VerificationError):
        export_audit(_TEST_REDIS_URL, ledger.out_path, True, public_key_pem=None)


def test_export_without_verify_still_works_and_claims_nothing(
    ledger: _Ledger,
) -> None:
    result = export_audit(_TEST_REDIS_URL, ledger.out_path, False)
    assert result.events == _EPOCHS * _EVENTS_PER_EPOCH
    assert result.verified_epochs == 0
    assert result.checks_performed == ()


def test_require_anchor_fails_when_no_watermark(
    ledger: _Ledger, tmp_path: Path
) -> None:
    absent = str(tmp_path / "nowhere.anchor")
    lenient = _verify(ledger, anchor_path=absent)
    assert lenient.intact is True
    # ...but the missing rollback witness is NAMED, never silently implied.
    assert any(CHECK_ANCHOR in item for item in lenient.checks_not_performed)
    assert CHECK_ANCHOR not in lenient.checks_performed

    strict = _verify(ledger, anchor_path=absent, require_anchor=True)
    assert strict.intact is False
    assert strict.failed_check is not None and CHECK_ANCHOR in strict.failed_check


def test_garbage_anchor_lines_never_break_the_watermark(ledger: _Ledger) -> None:
    """An attacker who can append to the anchor file cannot forge a higher head nor
    destroy the real one — unsigned lines are ignored, the max valid line stands."""
    with ledger.anchor_path.open("a", encoding="utf-8") as handle:
        handle.write("not json at all\n")
        handle.write(json.dumps({"epoch": 99, "epoch_hash": "d" * 64, "sig": "00"}) + "\n")
    result = _verify(ledger)
    assert result.intact is True
    assert result.anchor_epoch == _EPOCHS - 1


def test_bad_public_key_material_is_refused(ledger: _Ledger) -> None:
    with pytest.raises(VerificationError):
        _verify(ledger, public_key_pem=b"-----BEGIN PUBLIC KEY-----\nnope\n")


# ---------------------------------------------------------------------------
# 6) A COMPACTED chain re-anchors on the signed super-checkpoint (no false tamper),
#    and a tampered checkpoint is itself fail-closed.
# ---------------------------------------------------------------------------


async def _compact(ledger: _Ledger) -> tuple[int, str, int]:
    client = redis_async.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        worm = WormLogger(
            client,
            ledger.private_key,
            path=str(ledger.anchor_path.with_suffix(".jsonl")),
            anchor=AnchorStore(ledger.private_key, str(ledger.anchor_path)),
        )
        result = await worm.compact(keep_epochs=1, min_stride=1)
        assert result is not None
        return result
    finally:
        await client.aclose()


def test_compacted_chain_verifies_from_the_signed_checkpoint(ledger: _Ledger) -> None:
    """Compaction folds epochs 0–1 into ONE signed super-checkpoint and trims their
    headers. The exporter must re-anchor on it — a verifier that only knew about
    genesis would report a (false) linkage break on the surviving suffix."""
    epoch, _epoch_hash, _end_seq = asyncio.run(_compact(ledger))
    assert epoch == _EPOCHS - 2

    result = _verify(ledger)
    assert result.intact is True, result.failed_check
    assert result.epochs == 1  # only the un-subsumed suffix header survives.
    assert result.verified_epochs == 1
    assert result.anchor_epoch == _EPOCHS - 1


def test_tampered_super_checkpoint_fails_closed(ledger: _Ledger) -> None:
    """A present-but-unverifiable checkpoint is tamper at the compaction anchor —
    never a silent fall back to a genesis replay."""
    asyncio.run(_compact(ledger))
    client = _sync()
    try:
        payload = json.loads(client.get("mcpip:worm:supercp"))
        payload["end_seq"] = int(payload["end_seq"]) + 1
        client.set("mcpip:worm:supercp", json.dumps(payload, separators=(",", ":")))
    finally:
        client.close()

    result = _verify(ledger)
    assert result.intact is False
    assert result.failed_check == CHECK_SIGNATURE
    assert result.first_bad_epoch == 0


# ---------------------------------------------------------------------------
# 7) The CLI: --pubkey is real, the verdict lines name the checks, exit codes hold.
# ---------------------------------------------------------------------------


def test_cli_pubkey_flag_is_real_and_verdict_names_checks(
    ledger: _Ledger, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    pub = tmp_path / "worm_signing_ed25519.pub.pem"
    pub.write_bytes(ledger.public_pem)
    code = cli.main(
        [
            "export-audit",
            "--redis-url",
            _TEST_REDIS_URL,
            "--out",
            str(ledger.out_path),
            "--verify",
            "--pubkey",
            str(pub),
            "--anchor-path",
            str(ledger.anchor_path),
        ]
    )
    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert "audit chain: intact" in captured.out
    for named in (CHECK_LINKAGE, CHECK_MERKLE, CHECK_EPOCH_HASH, CHECK_SIGNATURE):
        assert named in captured.out
    assert "anchor low-watermark epoch 2 matched" in captured.out


def test_cli_reports_tampered_and_exits_2(
    ledger: _Ledger, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    client = _sync()
    try:
        client.hdel(_EPOCH_INDEX_KEY, str(_EPOCHS - 1))
    finally:
        client.close()
    pub = tmp_path / "worm.pub.pem"
    pub.write_bytes(ledger.public_pem)

    code = cli.main(
        [
            "export-audit",
            "--redis-url",
            _TEST_REDIS_URL,
            "--out",
            str(ledger.out_path),
            "--verify",
            "--pubkey",
            str(pub),
            "--anchor-path",
            str(ledger.anchor_path),
        ]
    )
    captured = capsys.readouterr()
    assert code == 2
    assert "audit chain: TAMPERED" in captured.err
    assert CHECK_ANCHOR in captured.err


def test_cli_verify_without_pubkey_is_a_usage_failure(ledger: _Ledger) -> None:
    with pytest.raises(SystemExit) as exit_info:
        cli.main(
            [
                "export-audit",
                "--redis-url",
                _TEST_REDIS_URL,
                "--out",
                str(ledger.out_path),
                "--verify",
            ]
        )
    assert exit_info.value.code == 2


# ---------------------------------------------------------------------------
# 8) Drift guard: the mirrored canonicalization rules ARE the producer's rules.
# ---------------------------------------------------------------------------


def test_canonical_rules_match_the_producer_byte_for_byte() -> None:
    fields = (7, 15, 22, 8, 1_753_000_000_000_000_000, "ab" * 32, "cd" * 32,
              "1753-0", "1754-3")
    assert audit_export._header_core(*fields) == _header_core(*fields)
    assert audit_export._DOMAIN_SUPERCP == _DOMAIN_SUPERCP
    assert audit_export._supercp_message(7, "ef" * 32, 22) == _supercp_message(
        7, "ef" * 32, 22
    )
    assert audit_export._anchor_message(7, "ef" * 32) == _anchor_message(7, "ef" * 32)


def test_anchor_path_resolution_matches_the_gateway(monkeypatch: Any) -> None:
    monkeypatch.delenv("MCPIP_WORM_ANCHOR_PATH", raising=False)
    monkeypatch.setenv("MCPIP_WORM_PATH", "/var/lib/mcpip/mcpip_worm.jsonl")
    assert resolve_anchor_path(None) == Path("/var/lib/mcpip/mcpip_worm.jsonl.anchor")
    monkeypatch.setenv("MCPIP_WORM_ANCHOR_PATH", "/mnt/anchor/head.jsonl")
    assert resolve_anchor_path(None) == Path("/mnt/anchor/head.jsonl")
    assert resolve_anchor_path("/explicit") == Path("/explicit")


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
