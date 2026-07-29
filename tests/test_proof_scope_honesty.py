"""
MCPIP — the compliance bundle must state the scope of the proof it is offering.

    ◐ "A signature over the chain is not a proof of the event."

The AU-10 mapping claimed "every event has a Merkle inclusion proof". The code has never
been able to honour that. ``inclusion_proof`` needs two things that are written at epoch
close and deleted at trim — the ``eventloc`` entry and the epoch's leaf-digest vector — so
it returns ``None`` in two real windows:

  * the CURRENT, still-open epoch (recorded before execution, but not yet sealed), and
  * anything older than ``WORM_HOT_EPOCHS``, which ``_trim_retention`` drops.

Outside the window the signed epoch chain still commits to the epoch and its sequence
range. That is genuine non-repudiation — of an EPOCH. It is a weaker claim than a proof
binding one decision's exact bytes to a signed root, and an assessor who samples a
decision from last quarter needs to know which of the two they are getting BEFORE they
rely on it. An evidence bundle that omits its own period and population reads as
unlimited scope, which is how a true artifact becomes a false impression.

So the fix is not a wording patch. The bundle now reports a MEASURED window, and these
tests pin both halves: the measurement is real (a live ledger, where an unsealed event
genuinely has no proof and a sealed one genuinely does), and the claim text can no longer
drift back to "every event".
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/2")
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_proof_scope_worm.jsonl"),
)

import asyncio
import json
from typing import Any

import redis.asyncio as redis_async
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from audit.worm_logger import (
    WORM_HOT_EPOCHS,
    ProofScope,
    WormAttestation,
    WormLogger,
)
from services.compliance_evidence import CONTROL_MAPPING, build_evidence_bundle

# Its own db: this suite emits real events and closes real epochs, and it must not race
# the API suite's ledger. Same reasoning as tests/test_decision_retention_honesty.py —
# the app's pooled client is bound to whichever event loop touched it first, so a
# self-contained ledger is the difference between a real gate and a flaky one.
_SCOPE_REDIS_URL = "redis://localhost:63790/14"


def _sealed_attestation() -> WormAttestation:
    """A synthesized sealed head. The scope block is orthogonal to the attestation's real
    contents, so a fixed one keeps these assertions about SCOPE and nothing else."""
    return WormAttestation(
        epoch=7,
        end_seq=42,
        merkle_root="a" * 64,
        epoch_hash="b" * 64,
        signature="c" * 128,
        signing_key_id="d" * 64,
        intact=True,
        first_bad_epoch=None,
        anchor_epoch=7,
        anchor_epoch_hash="b" * 64,
    )


def _window() -> ProofScope:
    """A representative measured window: five sealed-and-retained epochs, a live unsealed
    tail, and a population that is neither zero nor the whole ledger."""
    return ProofScope(
        hot_epochs=WORM_HOT_EPOCHS,
        oldest_proof_epoch=3,
        newest_proof_epoch=7,
        first_proof_seq=11,
        last_proof_seq=42,
        proof_bearing_events=31,
        unsealed_events=2,
        sealed_through_seq=42,
    )


_PROV: dict[str, Any] = {"version": "3.0.0", "signing_key_id": "f" * 64, "verified": True}
_AT = "2026-07-25T00:00:00+00:00"


def _au10_clause() -> dict[str, Any]:
    for block in CONTROL_MAPPING:
        if block["framework"].startswith("NIST"):
            for clause in block["clauses"]:
                if clause["clause"].startswith("AU-10"):
                    return dict(clause)
    raise AssertionError("the NIST AU-10 clause vanished from the control mapping")


# ---------------------------------------------------------------------------
# The claim text — what the bundle asserts about itself.
# ---------------------------------------------------------------------------


def test_au10_no_longer_claims_a_proof_for_every_event() -> None:
    """The exact overclaim, refused by substring. This is the sentence that would have
    been handed to an assessor as a description of what the ledger can produce."""
    evidence = _au10_clause()["mcpip_evidence"].lower()
    assert "every event has a merkle inclusion proof" not in evidence
    assert "every event has an inclusion proof" not in evidence


def test_au10_states_the_bound_and_names_what_survives_it() -> None:
    """Removing the overclaim is not enough — a reader who is told only what is NOT
    covered will assume nothing is. The clause has to say that the signed chain still
    covers the trimmed range, or the correction reads as a bigger gap than exists."""
    evidence = _au10_clause()["mcpip_evidence"].lower()
    assert "retention" in evidence or "retained" in evidence
    assert "chain" in evidence
    # The two failure windows must both be named; each is separately surprising.
    assert "open epoch" in evidence or "not yet" in evidence
    assert "aged out" in evidence or "trim" in evidence


def test_au10_points_at_the_code_that_creates_the_bound() -> None:
    """A reviewer checking the claim should land on ``_trim_retention``, not on a general
    'the audit module'. The pointer is the difference between a verifiable claim and a
    plausible one."""
    pointer = _au10_clause()["code_pointer"]
    assert "proof_scope" in pointer
    assert "_trim_retention" in pointer


def test_the_bundle_always_answers_period_and_population() -> None:
    """The two questions asked of every evidence artifact. A bundle that answers neither
    is read as covering everything — so the block is unconditional, never a field that
    appears only when the news is good."""
    bundle = build_evidence_bundle(
        attestation=_sealed_attestation(),
        gateway_version="3.0.0",
        release_provenance=_PROV,
        generated_at=_AT,
        proof_scope=_window(),
    )
    scope = bundle["evidence_scope"]
    assert scope["point_in_time"] == _AT
    assert scope["covers_observation_period"] is False, (
        "a point-in-time snapshot must never be readable as a Type II observation window"
    )
    window = scope["proof_window"]
    assert window["proof_bearing_events"] == 31
    assert window["unsealed_events"] == 2
    assert window["oldest_provable_epoch"] == 3
    assert window["newest_provable_epoch"] == 7
    assert window["retention_epochs"] == WORM_HOT_EPOCHS


def test_an_unmeasurable_window_says_so_instead_of_disappearing() -> None:
    """The dangerous default. If the scope block were simply omitted when the engine could
    not answer, the bundle would look exactly like one with unlimited coverage — the
    silent-failure shape this whole change exists to remove."""
    bundle = build_evidence_bundle(
        attestation=_sealed_attestation(),
        gateway_version="3.0.0",
        release_provenance=_PROV,
        generated_at=_AT,
        proof_scope=None,
    )
    scope = bundle["evidence_scope"]
    assert "evidence_scope" in bundle
    assert scope["proof_window"] is None
    assert "unavailable" in scope["proof_window_note"].lower()
    assert "never read as full coverage" in scope["proof_window_note"]


def test_the_scope_block_leaks_no_topology_or_payload() -> None:
    """The scope is counts and epoch numbers. If measuring coverage ever started carrying
    an alias, a target, or a record body, the bundle would breach the opacity boundary the
    rest of it is careful to hold."""
    bundle = build_evidence_bundle(
        attestation=_sealed_attestation(),
        gateway_version="3.0.0",
        release_provenance=_PROV,
        generated_at=_AT,
        proof_scope=_window(),
    )
    for value in bundle["evidence_scope"]["proof_window"].values():
        assert value is None or isinstance(value, int), (
            "the proof window must stay numeric — a string here is a channel for a "
            "target, an alias, or a record body"
        )


# ---------------------------------------------------------------------------
# The measurement — against a real ledger, because a scope block that reported a
# CONFIGURED bound rather than the real one would be the same class of overclaim in a
# new costume.
# ---------------------------------------------------------------------------


def test_measured_window_matches_what_inclusion_proof_can_actually_answer(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """The empirical half.

    Emit one event, ask for its proof BEFORE the epoch closes, then close and ask again.
    The claim and the capability are checked against each other: whatever
    ``proof_scope`` reports as provable must be exactly what ``inclusion_proof`` will
    actually produce. If they ever diverge, the bundle is lying with real numbers, which
    is harder to catch than lying with prose.
    """

    async def _probe() -> dict[str, Any]:
        client = redis_async.Redis.from_url(_SCOPE_REDIS_URL, decode_responses=True)
        await client.flushdb()
        try:
            worm = WormLogger(
                client,
                Ed25519PrivateKey.generate(),
                path=str(tmp_path / "proof_scope_worm.jsonl"),
            )
            receipt = await worm.emit(
                {
                    "decision": "allow",
                    "alias": "skill_spend_summary",
                    "agent_id": "agent-proof-scope",
                    "correlation_id": "corr-proof-scope",
                    "tenant_id": "tenant-live",
                }
            )
            before_scope = await worm.proof_scope()
            before_proof = await worm.inclusion_proof(receipt.event_id)

            await worm.close_epoch()

            after_scope = await worm.proof_scope()
            after_proof = await worm.inclusion_proof(receipt.event_id)
            return {
                "before_scope": before_scope,
                "before_proof": before_proof,
                "after_scope": after_scope,
                "after_proof": after_proof,
            }
        finally:
            await client.aclose()

    got = asyncio.run(_probe())
    before: ProofScope = got["before_scope"]
    after: ProofScope = got["after_scope"]

    # BEFORE the seal: durably recorded (write-before-execute already held), but no signed
    # root commits to it yet — so no proof exists, and the scope says so with a count.
    assert got["before_proof"] is None, (
        "an event in the open epoch returned a proof — then the whole premise of the "
        "unsealed window is wrong and this gate is measuring nothing"
    )
    assert before.proof_bearing_events == 0
    assert before.unsealed_events >= 1
    assert before.oldest_proof_epoch is None

    # AFTER the seal: the proof exists, and the reported population counts it.
    assert got["after_proof"] is not None, "a sealed event must be individually provable"
    assert after.proof_bearing_events >= 1
    assert after.unsealed_events == 0
    assert after.oldest_proof_epoch is not None
    assert after.newest_proof_epoch is not None
    assert after.first_proof_seq is not None and after.last_proof_seq is not None
    assert after.first_proof_seq <= after.last_proof_seq

    # The reported epoch must be the one the proof actually resolves against — the join
    # between the two surfaces, and the thing a re-implementation would most easily break.
    assert after.oldest_proof_epoch <= got["after_proof"].epoch <= after.newest_proof_epoch


def test_scope_is_measured_from_present_state_not_from_the_configured_bound(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """``head - WORM_HOT_EPOCHS`` is the arithmetic answer; after a restart or a partial
    trim it is not the real one. An evidence bundle has to report the window an assessor
    could reproduce by ASKING for the proofs, so the window is derived from the epochs
    whose leaf vectors are actually present."""

    async def _probe() -> tuple[ProofScope, int]:
        client = redis_async.Redis.from_url(_SCOPE_REDIS_URL, decode_responses=True)
        await client.flushdb()
        try:
            worm = WormLogger(
                client,
                Ed25519PrivateKey.generate(),
                path=str(tmp_path / "proof_scope_measured.jsonl"),
            )
            for i in range(3):
                await worm.emit(
                    {
                        "decision": "allow",
                        "alias": "skill_spend_summary",
                        "agent_id": f"agent-{i}",
                        "correlation_id": f"corr-{i}",
                        "tenant_id": "tenant-live",
                    }
                )
                await worm.close_epoch()
            scope = await worm.proof_scope()
            assert scope.oldest_proof_epoch is not None, "the probe sealed no epoch"
            # Simulate the divergence: drop ONE retained epoch's leaf vector, exactly as a
            # partial trim would. The arithmetic bound is unchanged; the truth is not.
            await client.hdel("mcpip:worm:epoch:leaves", str(scope.oldest_proof_epoch))
            return await worm.proof_scope(), scope.oldest_proof_epoch
        finally:
            await client.aclose()

    after, dropped = asyncio.run(_probe())
    assert after.oldest_proof_epoch is not None
    assert after.oldest_proof_epoch > dropped, (
        "the window still claimed an epoch whose leaf vector is gone — it is reporting "
        "the configured bound, not what can actually be proven"
    )


def test_per_event_mode_reports_no_proof_window_rather_than_an_empty_one(tmp_path) -> None:  # type: ignore[no-untyped-def]
    """Legacy migration mode has no epochs and no Merkle proofs at all. Reporting an
    epoch window of ``None`` with zero population is the honest shape; reporting a window
    that merely looks empty would suggest proofs are coming once an epoch seals."""

    async def _probe() -> ProofScope:
        client = redis_async.Redis.from_url(_SCOPE_REDIS_URL, decode_responses=True)
        await client.flushdb()
        try:
            worm = WormLogger(
                client,
                Ed25519PrivateKey.generate(),
                path=str(tmp_path / "proof_scope_per_event.jsonl"),
                mode="per_event",
            )
            await worm.emit(
                {
                    "decision": "allow",
                    "alias": "skill_spend_summary",
                    "agent_id": "agent-legacy",
                    "correlation_id": "corr-legacy",
                    "tenant_id": "tenant-live",
                }
            )
            return await worm.proof_scope()
        finally:
            await client.aclose()

    scope = asyncio.run(_probe())
    assert scope.oldest_proof_epoch is None
    assert scope.newest_proof_epoch is None
    assert scope.proof_bearing_events == 0
    assert scope.unsealed_events == 0
    assert scope.sealed_through_seq is None
    # The configured depth still rides along so the block never renders as "unknown".
    assert scope.hot_epochs == WORM_HOT_EPOCHS


def test_the_scope_survives_json_serialization() -> None:
    """The bundle is exported over HTTP and read by tooling. A dataclass that serialized
    to something lossy would make the honest numbers unusable at exactly the moment they
    matter."""
    bundle = build_evidence_bundle(
        attestation=_sealed_attestation(),
        gateway_version="3.0.0",
        release_provenance=_PROV,
        generated_at=_AT,
        proof_scope=_window(),
    )
    round_tripped = json.loads(json.dumps(bundle))
    assert round_tripped["evidence_scope"]["proof_window"]["proof_bearing_events"] == 31
