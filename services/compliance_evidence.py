"""
MCPIP — compliance-evidence bundle assembly (pure, I/O-free).

    ◐  "Evidence, not a certificate. This module exports what the gateway has ALREADY
       signed — the WORM attestation, the fresh verify_chain verdict, the public
       signing_key_id, the running version + signed release provenance — alongside a
       static control-mapping manifest that says which MCPIP mechanism PROVIDES EVIDENCE
       FOR which regulatory control clause. It NEVER asserts a certification, a customer,
       an auditor sign-off, or a control 'pass' — those are external third-party
       processes this software cannot produce."

Design constraints (all load-bearing):
  * PURE. No HTTP/socket/LLM-SDK/env-credential import; no Redis; no signing; no clock read
    (the caller passes ``generated_at``). ``build_evidence_bundle`` takes already-fetched REAL
    gateway state and returns a JSON-serializable ``dict`` — trivially unit-testable Redis-free.
  * NO FABRICATION. The attestation fields are serialized 1:1 from the REAL
    ``WormAttestation`` (the same signed commitments ``/v1/audit/attestation`` surfaces); the
    ``intact``/``first_bad_epoch`` verdict is the engine's real one; the empty-state before the
    first seal is reported honestly (``sealed=False`` + an ``empty_state_note``). No epoch
    header, verdict, signature, customer, or certification is ever synthesized.
  * NO SECRET / NO TOPOLOGY. Only signed commitments (hashes / signatures / public key ids),
    the version string, and static mapping text ever appear — never an alias→target map, a
    payload, a PIN/OTP, or a vended credential.
  * EVIDENCE ≠ CERTIFICATION. Every framework block carries a ``certification_note`` and the
    bundle carries a top-level ``BUNDLE_DISCLAIMER`` restating this. Every clause entry is
    phrased "this mechanism PROVIDES EVIDENCE FOR this clause", never "certified/authorized/
    passed".
"""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:  # pragma: no cover — type-only; keeps this module import-cycle-free.
    from audit.worm_logger import WormAttestation


# The single certification-hygiene sentence stamped onto every framework block: the mechanism
# is technical evidence; the certification itself is an EXTERNAL third-party process.
_CERTIFICATION_NOTE = (
    "MCPIP provides technical evidence toward this clause; the certification, authorization, "
    "or attestation itself is an external third-party process this software cannot produce."
)


# Top-level honesty string — restates evidence ≠ certification and that nothing here asserts a
# customer, an auditor sign-off, or a control pass.
BUNDLE_DISCLAIMER: str = (
    "This bundle is portable technical EVIDENCE assembled from the running MCPIP gateway's own "
    "already-signed audit state — it is NOT a certification, an authorization, an audit "
    "opinion, or a compliance attestation. It reports what the gateway cryptographically "
    "commits to (the "
    "signed WORM epoch chain, a fresh verify_chain verdict, the public signing_key_id, the "
    "running version, and signed release provenance) and maps each MCPIP mechanism to the "
    "control clauses it provides evidence FOR. It asserts no SOC 2 report, no FedRAMP "
    "authorization, no ISO/DORA/EU-AI-Act certificate, no named customer, and no auditor "
    "sign-off. Achieving any certification is an external third-party process performed by an "
    "accredited assessor against a deploying organization's people, processes, and "
    "environment; this software cannot produce it. Where the chain is empty (no epoch sealed "
    "yet) the bundle says so honestly rather than fabricating a header."
)


# ---------------------------------------------------------------------------
# Static control-mapping manifest.
#
# Grounded in docs/COMPLIANCE.md §1 (the T-controls) + §2/§3 mappings, reusing the SAME
# mechanism language so the doc and this code agree. Each clause entry states the MCPIP
# mechanism, the concrete evidence it yields, a repository code pointer, and a coverage note.
# Phrasing is always "provides evidence FOR" — never "certified/authorized/passed".
# ---------------------------------------------------------------------------
_CONTROL_MAPPING: tuple[dict[str, Any], ...] = (
    {
        "framework": "EU AI Act",
        "reference": "Regulation (EU) 2024/1689",
        "certification_note": _CERTIFICATION_NOTE,
        "clauses": (
            {
                "clause": "Art. 12 — Record-keeping (automatic logging of events)",
                "mechanism": "Write-before-execute Merkle-epoch WORM ledger (T7)",
                "mcpip_evidence": (
                    "Every authorization decision is durably buffered and Ed25519-signed into a "
                    "root-chained per-epoch Merkle ledger BEFORE the action executes; the "
                    "attestation exports the sealed epoch head + a fresh verify_chain verdict as "
                    "tamper-evident proof the log exists and is intact."
                ),
                "code_pointer": "audit/worm_logger.py, audit/merkle.py, audit/anchor.py",
                "coverage": "provides-evidence-for",
            },
            {
                "clause": "Art. 14 — Human oversight",
                "mechanism": "Payload-bound one-time PIN step-up + staged human-in-the-loop challenge (T10)",
                "mcpip_evidence": (
                    "High-risk actions require an out-of-band one-time PIN bound to the exact "
                    "canonical payload; the staged challenge inserts a human approval gate before "
                    "execution, and both the staging and completion are recorded to WORM."
                ),
                "code_pointer": "auth/pin_validator.py, app/main.py (staged challenge)",
                "coverage": "provides-evidence-for",
            },
        ),
    },
    {
        "framework": "SEC 17a-4 / FINRA 4511",
        "reference": "17 CFR 240.17a-4(f) WORM recordkeeping; FINRA Rule 4511",
        "certification_note": _CERTIFICATION_NOTE,
        "clauses": (
            {
                "clause": "Non-rewritable, non-erasable (WORM) preservation of records",
                "mechanism": "Append-only Ed25519-signed root-chained ledger (T7)",
                "mcpip_evidence": (
                    "Records are append-only and root-chained; each epoch header is Ed25519-signed "
                    "so any rewrite or erasure breaks the chain and is detected by verify_chain."
                ),
                "code_pointer": "audit/worm_logger.py, audit/merkle.py",
                "coverage": "provides-evidence-for",
            },
            {
                "clause": "Detection of alteration / deletion of stored records",
                "mechanism": "Out-of-tamper-domain anchor low-watermark rollback/truncation detection (T7)",
                "mcpip_evidence": (
                    "A signed anchor head held outside the tamper domain detects tail truncation and "
                    "rollback; the attestation surfaces the anchor low-watermark and first_bad_epoch."
                ),
                "code_pointer": "audit/anchor.py",
                "coverage": "provides-evidence-for",
            },
        ),
    },
    {
        "framework": "DORA",
        "reference": "Regulation (EU) 2022/2554, Art. 9 & Art. 17",
        "certification_note": _CERTIFICATION_NOTE,
        "clauses": (
            {
                "clause": "Art. 9 — Protection & prevention (ICT logging integrity & retention)",
                "mechanism": "Durable WORM buffer (Redis AOF appendfsync always) + tamper-evident retention (T7)",
                "mcpip_evidence": (
                    "Production refuses to boot unless Redis AOF is appendfsync=always; the "
                    "retention low-watermark ties content integrity to the retention window so "
                    "recent-epoch event deletion reads as tamper, not trimming."
                ),
                "code_pointer": "audit/worm_logger.py (assert_persistence_posture, _verify_header_fields)",
                "coverage": "provides-evidence-for",
            },
            {
                "clause": "Art. 17 — ICT-related incident management (logging & fail-closed posture)",
                "mechanism": "Fail-closed boot + opaque fail-closed deny posture (T6)",
                "mcpip_evidence": (
                    "Missing keys/license/manifest or any ambiguity fails closed at boot or as an "
                    "opaque deny; concrete reasons are preserved only in the tamper-evident log for "
                    "incident reconstruction."
                ),
                "code_pointer": "core/config.py, app/main.py, interfaces.py (MCPIPDenied)",
                "coverage": "provides-evidence-for",
            },
        ),
    },
    {
        "framework": "NIST SP 800-53 rev. 5",
        "reference": "FedRAMP control families",
        "certification_note": _CERTIFICATION_NOTE,
        "clauses": (
            {
                "clause": "AU-10 — Non-repudiation",
                "mechanism": "Per-epoch Ed25519 signatures + O(log n) inclusion proofs (T7)",
                "mcpip_evidence": (
                    "Each epoch is Ed25519-signed and every event has a Merkle inclusion proof "
                    "bound to the public signing_key_id, so a recorded decision cannot be repudiated."
                ),
                "code_pointer": "audit/worm_logger.py, audit/merkle.py",
                "coverage": "provides-evidence-for",
            },
            {
                "clause": "AC-3 — Access enforcement (of approved authorizations)",
                "mechanism": "Capability-UUID gating; role authorizes nothing (T8/T9)",
                "mcpip_evidence": (
                    "Privileged actions gate on capability UUIDs matched constant-time; the JWT "
                    "role claim authorizes nothing."
                ),
                "code_pointer": "interfaces.py, obfuscator/alias_registry.py",
                "coverage": "provides-evidence-for",
            },
            {
                "clause": "AC-6 — Least privilege",
                "mechanism": "Compartments + TTL-bounded scoped grant issuance (T9)",
                "mcpip_evidence": (
                    "Compartmented aliases deny without a direct claim or an active delegated grant; "
                    "grants are explicit, TTL-bounded, and compartment-scoped — no tenant-wide master key."
                ),
                "code_pointer": "services/grant_store.py, obfuscator/alias_registry.py",
                "coverage": "provides-evidence-for",
            },
            {
                "clause": "IA-2 / IA-9 — Identification & service authentication",
                "mechanism": "JWT-only verified identity + identity-shaped-key hard deny (T8)",
                "mcpip_evidence": (
                    "Identity comes exclusively from a verified JWT (EdDSA/RS256; alg=none and "
                    "HMAC-confusion rejected); an identity- or capability-shaped key inside arguments "
                    "is a hard deny, not a strip."
                ),
                "code_pointer": "auth/token_resolver.py, bridge/intent_parser.py",
                "coverage": "provides-evidence-for",
            },
        ),
    },
    {
        "framework": "SOC 2",
        "reference": "AICPA Trust Services Criteria (2017, 2022 points of focus)",
        "certification_note": _CERTIFICATION_NOTE,
        "clauses": (
            {
                "clause": "CC6.1 — Logical access security",
                "mechanism": "JWT identity + capability-UUID authorization + payload-bound approval locks (T8/T9/T10)",
                "mcpip_evidence": (
                    "JWT-only identity, capability-UUID authorization, compartment need-to-know, and "
                    "exactly-once payload-bound approval locks on high-risk actions."
                ),
                "code_pointer": "auth/token_resolver.py, interfaces.py, auth/pin_validator.py",
                "coverage": "provides-evidence-for",
            },
            {
                "clause": "CC6.2 — Registration, authorization, and removal of access",
                "mechanism": "TTL-bounded, step-up-gated, audited grants (T9)",
                "mcpip_evidence": (
                    "Grants are explicit, TTL-bounded, compartment-scoped; issuance is itself an "
                    "authorized, step-up-gated, audited action; revocation/expiry re-denies immediately."
                ),
                "code_pointer": "services/grant_store.py, app/main.py (grant admin)",
                "coverage": "provides-evidence-for",
            },
        ),
    },
    {
        "framework": "ISO/IEC 42001",
        "reference": "AI management system — Annex A controls",
        "certification_note": _CERTIFICATION_NOTE,
        "clauses": (
            {
                "clause": "Annex A — Logging & traceability of AI system operation",
                "mechanism": "Write-before-execute WORM traceability (T7)",
                "mcpip_evidence": (
                    "Every AI tool-call decision is traceable to a signed, tamper-evident record "
                    "emitted before execution and independently verifiable via the attestation."
                ),
                "code_pointer": "audit/worm_logger.py",
                "coverage": "provides-evidence-for",
            },
            {
                "clause": "Annex A — Human oversight of AI systems",
                "mechanism": "Payload-bound one-time PIN oversight (T10)",
                "mcpip_evidence": (
                    "High-risk AI actions require an out-of-band human-approved one-time PIN bound to "
                    "the exact payload before execution."
                ),
                "code_pointer": "auth/pin_validator.py",
                "coverage": "provides-evidence-for",
            },
            {
                "clause": "Annex A — Resilience & fail-safe operation",
                "mechanism": "Opaque fail-closed posture (T6)",
                "mcpip_evidence": (
                    "Any ambiguity or dependency failure fails closed as an opaque deny; reasons live "
                    "only in the tamper-evident log, so a probing agent learns nothing."
                ),
                "code_pointer": "core/config.py, app/main.py, interfaces.py (MCPIPDenied)",
                "coverage": "provides-evidence-for",
            },
        ),
    },
)


# JSON-serializable public view of the static mapping (tuples → lists), computed once. It is
# deep-copied on every bundle build so a returned bundle can never mutate this source.
CONTROL_MAPPING: list[dict[str, Any]] = [
    {
        "framework": block["framework"],
        "reference": block["reference"],
        "certification_note": block["certification_note"],
        "clauses": [dict(clause) for clause in block["clauses"]],
    }
    for block in _CONTROL_MAPPING
]


_EMPTY_STATE_NOTE = (
    "No epoch has been sealed yet; the WORM chain is empty but verifiable. This is honest "
    "empty state, not a fabricated header — signing_key_id and the verify_chain verdict are "
    "still the gateway's real values."
)


def build_evidence_bundle(
    attestation: "WormAttestation",
    gateway_version: str,
    release_provenance: dict[str, Optional[object]],
    generated_at: str,
) -> dict[str, Any]:
    """
    Assemble the portable compliance-evidence bundle from ALREADY-FETCHED real gateway state.

    PURE: no I/O, no clock, no signing. Serializes the ``WormAttestation`` fields 1:1 (the same
    signed commitments ``/v1/audit/attestation`` emits), the running ``gateway_version``, the
    signed ``release_provenance`` (version + public signing_key_id + verified bool), the static
    ``CONTROL_MAPPING``, and ``BUNDLE_DISCLAIMER``. Derives ``sealed`` honestly from whether an
    epoch has been sealed and attaches an ``empty_state_note`` when it has not. Contains NO
    target, payload, PIN/OTP, or vended credential — only signed commitments and static text.
    """
    sealed = attestation.epoch is not None
    bundle: dict[str, Any] = {
        "generated_at": generated_at,
        "gateway_version": gateway_version,
        "release_provenance": {
            "version": release_provenance.get("version"),
            "signing_key_id": release_provenance.get("signing_key_id"),
            "verified": release_provenance.get("verified"),
        },
        "sealed": sealed,
        "attestation": {
            "epoch": attestation.epoch,
            "end_seq": attestation.end_seq,
            "merkle_root": attestation.merkle_root,
            "epoch_hash": attestation.epoch_hash,
            "signature": attestation.signature,
            "signing_key_id": attestation.signing_key_id,
            "intact": attestation.intact,
            "first_bad_epoch": attestation.first_bad_epoch,
            "anchor_epoch": attestation.anchor_epoch,
            "anchor_epoch_hash": attestation.anchor_epoch_hash,
        },
        "control_mapping": copy.deepcopy(CONTROL_MAPPING),
        "disclaimer": BUNDLE_DISCLAIMER,
    }
    if not sealed:
        bundle["empty_state_note"] = _EMPTY_STATE_NOTE
    return bundle
