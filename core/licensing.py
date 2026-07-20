"""
MCPIP V2 — Core: offline license / entitlement gate (fail-closed, boot-time only).

    ◐ "Authorize every AI action before execution."

A license is a small JSON document signed OFFLINE with the dedicated Ed25519
license-root key (a SEPARATE keypair from both the release-root key and the WORM
epoch-signing key). Verification needs no network and no vendor service — the
public key ships with the release and the check is pure local cryptography, so
air-gapped enclaves validate entitlements exactly like connected deployments.

Separation of concerns (normative): licensing gates PROCESS BOOT only. The
verified :class:`License` is held on the composition root for operator
visibility, but it is NEVER consulted by the authorization pipeline — a per-
request entitlement check would entangle commercial state with the security
decision path. Expiry is checked at boot only: deployments are immutable, and
the operator's change-control cadence re-verifies on every redeploy.

Failure posture mirrors the integrity self-check: every specific cause is logged
at CRITICAL on ``mcpip.boot``, while the raised error is the OPAQUE
``license verification failed`` — nothing about the customer, tier, or dates
leaks through crash loops.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import json
import logging
from pathlib import Path
from typing import Any, NoReturn, Optional

from core.integrity import verify_ed25519_signature

_OPAQUE_ERROR = "license verification failed"
_LICENSE_SCHEMA = "mcpip-license/1"
# Closed tier set — anything else is a forgery or a newer, unknown grammar; both
# are fail-closed (an old gateway must not guess at entitlements it cannot parse).
_VALID_TIERS = frozenset({"cloud", "self-hosted", "air-gapped"})

_log = logging.getLogger("mcpip.boot")


@dataclass(frozen=True)
class License:
    """The verified, immutable view of a customer entitlement document."""

    license_id: str
    customer: str
    tier: str
    issued_at: datetime
    expires_at: datetime
    entitlements: frozenset[str]


class LicenseError(Exception):
    """
    A license document failed to verify or validate.

    Raised by :func:`verify_license_bytes` on ANY problem (malformed JSON, unknown
    schema, bad/forged/wrong-root Ed25519 signature, tier outside the closed set,
    malformed fields, expired, not-yet-valid). It carries only the operator-facing
    cause string.

    The BOOT gate (:func:`load_and_verify_license`) catches this and re-raises the
    OPAQUE ``RuntimeError("license verification failed")`` after CRITICAL-logging the
    cause, so boot behavior is byte-identical to before this exception existed. The
    OFF-hot-path license REFRESH (``services/license_refresh.py``) catches it to RETAIN
    the last-good license — a failed refresh is best-effort, never a brick, never a
    fail-open to unlicensed.
    """


def _fail(cause: str) -> NoReturn:
    """CRITICAL-log the specific cause, then raise the OPAQUE boot error."""
    _log.critical("license gate failed: %s", cause)
    raise RuntimeError(_OPAQUE_ERROR)


def _parse_utc(value: object, field: str) -> datetime:
    """Parse an ISO-8601 timestamp (Z or offset) to an aware UTC datetime."""
    if not isinstance(value, str):
        raise LicenseError(f"{field} missing or not a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise LicenseError(f"{field} is not valid ISO-8601") from None
    if parsed.tzinfo is None:
        # A naive timestamp is ambiguous; the license grammar requires UTC.
        raise LicenseError(f"{field} lacks a timezone")
    return parsed.astimezone(timezone.utc)


def verify_license_bytes(
    raw: bytes, public_key_pem: bytes, *, now: Optional[datetime] = None
) -> License:
    """
    Signature-verify + validity-check a license from its raw bytes. Fail-closed.

    This is the SINGLE authoritative validator — the exact checks the boot gate
    applies (schema ``mcpip-license/1``; Ed25519 signature over the §2 canonical
    bytes with the license-ROOT key; ``tier`` in the closed 3-set; string
    ``license_id`` / ``customer``; ``entitlements`` a list of strings;
    ``issued_at <= now < expires_at``). It NEVER widens verification, NEVER adds a
    trust root, and NEVER accepts an unsigned / forged / wrong-root / expired
    document.

    Raises :class:`LicenseError` on ANY problem (the concrete cause). Both callers —
    the boot gate and the off-hot-path refresh — reuse it VERBATIM, so a refreshed
    candidate is held to exactly the boot bar. ``public_key_pem`` is the EXISTING
    license-root public key the boot gate loads; passing any other key is the caller's
    bug, not a widening this function permits.
    """
    moment = now if now is not None else datetime.now(timezone.utc)

    try:
        loaded: Any = json.loads(raw)
    except ValueError as exc:
        raise LicenseError(f"license malformed ({type(exc).__name__})") from exc

    if not isinstance(loaded, dict):
        raise LicenseError("license is not a JSON object")
    document: dict[str, Any] = loaded
    if document.get("schema") != _LICENSE_SCHEMA:
        raise LicenseError("unknown license schema")

    try:
        verify_ed25519_signature(document, public_key_pem)
    except Exception as exc:  # noqa: BLE001 — any signature problem is terminal.
        raise LicenseError(f"license signature invalid ({type(exc).__name__})") from exc

    license_id = document.get("license_id")
    customer = document.get("customer")
    tier = document.get("tier")
    raw_entitlements = document.get("entitlements")
    if not isinstance(license_id, str) or not license_id:
        raise LicenseError("license_id missing or not a string")
    if not isinstance(customer, str) or not customer:
        raise LicenseError("customer missing or not a string")
    if not isinstance(tier, str) or tier not in _VALID_TIERS:
        raise LicenseError("tier missing or outside the closed set")
    if not isinstance(raw_entitlements, list) or not all(
        isinstance(item, str) for item in raw_entitlements
    ):
        raise LicenseError("entitlements missing or not a list of strings")

    issued_at = _parse_utc(document.get("issued_at"), "issued_at")
    expires_at = _parse_utc(document.get("expires_at"), "expires_at")
    if expires_at <= moment:
        raise LicenseError("license expired")
    if issued_at > moment:
        raise LicenseError("license not yet valid (issued_at in the future)")

    return License(
        license_id=license_id,
        customer=customer,
        tier=tier,
        issued_at=issued_at,
        expires_at=expires_at,
        entitlements=frozenset(raw_entitlements),
    )


def is_newer_license(candidate: License, current: License) -> bool:
    """
    True iff ``candidate`` was issued STRICTLY after ``current``.

    A pure ordering helper for the off-hot-path refresh's atomic-swap decision: a
    valid candidate replaces the running license ONLY when it is strictly newer, so a
    replayed or stale (older-or-equal) document — even a perfectly-signed one — is
    never swapped in. The validity WINDOW (``issued_at <= now < expires_at``) is
    already enforced by :func:`verify_license_bytes`; this compares only issuance
    recency. It does NOT gate boot and is never consulted by the authorization
    pipeline.
    """
    return candidate.issued_at > current.issued_at


def load_and_verify_license(
    license_path: Path, public_key_pem: bytes, *, now: Optional[datetime] = None
) -> License:
    """
    Load, signature-verify, and validity-check a license file. Fail-closed.

    Reads the file (an unreadable path is fail-closed) then delegates every content
    check to :func:`verify_license_bytes`. Raises
    ``RuntimeError("license verification failed")`` on ANY problem: unreadable/
    malformed JSON, unknown schema, bad Ed25519 signature (over the §2 canonical
    bytes), tier outside the closed 3-set, malformed fields, ``expires_at <= now``,
    or ``issued_at > now``. The concrete cause goes only to the ``mcpip.boot`` logger
    at CRITICAL — boot behavior is byte-identical to before the verifier was extracted.
    """
    try:
        raw = license_path.read_bytes()
    except OSError as exc:
        _fail(f"license unreadable ({type(exc).__name__})")

    try:
        return verify_license_bytes(raw, public_key_pem, now=now)
    except LicenseError as exc:
        _fail(str(exc))
