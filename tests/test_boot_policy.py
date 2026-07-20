"""
MCPIP — production boot policy: sender-constraint lint.

    ◐ "Fail closed at boot: the secure posture cannot be silently forgotten."

`_enforce_sender_constraint_policy` is a production (``sandbox_mode=False``)
boot-refusal, in the same family as the integrity-manifest / license / signing-key
refusals. It guarantees that a RESTRICTED/CLASSIFIED alias with NO human step-up
(i.e. `RiskTier.AUTO`, so no payload-bound PIN) cannot be served unless it also
demands a sender-constrained token — otherwise a stolen bearer that clears the
compartment gate would exfiltrate sensitive data on every request.

These are pure-function tests (no Redis, no app boot). The env is set to sandbox
before importing `app.main` only so importing the module's composition root does
not itself trip the production refusals.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MCPIP_SANDBOX_MODE", "true")
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/5")

import pytest

from app.main import _enforce_sender_constraint_policy
from interfaces import Classification, RiskTier
from obfuscator import build_demo_registry
from obfuscator.alias_registry import AliasEntry, AliasRegistry


def _reg(entry: AliasEntry) -> AliasRegistry:
    reg = AliasRegistry()
    reg.register("t", entry)
    return reg


def test_sensitive_auto_without_flag_refuses_production_boot() -> None:
    """A CLASSIFIED AUTO alias missing require_sender_constraint → RuntimeError in prod."""
    reg = _reg(
        AliasEntry(
            "skill_secret_read", "rest.x.get", "cloud_rest", RiskTier.AUTO,
            classification=Classification.CLASSIFIED,
        )
    )
    with pytest.raises(RuntimeError, match="require_sender_constraint"):
        _enforce_sender_constraint_policy(reg, sandbox_mode=False)


def test_restricted_auto_without_flag_refuses_production_boot() -> None:
    """RESTRICTED is sensitive too (covers the PHI/PII reads)."""
    reg = _reg(
        AliasEntry(
            "skill_pii_read", "rest.pii.get", "cloud_rest", RiskTier.AUTO,
            classification=Classification.RESTRICTED,
        )
    )
    with pytest.raises(RuntimeError, match="skill_pii_read"):
        _enforce_sender_constraint_policy(reg, sandbox_mode=False)


def test_sensitive_auto_with_flag_boots() -> None:
    """The same alias WITH require_sender_constraint boots clean."""
    reg = _reg(
        AliasEntry(
            "skill_secret_read", "rest.x.get", "cloud_rest", RiskTier.AUTO,
            classification=Classification.CLASSIFIED, require_sender_constraint=True,
        )
    )
    _enforce_sender_constraint_policy(reg, sandbox_mode=False)  # no raise


def test_pin_required_sensitive_is_exempt() -> None:
    """A CLASSIFIED PIN_REQUIRED write is exempt — the OTP is the human control."""
    reg = _reg(
        AliasEntry(
            "skill_secret_write", "rest.x.set", "cloud_rest", RiskTier.PIN_REQUIRED,
            classification=Classification.CLASSIFIED,
        )
    )
    _enforce_sender_constraint_policy(reg, sandbox_mode=False)  # no raise


def test_unclassified_auto_is_exempt() -> None:
    """A non-sensitive AUTO read needs no proof — the keyless majority is untouched."""
    reg = _reg(
        AliasEntry("skill_status", "rest.status.get", "cloud_rest", RiskTier.AUTO)
    )
    _enforce_sender_constraint_policy(reg, sandbox_mode=False)  # no raise


def test_sandbox_is_exempt_even_when_offending() -> None:
    """Sandbox never trips the lint (it demonstrates the compartment model with bearers)."""
    reg = _reg(
        AliasEntry(
            "skill_secret_read", "rest.x.get", "cloud_rest", RiskTier.AUTO,
            classification=Classification.CLASSIFIED,
        )
    )
    _enforce_sender_constraint_policy(reg, sandbox_mode=True)  # skipped, no raise


def test_shipped_demo_catalog_is_production_clean() -> None:
    """The reference catalog is secure-by-default: every sensitive AUTO read is flagged,
    so it passes its own production lint."""
    _enforce_sender_constraint_policy(build_demo_registry(), sandbox_mode=False)  # no raise
