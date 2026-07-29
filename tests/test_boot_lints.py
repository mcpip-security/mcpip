"""
MCPIP — production boot lints: identity/transport config + key-file permissions.

    ◐ "Fail closed at boot on the unambiguously-wrong; warn loud on the loose."

Companions to ``test_boot_policy.py``. These cover the SOC 2 readiness boot lints:

  * ``_enforce_production_config`` — refuse the shipped DEMO jwt issuer/audience in
    production (a predictable, published audience is a downgrade); warn (never refuse)
    on a plaintext ``redis://`` backplane, since internal-network isolation is a valid
    documented control.
  * ``_assert_secure_key_file`` — refuse a group/world-WRITABLE private key/secret in
    production (a swappable key controls identity/audit/vault); warn (never refuse) on
    a group/world-READABLE file (the common k8s 0644 secret-mount pattern).

Pure-function tests (no Redis, no app boot). Sandbox is set before importing
``app.main`` only so the module's composition root does not trip the prod refusals.
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MCPIP_SANDBOX_MODE", "true")
os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/5")

import pytest

from app.main import _assert_secure_key_file, _enforce_production_config
from core.config import Settings


def _settings(**over: object) -> Settings:
    base: dict[str, object] = {
        "sandbox_mode": False,
        "jwt_issuer": "corp-idp",
        "jwt_audience": "corp-gateway",
        "redis_url": "rediss://redis.internal:6379/0",
    }
    base.update(over)
    return Settings(**base)  # type: ignore[arg-type]


# --- _enforce_production_config ------------------------------------------------


def test_demo_issuer_refuses_production_boot() -> None:
    with pytest.raises(RuntimeError, match="non-demo"):
        _enforce_production_config(_settings(jwt_issuer="mcpip-demo-idp"))


def test_demo_audience_refuses_production_boot() -> None:
    with pytest.raises(RuntimeError, match="non-demo"):
        _enforce_production_config(_settings(jwt_audience="mcpip-gateway"))


def test_custom_issuer_audience_boots_clean() -> None:
    _enforce_production_config(_settings())  # no raise


def test_plaintext_redis_warns_not_refuses(capsys: pytest.CaptureFixture[str]) -> None:
    # redis:// in prod is a loud warning, never a boot refusal.
    _enforce_production_config(_settings(redis_url="redis://redis.internal:6379/0"))
    assert "plaintext" in capsys.readouterr().err.lower()


def test_sandbox_is_exempt_from_config_lint() -> None:
    # Even with the demo defaults, sandbox never trips the refusal.
    _enforce_production_config(
        _settings(sandbox_mode=True, jwt_issuer="mcpip-demo-idp", jwt_audience="mcpip-gateway")
    )


# --- _assert_secure_key_file ---------------------------------------------------


def _keyfile(tmp_path, mode: int) -> str:
    p = tmp_path / "master.key"
    p.write_bytes(b"x" * 32)
    os.chmod(p, mode)
    return str(p)


def test_world_writable_key_refuses_production_boot(tmp_path) -> None:
    path = _keyfile(tmp_path, 0o666)
    with pytest.raises(RuntimeError, match="writable"):
        _assert_secure_key_file(path, sandbox_mode=False, label="vault master")


def test_group_writable_key_refuses_production_boot(tmp_path) -> None:
    path = _keyfile(tmp_path, 0o620)
    with pytest.raises(RuntimeError, match="writable"):
        _assert_secure_key_file(path, sandbox_mode=False, label="WORM signing")


def test_0600_key_boots_clean(tmp_path) -> None:
    path = _keyfile(tmp_path, 0o600)
    _assert_secure_key_file(path, sandbox_mode=False, label="vault master")  # no raise


def test_readable_key_warns_not_refuses(
    tmp_path, capsys: pytest.CaptureFixture[str]
) -> None:
    # 0644 (the common k8s secret-mount default) is a warning, never a refusal.
    path = _keyfile(tmp_path, 0o644)
    _assert_secure_key_file(path, sandbox_mode=False, label="forensic master")
    assert "readable" in capsys.readouterr().err.lower()


def test_sandbox_is_exempt_from_key_perm_check(tmp_path) -> None:
    path = _keyfile(tmp_path, 0o666)  # even world-writable
    _assert_secure_key_file(path, sandbox_mode=True, label="vault master")  # no raise


def test_missing_key_file_does_not_mask_the_readers_error(tmp_path) -> None:
    # A missing file is left for the caller's own read to fail-close with a clearer error.
    _assert_secure_key_file(str(tmp_path / "nope.key"), sandbox_mode=False, label="x")
