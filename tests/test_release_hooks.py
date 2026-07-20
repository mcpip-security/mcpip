"""
MCPIP V2 — Release-capstone app hooks test suite (Builder A surface).

    ◐ "Authorize every AI action before execution."

Covers the four boot/observability hooks added to ``app.main`` + ``core/``:

  * STARTUP INTEGRITY SELF-CHECK — verified boot passes on a matching signed
    manifest, and FAILS CLOSED (nonzero exit, no socket) on tamper, on a missing
    listed file, on a bad signature, and on a production boot without paths. The
    dev-only bypass boots with its loud banner.
  * LICENSE / ENTITLEMENT GATE — valid dev license boots; expired / tampered /
    malformed licenses fail closed with the OPAQUE error only.
  * ``/metrics`` — Prometheus text with NO sensitive label material.
  * ``/healthz`` — carries the single-source release version.

Boot-level scenarios run in SUBPROCESSES (``import app.main`` builds the
composition root at import, and its settings are process-global), so this file
never perturbs the sibling suites' import of ``app.main``. Fixture keys and
manifests are generated per-session in tmp dirs — no dependency on the release
tooling scripts, and nothing key-like is written inside the repo.

Requires the dev Redis container (``mcpip-v2-redis``) on localhost:63790.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Mapping, Optional

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PublicFormat,
)

# Repo root importable when run directly; pytest adds it via rootdir.
_REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO_ROOT))

from core.integrity import canonical_signed_bytes, verify_boot_integrity
from core.licensing import load_and_verify_license
from core.version import get_version

_BOOT_REDIS_URL = "redis://localhost:63790/11"

# The normative integrity file set (§6): every *.py under these roots plus the
# top-level modules and VERSION, repo-root-relative POSIX paths, sorted.
_INTEGRITY_ROOTS = (
    "app",
    "core",
    "auth",
    "audit",
    "bridge",
    "services",
    "models",
    "obfuscator",
    "mcpip_verify",
)
_INTEGRITY_EXTRAS = ("interfaces.py", "main.py", "VERSION")

# Sensitive material that must NEVER appear in /metrics exposition: tenant ids,
# aliases, compartment names, JWT prefixes, correlation-id/UUID shapes.
_SENSITIVE_METRIC_FRAGMENTS = (
    "tenant-acme",
    "aegis-dynamics",
    "skill_",
    "eyJ",  # base64 JWT header prefix
    "correlation",
    "challenge",
)


# ---------------------------------------------------------------------------
# Signing helpers (local reimplementation of the §2 normative rule).
# ---------------------------------------------------------------------------


def _sign_document(document: dict[str, Any], private_key: Ed25519PrivateKey) -> dict[str, Any]:
    """Attach the base64 Ed25519 signature over the canonical unsigned bytes."""
    unsigned = {key: value for key, value in document.items() if key != "signature"}
    signature = private_key.sign(canonical_signed_bytes(unsigned))
    signed = dict(unsigned)
    signed["signature"] = base64.b64encode(signature).decode("ascii")
    return signed


def _public_pem(private_key: Ed25519PrivateKey) -> bytes:
    return private_key.public_key().public_bytes(
        Encoding.PEM, PublicFormat.SubjectPublicKeyInfo
    )


def _integrity_file_set() -> list[str]:
    files: list[str] = []
    for root in _INTEGRITY_ROOTS:
        base = _REPO_ROOT / root
        if not base.is_dir():
            continue  # mcpip_verify may not exist until the tooling builder lands.
        for path in base.rglob("*.py"):
            if "__pycache__" in path.parts:
                continue
            files.append(path.relative_to(_REPO_ROOT).as_posix())
    for extra in _INTEGRITY_EXTRAS:
        if (_REPO_ROOT / extra).is_file():
            files.append(extra)
    return sorted(files)


def _build_integrity_manifest(private_key: Ed25519PrivateKey) -> dict[str, Any]:
    entries = [
        {
            "path": rel,
            "sha256": hashlib.sha256((_REPO_ROOT / rel).read_bytes()).hexdigest(),
        }
        for rel in _integrity_file_set()
    ]
    manifest: dict[str, Any] = {
        "schema": "mcpip-integrity-manifest/1",
        "version": get_version(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": entries,
    }
    return _sign_document(manifest, private_key)


def _build_license(
    private_key: Ed25519PrivateKey,
    *,
    days: int = 365,
    tier: str = "self-hosted",
    issued_delta_days: int = 0,
) -> dict[str, Any]:
    now = datetime.now(timezone.utc)
    document: dict[str, Any] = {
        "schema": "mcpip-license/1",
        "license_id": "6a2f1f7e-0000-4000-8000-000000000042",
        "customer": "release-hooks-test",
        "tier": tier,
        "issued_at": (now + timedelta(days=issued_delta_days)).isoformat(),
        "expires_at": (now + timedelta(days=days)).isoformat(),
        "entitlements": ["authorize", "mcp_edge", "audit_export", "metrics"],
    }
    return _sign_document(document, private_key)


# ---------------------------------------------------------------------------
# Session fixtures — demo keys, signed manifest, dev license (all in tmp).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class HookFixtures:
    release_private: Ed25519PrivateKey
    license_private: Ed25519PrivateKey
    release_pub_path: Path
    license_pub_path: Path
    manifest_path: Path
    license_path: Path
    workdir: Path


@pytest.fixture(scope="session")
def hooks(tmp_path_factory: pytest.TempPathFactory) -> HookFixtures:
    workdir = tmp_path_factory.mktemp("release-hooks")
    release_private = Ed25519PrivateKey.generate()
    license_private = Ed25519PrivateKey.generate()

    release_pub_path = workdir / "release_root_ed25519.pub.pem"
    license_pub_path = workdir / "license_root_ed25519.pub.pem"
    release_pub_path.write_bytes(_public_pem(release_private))
    license_pub_path.write_bytes(_public_pem(license_private))

    manifest_path = workdir / "integrity_manifest.json"
    manifest_path.write_text(
        json.dumps(_build_integrity_manifest(release_private), indent=2),
        encoding="utf-8",
    )

    license_path = workdir / "dev_license.json"
    license_path.write_text(
        json.dumps(_build_license(license_private), indent=2), encoding="utf-8"
    )

    return HookFixtures(
        release_private=release_private,
        license_private=license_private,
        release_pub_path=release_pub_path,
        license_pub_path=license_pub_path,
        manifest_path=manifest_path,
        license_path=license_path,
        workdir=workdir,
    )


def _hook_env(
    hooks: HookFixtures, workdir: Path, overrides: Optional[Mapping[str, str]] = None
) -> dict[str, str]:
    """A clean MCPIP_* environment with all four hook paths set (sandbox mode)."""
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCPIP_")}
    env.update(
        {
            "MCPIP_SANDBOX_MODE": "true",
            "MCPIP_REDIS_URL": _BOOT_REDIS_URL,
            "MCPIP_WORM_PATH": str(workdir / "worm.jsonl"),
            "MCPIP_INTEGRITY_MANIFEST_PATH": str(hooks.manifest_path),
            "MCPIP_INTEGRITY_PUBLIC_KEY_PATH": str(hooks.release_pub_path),
            "MCPIP_LICENSE_PATH": str(hooks.license_path),
            "MCPIP_LICENSE_PUBLIC_KEY_PATH": str(hooks.license_pub_path),
        }
    )
    if overrides:
        env.update(overrides)
    return env


def _boot_import(env: dict[str, str]) -> "subprocess.CompletedProcess[str]":
    """``import app.main`` in a subprocess — runs the full composition root."""
    return subprocess.run(
        [sys.executable, "-c", "import app.main"],
        cwd=_REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=120,
    )


# ---------------------------------------------------------------------------
# Unit level — version, licensing, integrity, metrics rendering.
# ---------------------------------------------------------------------------


def test_version_is_single_sourced() -> None:
    on_disk = (_REPO_ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert get_version() == on_disk
    assert get_version().count(".") == 2


def test_license_valid_roundtrip(hooks: HookFixtures) -> None:
    verified = load_and_verify_license(
        hooks.license_path, hooks.license_pub_path.read_bytes()
    )
    assert verified.customer == "release-hooks-test"
    assert verified.tier == "self-hosted"
    assert "authorize" in verified.entitlements
    assert verified.expires_at > datetime.now(timezone.utc)


@pytest.mark.parametrize(
    "mutation",
    ["expired", "future_issued", "bad_tier", "tampered_signature", "wrong_key"],
)
def test_license_failures_are_opaque(
    hooks: HookFixtures, tmp_path: Path, mutation: str
) -> None:
    pub = hooks.license_pub_path.read_bytes()
    if mutation == "expired":
        document = _build_license(hooks.license_private, days=-1)
    elif mutation == "future_issued":
        document = _build_license(hooks.license_private, issued_delta_days=30)
    elif mutation == "bad_tier":
        document = _build_license(hooks.license_private, tier="enterprise-platinum")
    elif mutation == "tampered_signature":
        document = _build_license(hooks.license_private)
        document["customer"] = "someone-else"  # invalidates the signature
    else:  # wrong_key — signed by an unrelated root.
        document = _build_license(Ed25519PrivateKey.generate())

    target = tmp_path / "license.json"
    target.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(RuntimeError) as excinfo:
        load_and_verify_license(target, pub)
    # OPAQUE: exactly the generic message — no customer, tier, date, or path.
    assert str(excinfo.value) == "license verification failed"


def test_integrity_verifies_then_fails_closed_on_tamper(
    hooks: HookFixtures, tmp_path: Path
) -> None:
    base = tmp_path / "tree"
    base.mkdir()
    (base / "module.py").write_text("GLYPH = 'half-circle'\n", encoding="utf-8")
    manifest: dict[str, Any] = {
        "schema": "mcpip-integrity-manifest/1",
        "version": get_version(),
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "files": [
            {
                "path": "module.py",
                "sha256": hashlib.sha256(
                    (base / "module.py").read_bytes()
                ).hexdigest(),
            }
        ],
    }
    signed = _sign_document(manifest, hooks.release_private)
    manifest_path = tmp_path / "manifest.json"
    manifest_path.write_text(json.dumps(signed), encoding="utf-8")
    pub = hooks.release_pub_path.read_bytes()

    # Pristine tree verifies.
    verify_boot_integrity(manifest_path, pub, base)

    # (a) Tampered file content → opaque RuntimeError, no filename in message.
    (base / "module.py").write_text("GLYPH = 'tampered'\n", encoding="utf-8")
    with pytest.raises(RuntimeError) as tampered:
        verify_boot_integrity(manifest_path, pub, base)
    assert str(tampered.value) == "integrity verification failed"
    assert "module.py" not in str(tampered.value)

    # (b) Missing listed file → same opaque failure.
    (base / "module.py").unlink()
    with pytest.raises(RuntimeError, match="^integrity verification failed$"):
        verify_boot_integrity(manifest_path, pub, base)

    # (c) Manifest signed by the WRONG root → same opaque failure.
    (base / "module.py").write_text("GLYPH = 'half-circle'\n", encoding="utf-8")
    forged = _sign_document(manifest, Ed25519PrivateKey.generate())
    forged_path = tmp_path / "forged.json"
    forged_path.write_text(json.dumps(forged), encoding="utf-8")
    with pytest.raises(RuntimeError, match="^integrity verification failed$"):
        verify_boot_integrity(forged_path, pub, base)


def test_render_metrics_exposition_and_label_hygiene() -> None:
    from core.metrics import DECISIONS, SHED, render_metrics

    # Touch label sets exactly the way app.main does: coarse ``decision`` outcome ONLY.
    # The concrete deny reason is NEVER a label (it would leak on the unauthenticated,
    # agent-reachable /metrics socket) — so the counter takes exactly one label.
    DECISIONS.labels("deny").inc()
    DECISIONS.labels("allow").inc()
    DECISIONS.labels("staged").inc()
    SHED.labels("oversized").inc()

    payload, content_type = render_metrics()
    text = payload.decode("utf-8")
    assert "text/plain" in content_type
    for family in (
        "mcpip_authorize_decisions_total",
        "mcpip_authorize_latency_seconds",
        "mcpip_requests_shed_total",
        "mcpip_worm_epoch",
        "mcpip_worm_sequence",
    ):
        assert family in text
    # The coarse outcome is present; the concrete deny reason must NOT be a label at all.
    assert 'mcpip_authorize_decisions_total{decision="deny"}' in text
    assert "deny_reason" not in text
    for fragment in _SENSITIVE_METRIC_FRAGMENTS:
        assert fragment not in text


# ---------------------------------------------------------------------------
# Boot level — full composition root in subprocesses (fail-closed semantics).
# ---------------------------------------------------------------------------


def test_boot_with_hooks_serves_probes_and_metrics(
    hooks: HookFixtures, tmp_path: Path
) -> None:
    """Sandbox boot with ALL hooks enabled: healthz/readyz/metrics live."""
    driver = (
        "import json\n"
        "from fastapi.testclient import TestClient\n"
        "from app.main import app\n"
        "with TestClient(app) as client:\n"
        "    health = client.get('/healthz')\n"
        "    ready = client.get('/readyz')\n"
        "    bad = client.post(\n"
        "        '/v1/authorize',\n"
        "        json={\n"
        "            'source_format': 'openai_tool_call',\n"
        "            'jwt': 'not-a-real-token',\n"
        "            'tool_call': {\n"
        "                'id': 'call_x', 'type': 'function',\n"
        "                'function': {'name': 'skill_spend_summary',\n"
        "                             'arguments': '{}'},\n"
        "            },\n"
        "        },\n"
        "    )\n"
        "    metrics = client.get('/metrics')\n"
        "print('RESULT::' + json.dumps({\n"
        "    'health_status': health.status_code,\n"
        "    'health_body': health.json(),\n"
        "    'ready_status': ready.status_code,\n"
        "    'deny_status': bad.status_code,\n"
        "    'metrics_status': metrics.status_code,\n"
        "    'metrics_type': metrics.headers['content-type'],\n"
        "    'metrics_text': metrics.text,\n"
        "}))\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", driver],
        cwd=_REPO_ROOT,
        env=_hook_env(hooks, tmp_path),
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert result.returncode == 0, result.stderr
    line = next(
        raw for raw in result.stdout.splitlines() if raw.startswith("RESULT::")
    )
    report = json.loads(line[len("RESULT::") :])

    assert report["health_status"] == 200
    assert report["health_body"]["version"] == get_version()
    assert report["health_body"]["status"] == "live"
    assert report["ready_status"] == 200
    # The garbage-JWT authorize is an opaque 403 AND lands in the deny counter.
    assert report["deny_status"] == 403
    assert report["metrics_status"] == 200
    assert "text/plain" in report["metrics_type"]
    exposition = report["metrics_text"]
    # The coarse deny outcome is counted, but the concrete reason must NEVER be exposed on
    # this unauthenticated, agent-reachable socket (opacity / canary-oracle guard): the
    # counter has ONLY a ``decision`` label, and no ``deny_reason``/``jwt_invalid`` leaks.
    assert 'mcpip_authorize_decisions_total{decision="deny"}' in exposition
    assert "deny_reason" not in exposition
    assert "jwt_invalid" not in exposition
    for fragment in _SENSITIVE_METRIC_FRAGMENTS:
        assert fragment not in exposition
    # License banner recorded id/tier/expiry — never the customer name.
    assert "MCPIP LICENSE: verified" in result.stderr
    assert "release-hooks-test" not in result.stderr


def test_boot_fails_closed_on_tampered_source_hash(
    hooks: HookFixtures, tmp_path: Path
) -> None:
    """Flip one hash byte in a SIGNED-then-tampered manifest → refuse to start."""
    manifest = json.loads(hooks.manifest_path.read_text(encoding="utf-8"))
    entry = manifest["files"][0]
    original = entry["sha256"]
    entry["sha256"] = ("0" if original[0] != "0" else "1") + original[1:]
    tampered_path = tmp_path / "tampered_manifest.json"
    tampered_path.write_text(json.dumps(manifest), encoding="utf-8")

    # Tampering the manifest breaks its SIGNATURE first — fails closed.
    result = _boot_import(
        _hook_env(
            hooks, tmp_path, {"MCPIP_INTEGRITY_MANIFEST_PATH": str(tampered_path)}
        )
    )
    assert result.returncode != 0
    assert "integrity verification failed" in result.stderr

    # Re-SIGN the tampered hash list (attacker WITHOUT the root key cannot; this
    # simulates a changed source file with a legitimate manifest) → still refuses.
    resigned = _sign_document(manifest, hooks.release_private)
    resigned_path = tmp_path / "resigned_manifest.json"
    resigned_path.write_text(json.dumps(resigned), encoding="utf-8")
    result = _boot_import(
        _hook_env(
            hooks, tmp_path, {"MCPIP_INTEGRITY_MANIFEST_PATH": str(resigned_path)}
        )
    )
    assert result.returncode != 0
    assert "integrity verification failed" in result.stderr


def test_boot_fails_closed_on_expired_license(
    hooks: HookFixtures, tmp_path: Path
) -> None:
    expired = _build_license(hooks.license_private, days=-1)
    expired_path = tmp_path / "expired_license.json"
    expired_path.write_text(json.dumps(expired), encoding="utf-8")
    result = _boot_import(
        _hook_env(hooks, tmp_path, {"MCPIP_LICENSE_PATH": str(expired_path)})
    )
    assert result.returncode != 0
    assert "license verification failed" in result.stderr


def test_production_boot_requires_hook_paths(
    hooks: HookFixtures, tmp_path: Path
) -> None:
    """Non-sandbox boot without integrity/license config refuses to start."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding as Enc,
        NoEncryption,
        PrivateFormat,
    )

    jwt_pub = tmp_path / "jwt_public.pem"
    jwt_pub.write_bytes(_public_pem(Ed25519PrivateKey.generate()))
    worm_key = tmp_path / "worm_signing.pem"
    worm_key.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            Enc.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("MCPIP_")}
    env.update(
        {
            "MCPIP_SANDBOX_MODE": "false",
            "MCPIP_REDIS_URL": _BOOT_REDIS_URL,
            "MCPIP_WORM_PATH": str(tmp_path / "worm.jsonl"),
            "MCPIP_JWT_PUBLIC_KEY_PATH": str(jwt_pub),
            "MCPIP_WORM_SIGNING_KEY_PATH": str(worm_key),
        }
    )
    result = _boot_import(env)
    assert result.returncode != 0
    assert "MCPIP_INTEGRITY_MANIFEST_PATH" in result.stderr


def test_dev_bypass_refused_on_production_boot(
    hooks: HookFixtures, tmp_path: Path
) -> None:
    """An injected MCPIP_INTEGRITY_DEV_BYPASS cannot disable verified boot in prod."""
    from cryptography.hazmat.primitives.serialization import (
        Encoding as Enc,
        NoEncryption,
        PrivateFormat,
    )

    jwt_pub = tmp_path / "jwt_public.pem"
    jwt_pub.write_bytes(_public_pem(Ed25519PrivateKey.generate()))
    worm_key = tmp_path / "worm_signing.pem"
    worm_key.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            Enc.PEM, PrivateFormat.PKCS8, NoEncryption()
        )
    )
    env = _hook_env(
        hooks,
        tmp_path,
        {
            "MCPIP_SANDBOX_MODE": "false",
            "MCPIP_JWT_PUBLIC_KEY_PATH": str(jwt_pub),
            "MCPIP_WORM_SIGNING_KEY_PATH": str(worm_key),
            "MCPIP_INTEGRITY_DEV_BYPASS": "true",
        },
    )
    result = _boot_import(env)
    assert result.returncode != 0
    assert "MCPIP_INTEGRITY_DEV_BYPASS" in result.stderr
    assert "sandbox-only" in result.stderr
    assert "INTEGRITY DEV BYPASS ACTIVE" not in result.stderr


def test_dev_bypass_boots_with_loud_banner(
    hooks: HookFixtures, tmp_path: Path
) -> None:
    """The documented dev-only bypass skips the check but screams on stderr."""
    manifest = json.loads(hooks.manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["sha256"] = "0" * 64
    broken_path = tmp_path / "broken_manifest.json"
    broken_path.write_text(json.dumps(manifest), encoding="utf-8")
    result = _boot_import(
        _hook_env(
            hooks,
            tmp_path,
            {
                "MCPIP_INTEGRITY_MANIFEST_PATH": str(broken_path),
                "MCPIP_INTEGRITY_DEV_BYPASS": "true",
            },
        )
    )
    assert result.returncode == 0, result.stderr
    assert "INTEGRITY DEV BYPASS ACTIVE" in result.stderr
