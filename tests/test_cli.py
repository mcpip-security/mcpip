"""
MCPIP V2 — the ``mcpip`` CLI, unit + LIVE contract suite.

    ◐  "The same choke point, now from your shell."

Two layers:

* Pure-unit tests (no gateway) for the security-critical local surface: ``--arg``
  typed coercion (NO inference — a ZIP stays a string), config 0600 creation and
  the fail-closed refusal of a group/world-readable config, the refusal to inline
  a literal token, the opaque deny renderer (correlation id only, never a reason),
  the exit-code map, and a REGRESSION GUARD that the parser exposes no
  secret-leaking ``--token``/``--otp`` string flag.
* LIVE tests that drive ``mcpip.cli.main`` end to end against the REAL in-process
  gateway through ``httpx.ASGITransport`` (the ``tests/test_sdk_python.py``
  pattern) — real authorize/deny/step-up traffic, no mocks, asserting the ``--json``
  shape, opacity, and honest exit codes.
"""

from __future__ import annotations

import os
import sys

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO_ROOT)
sys.path.insert(0, os.path.join(_REPO_ROOT, "sdk", "python", "src"))

_TEST_REDIS_URL = "redis://localhost:63790/7"
os.environ["MCPIP_REDIS_URL"] = _TEST_REDIS_URL
os.environ["MCPIP_SANDBOX_MODE"] = "true"
os.environ.setdefault(
    "MCPIP_WORM_PATH",
    os.path.join(os.path.dirname(__file__), ".mcpip_test_cli_worm.jsonl"),
)

import asyncio
import json
import stat
from io import StringIO
from typing import Any, Iterator

import httpx
import pytest
import redis as redis_sync
from pathlib import Path

from interfaces import CAP_DIRECTORY_ADMIN

from app.main import _components, app

from mcpip_sdk import SandboxClient
from mcpip_sdk.cli import config as cfg
from mcpip_sdk.cli._runtime import set_transport_override
from mcpip_sdk.cli.args import collect_args, coerce_value
from mcpip_sdk.cli.errors import (
    CLIConfigError,
    ExitCode,
    StepUpPending,
    map_exception,
)
from mcpip_sdk.cli.main import build_parser, main
from mcpip_sdk.cli.render import OutputMode, render_error
from mcpip_sdk.errors import (
    MCPIPDenied,
    MCPIPInvalidRequest,
    MCPIPNotFound,
    MCPIPSandboxOnly,
    MCPIPUnavailable,
)

_BASE_URL = "http://gateway.cli.test"
_AUTO_ALIAS = "skill_spend_summary"
_PIN_ALIAS = "skill_payroll_run"


# ---------------------------------------------------------------------------
# Pure-unit: --arg coercion (no inference).
# ---------------------------------------------------------------------------


def test_arg_default_is_string_no_inference() -> None:
    # A ZIP code, a bool-looking string, a numeric string — ALL stay strings.
    assert coerce_value("01234") == "01234"
    assert coerce_value("true") == "true"
    assert coerce_value("42") == "42"


def test_arg_explicit_prefixes() -> None:
    assert coerce_value("int:42") == 42
    assert coerce_value("float:1.5") == 1.5
    assert coerce_value("bool:true") is True
    assert coerce_value("bool:no") is False
    assert coerce_value("json:{\"a\":1}") == {"a": 1}
    assert coerce_value("str:42") == "42"


def test_arg_bad_prefix_is_config_error() -> None:
    with pytest.raises(CLIConfigError):
        coerce_value("int:notanint")
    with pytest.raises(CLIConfigError):
        coerce_value("bool:maybe")


def test_collect_args_requires_equals() -> None:
    assert collect_args(["a=1", "b=str:x"]) == {"a": "1", "b": "x"}
    with pytest.raises(CLIConfigError):
        collect_args(["missing_equals"])


# ---------------------------------------------------------------------------
# Pure-unit: config 0600 + fail-closed perms + no inline token.
# ---------------------------------------------------------------------------


def test_config_roundtrip_and_0600(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("MCPIP_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("MCPIP_CONFIG", raising=False)
    config = cfg.load()
    config = cfg.config_set(config, "context.dev.base_url", "http://localhost:8080")
    config = cfg.config_set(config, "context.dev.sandbox", "true")
    config = cfg.config_set(config, "context.dev.token-source", "env:MCPIP_TOKEN")
    config = cfg.config_set(config, "current-context", "dev")
    cfg.save(config)

    path = cfg.config_path()
    mode = stat.S_IMODE(os.stat(path).st_mode)
    assert mode == 0o600, f"config must be 0600, got {mode:o}"

    reloaded = cfg.load()
    assert reloaded.current_context == "dev"
    assert reloaded.contexts["dev"].base_url == "http://localhost:8080"
    assert reloaded.contexts["dev"].sandbox is True
    assert reloaded.contexts["dev"].token_source == "env:MCPIP_TOKEN"


def test_config_refuses_group_readable(tmp_path: Any, monkeypatch: Any) -> None:
    monkeypatch.setenv("MCPIP_CONFIG_HOME", str(tmp_path))
    monkeypatch.delenv("MCPIP_CONFIG", raising=False)
    cfg.save(cfg.Config(current_context=None, contexts={}))
    os.chmod(cfg.config_path(), 0o644)  # group/world-readable
    with pytest.raises(CLIConfigError):
        cfg.load()


def test_config_refuses_literal_token() -> None:
    with pytest.raises(CLIConfigError):
        cfg.validate_token_source("eyJhbGciOi.payload.sig")
    # A proper reference is accepted.
    assert cfg.validate_token_source("env:MCPIP_TOKEN") == "env:MCPIP_TOKEN"


# ---------------------------------------------------------------------------
# Pure-unit: exit-code map + opaque deny rendering.
# ---------------------------------------------------------------------------


def test_exit_code_map() -> None:
    assert map_exception(MCPIPDenied("corr")) == ExitCode.DENIED
    assert map_exception(MCPIPUnavailable("x")) == ExitCode.UNAVAILABLE
    assert map_exception(MCPIPInvalidRequest("x")) == ExitCode.INVALID_REQUEST
    assert map_exception(MCPIPNotFound("x")) == ExitCode.NOT_FOUND
    assert map_exception(MCPIPSandboxOnly("/x")) == ExitCode.SANDBOX_ONLY
    assert map_exception(CLIConfigError("x")) == ExitCode.CONFIG
    assert map_exception(StepUpPending("cid", "corr")) == ExitCode.STEP_UP_PENDING


def test_deny_render_is_opaque(capsys: Any) -> None:
    mode = OutputMode(json=True, quiet=False, color=False)
    # http_status varies by cause/edge (401/403/200/500); the JSON deny payload
    # must NOT surface it — a deny discloses ONLY the opaque correlation id.
    render_error(mode, MCPIPDenied("corr-123", http_status=403))
    out = capsys.readouterr().out
    payload = json.loads(out)
    assert payload == {
        "error": "denied",
        "correlation_id": "corr-123",
    }
    # No reason- or status-shaped discriminator ever appears.
    assert "http_status" not in out and "status" not in out
    assert "reason" not in out and "deny_reason" not in out and "target" not in out


def test_deny_render_is_opaque_regardless_of_status(capsys: Any) -> None:
    """A 401/200/500 deny renders byte-identically to a 403 deny — the edge/cause
    can never be recovered from the --json payload (opacity is uniform)."""
    mode = OutputMode(json=True, quiet=False, color=False)
    render_error(mode, MCPIPDenied("corr-9", http_status=403))
    a = capsys.readouterr().out
    for status in (401, 200, 500):
        render_error(mode, MCPIPDenied("corr-9", http_status=status))
        assert capsys.readouterr().out == a


# ---------------------------------------------------------------------------
# Pure-unit: a vended cloud credential NEVER reaches stdout (pipe/CI/redirect
# are not private sinks); it is captured only via --credential-out (0600 O_EXCL).
# ---------------------------------------------------------------------------


def test_vended_credential_never_on_stdout(tmp_path: Any) -> None:
    from mcpip_sdk.cli._runtime import Runtime
    from mcpip_sdk.cli.commands.agent import _receipt_json, _render_receipt
    from mcpip_sdk.cli.config import Resolved
    from mcpip_sdk.models import Allowed

    secret = {"access_key_id": "AKIA_REAL", "secret_access_key": "s3cr3t", "expiration": "2026-07-17T14:00:00Z"}
    receipt = Allowed(
        correlation_id="corr-x",
        decision="allow",
        status="committed",
        transaction_ref="txn_1",
        executed_target_class="cloud_iam",
        worm_sequence=7,
        vended_credential=secret,
    )

    # --json ALWAYS redacts the material, with or without a TTY, capture path, etc.
    payload = _receipt_json(receipt)
    assert payload["vended_credential"] == {
        "redacted": True,
        "reason": payload["vended_credential"]["reason"],
    }
    blob = json.dumps(payload)
    assert "AKIA_REAL" not in blob and "s3cr3t" not in blob

    # --credential-out FILE captures the material to a 0600 O_EXCL file; stdout
    # shows only where it landed, never the material.
    rt = Runtime(
        resolved=Resolved(base_url="http://x", sandbox=True, context_name=None, token_source=None),
        mode=OutputMode(json=True, quiet=False, color=False),
    )
    out_path = str(tmp_path / "cred.json")
    written = _receipt_json(receipt, out_path)
    assert written["vended_credential"] == {"redacted": True, "written_to": out_path}

    # Drive the real write path and assert 0600 + real material on disk only.
    _render_receipt(rt, receipt, credential_out=out_path)
    assert stat.S_IMODE(os.stat(out_path).st_mode) == 0o600
    on_disk = json.loads(open(out_path).read())
    assert on_disk == secret


# ---------------------------------------------------------------------------
# Pure-unit: parser has NO secret-leaking string flags (regression guard).
# ---------------------------------------------------------------------------


def test_no_secret_leaking_flags() -> None:
    """A ``--token`` or ``--otp`` STRING flag would leak via ps/shell-history.
    Assert the whole parser tree exposes none — only the safe file/stdin/cmd
    inputs and the boolean OTP switches."""
    parser = build_parser()
    banned = {"--token", "--otp", "--pin", "--secret", "--material"}
    seen: set[str] = set()

    def _walk(p: Any) -> None:
        for action in p._actions:
            for opt in action.option_strings:
                seen.add(opt)
            if hasattr(action, "choices") and isinstance(action.choices, dict):
                for sub in action.choices.values():
                    _walk(sub)

    _walk(parser)
    leaked = banned & seen
    assert not leaked, f"secret-leaking string flag(s) present: {leaked}"
    # The safe inputs DO exist.
    assert "--token-file" in seen and "--token-stdin" in seen and "--token-cmd" in seen
    assert "--otp-stdin" in seen and "--material-file" in seen


def test_version_and_usage_exit_codes(capsys: Any) -> None:
    assert main(["--version"]) == 0
    assert "mcpip" in capsys.readouterr().out
    assert main(["version", "--client"]) == 0
    # An unknown command is argparse usage error → exit 2.
    assert main(["definitely-not-a-command"]) == 2


# ---------------------------------------------------------------------------
# LIVE: the in-process gateway behind an ASGI transport (test_sdk_python pattern).
# ---------------------------------------------------------------------------


class _LoopASGITransport(httpx.BaseTransport):
    def __init__(self, loop: asyncio.AbstractEventLoop, asgi_app: Any) -> None:
        self._loop = loop
        self._asgi = httpx.ASGITransport(app=asgi_app)

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        async def _dispatch() -> tuple[int, list[tuple[bytes, bytes]], bytes]:
            response = await self._asgi.handle_async_request(request)
            body = await response.aread()
            return response.status_code, list(response.headers.raw), body

        status, headers, body = self._loop.run_until_complete(_dispatch())
        return httpx.Response(status_code=status, headers=headers, content=body)


def _reset_backing_state() -> None:
    reset: Any = redis_sync.Redis.from_url(_TEST_REDIS_URL, decode_responses=True)
    try:
        reset.flushdb()
    finally:
        reset.close()
    worm_path = _components.settings.worm_path
    for artifact in (worm_path, worm_path + ".anchor"):
        try:
            os.remove(artifact)
        except FileNotFoundError:
            pass


@pytest.fixture(scope="module")
def gateway() -> Iterator[httpx.BaseTransport]:
    _reset_backing_state()
    loop = asyncio.new_event_loop()
    lifespan = app.router.lifespan_context(app)
    loop.run_until_complete(lifespan.__aenter__())
    transport = _LoopASGITransport(loop, app)
    set_transport_override(transport)
    try:
        yield transport
    finally:
        set_transport_override(None)
        loop.run_until_complete(lifespan.__aexit__(None, None, None))
        loop.close()
        _reset_backing_state()


@pytest.fixture()
def cli_env(
    gateway: httpx.BaseTransport, tmp_path: Any, monkeypatch: Any
) -> Iterator[dict[str, str]]:
    """Isolated config home + an agent bearer in MCPIP_TOKEN, minted for real."""
    monkeypatch.setenv("MCPIP_CONFIG_HOME", str(tmp_path))
    monkeypatch.setenv("MCPIP_GATEWAY", _BASE_URL)
    monkeypatch.delenv("MCPIP_CONFIG", raising=False)
    monkeypatch.delenv("MCPIP_CONTEXT", raising=False)
    monkeypatch.delenv("MCPIP_SANDBOX", raising=False)
    with SandboxClient(_BASE_URL, transport=gateway) as minter:
        token = minter.dev_token(agent_id="agent-cli-test")
        admin_token = minter.dev_token(
            agent_id="agent-cli-admin", capabilities=[CAP_DIRECTORY_ADMIN]
        )
    monkeypatch.setenv("MCPIP_TOKEN", token)
    yield {"token": token, "admin_token": admin_token}


def _run(argv: list[str], capsys: Any) -> tuple[int, str, str]:
    code = main(argv)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_live_health_json(cli_env: dict[str, str], capsys: Any) -> None:
    code, out, _ = _run(["--json", "health"], capsys)
    assert code == 0
    assert json.loads(out)["status"] == "live"


def test_live_authorize_allowed_json(cli_env: dict[str, str], capsys: Any) -> None:
    code, out, _ = _run(
        ["--json", "authorize", _AUTO_ALIAS, "--arg", "period=2026-Q2"], capsys
    )
    assert code == ExitCode.OK
    receipt = json.loads(out)
    assert receipt["decision"] == "allow"
    assert receipt["status"] == "committed"
    assert receipt["transaction_ref"].startswith("txn_")
    # Zero topology leakage: a transport CLASS, never a real target.
    assert "." not in receipt["executed_target_class"]


def test_live_deny_is_opaque_exit_3(cli_env: dict[str, str], capsys: Any) -> None:
    code, out, _ = _run(["--json", "authorize", "skill_cli_unknown"], capsys)
    assert code == ExitCode.DENIED
    payload = json.loads(out)
    assert set(payload) == {"error", "correlation_id"}
    assert payload["error"] == "denied"
    assert payload["correlation_id"]
    # Not one concrete reason word crosses the boundary.
    for leak in ("unknown_alias", "reason", "target", "unknown", "policy_denied"):
        assert leak not in payload["correlation_id"]


def test_live_catalog_json(cli_env: dict[str, str], capsys: Any) -> None:
    code, out, _ = _run(["--json", "catalog"], capsys)
    assert code == 0
    rows = json.loads(out)
    assert isinstance(rows, list) and rows
    assert any(r["alias"] == _AUTO_ALIAS for r in rows)
    # metadata only — no target field exists on the model
    assert all("target" not in r for r in rows)


def test_live_step_up_persists_then_completes(
    cli_env: dict[str, str], gateway: httpx.BaseTransport, capsys: Any, monkeypatch: Any
) -> None:
    # 1) Non-interactive authorize on a pin_required alias → exit 9, envelope saved.
    monkeypatch.setattr(sys.stdin, "isatty", lambda: False)
    code, out, err = _run(
        ["authorize", _PIN_ALIAS, "--arg", "run_id=CLI-1", "--arg", "cycle=monthly"],
        capsys,
    )
    assert code == ExitCode.STEP_UP_PENDING
    staged_files = os.listdir(cfg.staged_dir())
    assert len(staged_files) == 1
    challenge_id = staged_files[0].removesuffix(".json")

    # 2) Fetch the OTP for real (sandbox authenticator) and resume via `complete`,
    #    feeding the OTP on stdin (never argv).
    with SandboxClient(_BASE_URL, transport=gateway) as sb:
        sb.set_token(cli_env["token"])
        otp = sb.authenticator_code(challenge_id)
    monkeypatch.setattr("sys.stdin", StringIO(otp + "\n"))
    code, out, _ = _run(
        ["--json", "complete", "--challenge", challenge_id, "--otp-stdin"], capsys
    )
    assert code == ExitCode.OK
    assert json.loads(out)["decision"] == "allow"
    # The spent envelope is discarded.
    assert not os.path.exists(os.path.join(cfg.staged_dir(), f"{challenge_id}.json"))


def test_live_dev_token_never_printed(cli_env: dict[str, str], capsys: Any) -> None:
    code, out, err = _run(
        ["--context", "sbx", "sandbox", "dev-token", "--agent", "agent-x"], capsys
    )
    # NOTE: --context sbx does not exist yet; dev-token wires it. It resolves
    # leniently (config-managing command), mints, and writes 0600.
    assert code == ExitCode.OK
    combined = out + err
    # The JWT (three base64 segments) must NEVER appear in any output.
    assert cli_env["token"] not in combined
    assert ".ey" not in combined  # no JWT body segment leaked
    token_path = cfg.default_token_path("sbx")
    assert stat.S_IMODE(os.stat(token_path).st_mode) == 0o600


def test_live_decision_permit_and_obligation(
    cli_env: dict[str, str], capsys: Any
) -> None:
    # A pin_required alias yields a permit carrying the step-up obligation.
    code, out, _ = _run(["--json", "decision", _PIN_ALIAS, "--arg", "run_id=D1"], capsys)
    assert code == 0
    verdict = json.loads(out)
    assert verdict["decision"] is True
    ids = [o["id"] for o in verdict["obligations"]]
    assert "mcpip.step_up.pin" in ids


def test_live_admin_decisions_via_env_token(
    cli_env: dict[str, str], capsys: Any, monkeypatch: Any
) -> None:
    _run(["authorize", _AUTO_ALIAS, "--arg", "period=2026-Q2"], capsys)
    capsys.readouterr()
    monkeypatch.setenv("MCPIP_TOKEN", cli_env["admin_token"])
    code, out, _ = _run(["--json", "admin", "decisions", "--limit", "5"], capsys)
    assert code == ExitCode.OK
    rows = json.loads(out)
    assert isinstance(rows, list)
    # deny_reason is operator-side visibility here (the agent never saw it).
    assert all("correlation_id" in r for r in rows)


def test_live_admin_stats_via_env_token(
    cli_env: dict[str, str], capsys: Any, monkeypatch: Any
) -> None:
    """`mcpip admin stats --json` renders the REAL local live numbers + honest
    opt-in-telemetry posture — never a fabricated client/number/"connected" state.
    This sandbox is air-gapped, so telemetry must report air-gap (never phones home)."""
    _run(["authorize", _AUTO_ALIAS, "--arg", "period=2026-Q2"], capsys)
    capsys.readouterr()
    monkeypatch.setenv("MCPIP_TOKEN", cli_env["admin_token"])
    code, out, _ = _run(["--json", "admin", "stats"], capsys)
    assert code == ExitCode.OK
    stats = json.loads(out)
    assert stats["governed_agent_identity_count"] >= 1
    assert stats["decisions"]["allow"] >= 1
    assert stats["license"]["licensed"] is False  # honest unlicensed sandbox boot.
    assert stats["telemetry"]["status"] == "air-gap"  # never phones home.
    # Honest dark-feature posture: sandbox defaults forensic capture ON, external PDP off.
    assert stats["features"]["forensic_capture"]["status"] == "enabled"
    assert stats["features"]["external_pdp"]["status"] == "off"
    # No per-tenant/agent identifier ever crosses this boundary — only aggregates.
    assert set(stats.keys()) == {
        "version",
        "governed_agent_identity_count",
        "decisions",
        "license",
        "telemetry",
        "features",
    }


def test_live_admin_users_lifecycle_cli(
    cli_env: dict[str, str], capsys: Any, monkeypatch: Any
) -> None:
    """`mcpip admin users invite|ls|update|rm` mirrors the operator/team roster
    surface end-to-end through the REAL endpoints (WORM-audited server-side). The
    invite surfaces a real one-time reference token; the role is a management label."""
    monkeypatch.setenv("MCPIP_TOKEN", cli_env["admin_token"])
    email = "cli-teammate@example.com"

    code, out, _ = _run(
        ["--json", "admin", "users", "invite", email, "--role", "member"], capsys
    )
    assert code == ExitCode.OK
    inv = json.loads(out)
    assert inv["email"] == email and inv["role"] == "member" and inv["status"] == "invited"
    assert isinstance(inv["invite_token"], str) and inv["invite_token"]

    code, out, _ = _run(["--json", "admin", "users", "ls"], capsys)
    assert code == ExitCode.OK
    page = json.loads(out)
    assert any(u["email"] == email for u in page["users"])

    code, out, _ = _run(
        ["--json", "admin", "users", "update", email, "--status", "active"], capsys
    )
    assert code == ExitCode.OK
    assert json.loads(out)["status"] == "active"

    code, out, _ = _run(["--json", "admin", "users", "rm", email], capsys)
    assert code == ExitCode.OK
    assert json.loads(out)["removed"] is True


def test_live_admin_users_requires_admin_cli(
    cli_env: dict[str, str], capsys: Any, monkeypatch: Any
) -> None:
    """The roster CLI is CAP_DIRECTORY_ADMIN-gated — a plain agent token is the same
    opaque deny (exit 3) as everywhere else."""
    monkeypatch.setenv("MCPIP_TOKEN", cli_env["token"])  # plain agent, no admin cap
    code, out, _ = _run(["--json", "admin", "users", "ls"], capsys)
    assert code == ExitCode.DENIED
    assert set(json.loads(out)) == {"error", "correlation_id"}


# ---------------------------------------------------------------------------
# X1/X3 operator surfaces on the CLI — compliance evidence + verified publishers.
# ---------------------------------------------------------------------------


def test_live_admin_compliance_evidence_json(
    cli_env: dict[str, str], capsys: Any, monkeypatch: Any
) -> None:
    """`mcpip admin compliance evidence --json` renders the REAL bundle and never
    fabricates a certification: the disclaimer + framework mapping are present."""
    _run(["authorize", _AUTO_ALIAS, "--arg", "period=2026-Q2"], capsys)
    _run(["sandbox", "audit", "verify"], capsys)  # seal an epoch.
    capsys.readouterr()
    monkeypatch.setenv("MCPIP_TOKEN", cli_env["admin_token"])
    code, out, _ = _run(["--json", "admin", "compliance", "evidence"], capsys)
    assert code == ExitCode.OK
    bundle = json.loads(out)
    assert bundle["attestation"]["signing_key_id"]
    assert "not a certification" in bundle["disclaimer"].lower()
    assert any(f["framework"] == "SOC 2" for f in bundle["control_mapping"])


def test_live_admin_compliance_evidence_human_states_evidence_not_cert(
    cli_env: dict[str, str], capsys: Any, monkeypatch: Any
) -> None:
    """The human view always restates the honesty invariant — never a cert claim."""
    monkeypatch.setenv("MCPIP_TOKEN", cli_env["admin_token"])
    code, out, _ = _run(["admin", "compliance", "evidence"], capsys)
    assert code == ExitCode.OK
    assert "EVIDENCE, NOT A CERTIFICATION" in out


def test_live_admin_publishers_roundtrip(
    cli_env: dict[str, str], capsys: Any, monkeypatch: Any, gateway: httpx.BaseTransport
) -> None:
    """`mcpip admin publishers set/get` round-trips through the reviewer surface."""
    from interfaces import CAP_CATALOG_REVIEWER

    with SandboxClient(_BASE_URL, transport=gateway) as minter:
        reviewer_token = minter.dev_token(
            agent_id="agent-cli-reviewer", capabilities=[CAP_CATALOG_REVIEWER]
        )
    monkeypatch.setenv("MCPIP_TOKEN", reviewer_token)
    code, _, _ = _run(
        ["admin", "publishers", "set", "--namespace", "io.github.acme", "--namespace", "com.example.x"],
        capsys,
    )
    assert code == ExitCode.OK
    capsys.readouterr()
    code, out, _ = _run(["--json", "admin", "publishers", "get"], capsys)
    assert code == ExitCode.OK
    doc = json.loads(out)
    assert doc["schema"] == "mcpip-registry-publishers/1"
    assert set(doc["namespaces"]) == {"io.github.acme", "com.example.x"}


# ---------------------------------------------------------------------------
# up — the one blessed front door (plan + repo detection only; never boots)
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parents[1]


def test_up_print_only_plans_without_booting(capsys: Any) -> None:
    """`mcpip up --print-only` finds the checkout and prints the plan, exit 0."""
    code, out, _ = _run(["up", "--print-only", "--repo", str(_REPO_ROOT)], capsys)
    assert code == ExitCode.OK
    assert "quickstart_demo.sh" in out
    assert str(_REPO_ROOT) in out


def test_up_autodetects_checkout_from_subdir(monkeypatch: Any, capsys: Any) -> None:
    """Auto-detection walks upward from the CWD to the repo root."""
    monkeypatch.chdir(_REPO_ROOT / "tests")
    code, out, _ = _run(["up", "--print-only"], capsys)
    assert code == ExitCode.OK
    assert "quickstart_demo.sh" in out


def test_up_outside_checkout_fails_with_clone_hint(tmp_path: Any, capsys: Any) -> None:
    """Outside a checkout: CONFIG exit code + the exact git-clone hint, no traceback."""
    code, _, err = _run(["up", "--print-only", "--repo", str(tmp_path)], capsys)
    assert code == ExitCode.CONFIG
    assert "git clone" in err


def test_up_print_only_mentions_proof_and_auto(capsys: Any) -> None:
    """The plan names the proof beat, and --auto adds the consent-gated flow."""
    code, out, _ = _run(["up", "--print-only", "--repo", str(_REPO_ROOT)], capsys)
    assert code == ExitCode.OK
    assert "attestation" in out
    code, out, _ = _run(
        ["up", "--print-only", "--auto", "--repo", str(_REPO_ROOT)], capsys
    )
    assert code == ExitCode.OK
    assert "deny-by-default" in out
    assert "explicit consent" in out


def test_up_clone_hint_points_at_public_repo(tmp_path: Any, capsys: Any) -> None:
    """The outside-a-checkout hint clones the PUBLIC repo, not a private remote."""
    code, _, err = _run(["up", "--print-only", "--repo", str(tmp_path)], capsys)
    assert code == ExitCode.CONFIG
    assert "github.com/mcpip-security/mcpip" in err


def test_up_render_proposal_is_pure_and_tolerant() -> None:
    """_render_proposal renders org units, teams, and skills from a plan dict —
    and tolerates missing/odd fields without raising (it never trusts shape)."""
    from mcpip_sdk.cli.commands.up import _render_proposal

    # The real draft shape: org units/teams carry `label` + `id`; skills carry
    # `alias` / `target` / `risk_tier` (see services/workspace_plan).
    plan = {
        "org_units": [
            {
                "id": "tenant-acme",
                "label": "Engineering",
                "teams": [{"id": "t-p", "label": "Platform"}, {"id": "t-s", "label": "SRE"}],
            },
            {"id": "ou-fin", "label": "Finance", "teams": []},
            "not-a-dict",
        ],
        "skills": [
            {"alias": "skill_spend_summary", "target": "rest.spend.read", "risk_tier": "auto"},
            {"alias": "skill_wire_payment"},
            42,
        ],
    }
    lines = _render_proposal(plan, "org_units=2 teams=2 skills=2")
    text = "\n".join(lines)
    assert "Engineering" in text and "Platform" in text and "SRE" in text
    assert "skill_spend_summary" in text and "→ rest.spend.read" in text
    assert "skill_wire_payment" in text
    assert "deny-by-default" in text
    # Degenerate plan: still renders the header + footer, no exception.
    assert _render_proposal({}, "org_units=0 teams=0 skills=0")
