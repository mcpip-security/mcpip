"""
MCPIP — every production authenticator endpoint must be reachable without curl.

Step-up is the feature the product leads with, and its production channel had five
HTTP endpoints, no SDK methods and no CLI commands. So `mcpip authorize` would stage
a `pin_required` call, print "resume with `mcpip complete`", and that command could
not succeed: it needs a one-time code, and nothing in the CLI could fetch one. The
only way through was hand-rolled HTTP.

Nothing caught it because every layer was individually fine. These tests bind the
layers together: a production `/v1/authenticator/*` route must have a client method,
and the client method must have a command.
"""

from __future__ import annotations

import inspect
import os
import re

from mcpip_sdk.cli.main import build_parser
from mcpip_sdk.client import MCPIPClient, SandboxClient

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Route → the client method that must reach it. The sandbox stand-in is listed
#: separately because it legitimately lives on SandboxClient.
_PRODUCTION_ROUTES = {
    "GET /v1/authenticator": "authenticator_status",
    "POST /v1/authenticator/enroll": "authenticator_enroll",
    "POST /v1/authenticator/enroll/confirm": "authenticator_confirm",
    "POST /v1/authenticator/reveal": "authenticator_reveal",
    "POST /v1/authenticator/disable": "authenticator_disable",
}


def _gateway_source() -> str:
    with open(os.path.join(_REPO_ROOT, "app", "main.py"), encoding="utf-8") as handle:
        return handle.read()


def test_every_authenticator_route_the_gateway_serves_is_accounted_for() -> None:
    """A new /v1/authenticator/* route must be given a client method deliberately."""
    served = set(
        re.findall(r'@app\.(get|post|delete)\("(/v1/authenticator[^"]*)"\)', _gateway_source())
    )
    routes = {f"{verb.upper()} {path}" for verb, path in served}
    # The one sandbox-only route: it stands in for the enrolled device.
    routes.discard("GET /v1/authenticator/{challenge_id}")
    unaccounted = routes - set(_PRODUCTION_ROUTES)
    assert not unaccounted, (
        "the gateway serves authenticator routes with no client method: "
        f"{sorted(unaccounted)} — add one, or the only way through is curl"
    )


def test_the_production_client_reaches_every_authenticator_route() -> None:
    missing = [
        method
        for method in _PRODUCTION_ROUTES.values()
        if not callable(getattr(MCPIPClient, method, None))
    ]
    assert not missing, f"MCPIPClient is missing authenticator methods: {missing}"


def test_the_sandbox_stand_in_stays_on_the_sandbox_client() -> None:
    """`authenticator_code` discloses an OTP outright — it must never be production."""
    assert callable(getattr(SandboxClient, "authenticator_code", None))
    assert "authenticator_code" not in vars(MCPIPClient), (
        "authenticator_code discloses the step-up code without proving a human is "
        "present; it belongs to SandboxClient alone"
    )


def test_every_client_method_has_a_cli_command() -> None:
    parser = build_parser()
    group = parser._subparsers._group_actions[0].choices["authenticator"]  # type: ignore[union-attr]
    actions = set(group._subparsers._group_actions[0].choices)  # type: ignore[union-attr]
    expected = {"status", "enroll", "confirm", "reveal", "disable"}
    assert expected <= actions, f"mcpip authenticator is missing: {sorted(expected - actions)}"


def test_reveal_completes_inline_like_its_sandbox_twin() -> None:
    """The good UX is one command from staged challenge to receipt.

    `sandbox authenticator` already worked that way; production reveal must too,
    or the production path is strictly worse than the demo path.
    """
    from mcpip_sdk.cli.commands import authenticator, sandbox

    for source in (
        inspect.getsource(authenticator.cmd_authenticator_reveal),
        inspect.getsource(sandbox.cmd_sandbox_authenticator),
    ):
        assert "_load_staged" in source and "client.complete" in source


def test_the_staged_hint_names_a_command_that_can_succeed() -> None:
    """The hint used to name only `mcpip complete --challenge <id>`.

    That fails in any non-TTY with "no OTP available" — it needs a code no command
    could fetch, so the hint sent developers to a dead end. It must name a path that
    actually completes.
    """
    with open(
        os.path.join(_REPO_ROOT, "sdk", "python", "src", "mcpip_sdk", "cli", "render.py"),
        encoding="utf-8",
    ) as handle:
        render = handle.read()
    # Anchor on the render branch, not the import of the same name at the top.
    hint = render[render.index("isinstance(exc, StepUpPending)") :][:1200]
    assert "sandbox authenticator" in hint and "authenticator reveal" in hint, (
        "the step-up hint must name a command that can actually complete the cycle"
    )
