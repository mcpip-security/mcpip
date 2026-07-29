"""
MCPIP — the posture floor, exercised through the ROUTE rather than its helpers.

    ◐ "A pure-function test proves the arithmetic. It does not prove the gate is wired."

``tests/test_target_posture_floor.py`` covers canonicalization and subsumption as pure
functions, and that is genuinely useful — but it never calls
``_target_posture_conflict`` and never issues a request. Mutation testing showed what
that costs: replacing the whole conflict check with ``return False, None`` left the
suite at **1503 passed**. Every property the floor exists for was unprotected.

These tests close that. Each one below pins a mutation that previously survived:

  * strict-then-weak on one target        — the bypass itself
  * pin_required/unclassified duplicate   — the classification half of ``_weaker_than``
  * a storage failure                     — the fail-closed ``except`` branch
  * tightening, and unrelated targets     — that the floor is not simply refusing
                                            everything, which would "pass" a
                                            security test while breaking the product
"""

from __future__ import annotations

import os
import sys
import uuid

os.environ.setdefault("MCPIP_REDIS_URL", "redis://localhost:63790/7")
os.environ.setdefault("MCPIP_SANDBOX_MODE", "true")

from typing import Iterator  # noqa: E402

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.main import _components, app  # noqa: E402
from interfaces import CAP_DIRECTORY_ADMIN  # noqa: E402

_HOST = "https://api.example.test/v1/accounts/{account_id}/db"


def _uid() -> str:
    return uuid.uuid4().hex[:8]


@pytest.fixture(scope="module")
def client() -> Iterator[TestClient]:
    with TestClient(app) as c:
        yield c


@pytest.fixture(scope="module")
def admin(client: TestClient) -> str:
    demo = _components.demo_idp
    assert demo is not None, "sandbox IdP must be present"
    return demo.mint(
        tenant_id="tenant-posture",
        agent_id=f"agent-admin-{_uid()}",
        capabilities=[CAP_DIRECTORY_ADMIN],
    )


def _register(client: TestClient, token: str, alias: str, target: str,
              risk: str = "auto", classification: str = "unclassified"):
    return client.post(
        "/v1/admin/skills/register",
        json={"alias": alias, "target": target,
              "risk_tier": risk, "classification": classification},
        headers={"Authorization": f"Bearer {token}"},
    )


class TestTheFloorIsActuallyWired:
    def test_a_weaker_duplicate_of_the_same_target_is_refused(self, client, admin) -> None:
        """THE bypass: two aliases, one target, opposite postures.

        Kills the `return False, None` mutation — with the check disabled this
        registration succeeds and the endpoint has an auto-tier door beside its
        pin_required one.
        """
        target = _HOST.replace("{account_id}", f"acct-{_uid()}")
        strict = f"post.strict.{_uid()}"
        weak = f"post.weak.{_uid()}"

        assert _register(client, admin, strict, target,
                         "pin_required", "restricted").status_code == 200
        weaker = _register(client, admin, weak, target, "auto", "unclassified")
        assert weaker.status_code == 409, weaker.text
        assert weaker.json()["error"] == "target_posture_conflict"

    def test_a_weaker_CLASSIFICATION_alone_is_refused(self, client, admin) -> None:
        """Kills dropping the classification half of `_weaker_than`.

        Risk tier matches (`pin_required` both sides); only the classification is
        loosened. A floor comparing risk alone lets this through.
        """
        target = _HOST.replace("{account_id}", f"acct-{_uid()}")
        assert _register(client, admin, f"post.rc.{_uid()}", target,
                         "pin_required", "restricted").status_code == 200
        weaker = _register(client, admin, f"post.ru.{_uid()}", target,
                           "pin_required", "unclassified")
        assert weaker.status_code == 409, weaker.text

    def test_tightening_the_same_target_is_allowed(self, client, admin) -> None:
        """The floor must not be a blanket refusal — that would 'pass' and break the product."""
        target = _HOST.replace("{account_id}", f"acct-{_uid()}")
        assert _register(client, admin, f"post.a.{_uid()}", target,
                         "auto", "unclassified").status_code == 200
        assert _register(client, admin, f"post.b.{_uid()}", target,
                         "pin_required", "restricted").status_code == 200

    def test_an_unrelated_target_is_unaffected(self, client, admin) -> None:
        assert _register(client, admin, f"post.x.{_uid()}",
                         _HOST.replace("{account_id}", f"acct-{_uid()}"),
                         "pin_required", "restricted").status_code == 200
        assert _register(client, admin, f"post.y.{_uid()}",
                         _HOST.replace("{account_id}", f"acct-{_uid()}"),
                         "auto", "unclassified").status_code == 200

    def test_a_template_covers_a_literal_substitution(self, client, admin) -> None:
        """Canonicalization cannot see this; subsumption must."""
        acct = f"acct-{_uid()}"
        template = f"https://api.example.test/v1/accounts/{{account_id}}/db-{acct}"
        literal = f"https://api.example.test/v1/accounts/{acct}/db-{acct}"
        assert _register(client, admin, f"post.tpl.{_uid()}", template,
                         "pin_required", "restricted").status_code == 200
        narrowed = _register(client, admin, f"post.lit.{_uid()}", literal,
                             "auto", "unclassified")
        assert narrowed.status_code == 409, narrowed.text

    def test_a_storage_failure_refuses_rather_than_admits(self, client, admin, monkeypatch) -> None:
        """Kills flipping the fail-closed `except` to `return False`.

        If the overlay cannot be read, the gateway cannot PROVE the registration is
        safe — so it must refuse. A floor that admits on error is a floor an attacker
        opens by breaking Redis.
        """
        target = _HOST.replace("{account_id}", f"acct-{_uid()}")

        async def _boom(*_a, **_k):
            raise RuntimeError("redis down")

        monkeypatch.setattr(_components.catalog_overlay, "list_for_tenant", _boom)
        resp = _register(client, admin, f"post.err.{_uid()}", target, "auto", "unclassified")
        assert resp.status_code == 409, resp.text
        assert resp.json()["error"] == "target_posture_conflict"

    def test_the_query_string_is_not_a_second_door(self, client, admin) -> None:
        """`?x=1` once produced a distinct canonical form that subsumed against nothing.

        Sorting the query folded parameter ORDER and left PRESENCE alone, so a weaker
        alias registered beside a strict one on the same endpoint. The query is now
        dropped, so this is refused by the registration grammar itself.
        """
        target = _HOST.replace("{account_id}", f"acct-{_uid()}")
        assert _register(client, admin, f"post.q1.{_uid()}", target,
                         "pin_required", "restricted").status_code == 200
        evasion = _register(client, admin, f"post.q2.{_uid()}", target + "?x=1",
                            "auto", "unclassified")
        assert evasion.status_code != 200, evasion.text
