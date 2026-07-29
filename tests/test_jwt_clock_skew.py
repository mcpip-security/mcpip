"""
MCPIP — bounded clock-skew tolerance on JWT temporal claims.

    ◐ "An outage caused by NTP is still an outage."

PyJWT defaults to ``leeway=0``, which demands the gateway's clock agree with the issuing
IdP to the second. Real clocks never do. A one-second drift rejected every otherwise
valid token, and the failure was total and undiagnosable from the agent's side — it sees
only an opaque deny, so the operator gets "everything is broken" with no cause attached.

The fix tolerates ``JWT_CLOCK_SKEW_LEEWAY_SECONDS`` of drift in BOTH directions, because
both break a valid token: a fast gateway clock sees ``exp`` as already passed, a slow one
sees ``iat``/``nbf`` as still in the future. RFC 7519 §4.1.4 sanctions exactly this.

It is a widening of what the gateway accepts, so it is tested as one. These cases pin
both halves of the contract: drift INSIDE the window is tolerated, and everything outside
it is still rejected — including a genuinely expired token, which is the property the
leeway must never be allowed to erode.
"""

from __future__ import annotations

import time

import pytest

from interfaces import JWT_CLOCK_SKEW_LEEWAY_SECONDS


def test_leeway_is_bounded_and_small() -> None:
    """A few minutes at most. This value directly extends an EXPIRED token's usable life,
    so it is the one number here an attacker benefits from — it must stay small enough
    that it is a clock-correction allowance and never a replay window."""
    assert 0 < JWT_CLOCK_SKEW_LEEWAY_SECONDS <= 300


def test_leeway_is_a_hard_limit_not_a_setting() -> None:
    """Hard limits live only in interfaces.py. If this became an env-tunable an operator
    could widen it to hours to 'fix' a clock problem, converting a bounded allowance into
    a real replay window — the failure mode this whole change is meant to avoid."""
    import interfaces

    source = (
        __import__("pathlib").Path(interfaces.__file__).read_text(encoding="utf-8")
    )
    assert "JWT_CLOCK_SKEW_LEEWAY_SECONDS: Final[int] = " in source
    assert "getenv" not in source.split("JWT_CLOCK_SKEW_LEEWAY_SECONDS")[1][:200]


def test_resolver_passes_the_leeway_to_pyjwt() -> None:
    """The constant is inert unless it reaches jwt.decode. Asserting the wiring means a
    future refactor that drops the kwarg fails here rather than silently restoring the
    second-exact behaviour that caused the outage."""
    from pathlib import Path

    import auth.token_resolver as tr

    source = Path(tr.__file__).read_text(encoding="utf-8")
    assert "leeway=JWT_CLOCK_SKEW_LEEWAY_SECONDS" in source


@pytest.mark.parametrize(
    ("skew", "accepted"),
    [
        (0, True),
        (JWT_CLOCK_SKEW_LEEWAY_SECONDS // 2, True),
        (JWT_CLOCK_SKEW_LEEWAY_SECONDS - 1, True),
        (JWT_CLOCK_SKEW_LEEWAY_SECONDS + 30, False),
        (JWT_CLOCK_SKEW_LEEWAY_SECONDS * 10, False),
    ],
)
def test_expiry_boundary_is_the_leeway(skew: int, accepted: bool) -> None:
    """PyJWT's own rule, pinned: a token expired by `skew` seconds is accepted iff the
    skew is within the leeway. This is the arithmetic the gateway now relies on, so it is
    asserted directly rather than assumed from the library's docs.
    """
    import jwt

    secret = "test-secret-not-a-credential"
    now = int(time.time())
    token = jwt.encode(
        {"exp": now - skew, "iat": now - skew - 120, "nbf": now - skew - 120},
        secret,
        algorithm="HS256",
    )
    try:
        jwt.decode(
            token,
            secret,
            algorithms=["HS256"],
            leeway=JWT_CLOCK_SKEW_LEEWAY_SECONDS,
            options={"verify_aud": False},
        )
        got = True
    except jwt.InvalidTokenError:
        got = False
    assert got is accepted


def test_future_issued_token_inside_the_window_is_accepted() -> None:
    """The other drift direction: our clock is BEHIND the IdP, so a freshly minted token
    looks issued in the future. Without leeway this rejects brand-new, perfectly valid
    tokens — the same outage from the opposite side, and the half that is easy to forget
    because it only appears when the gateway is the slow clock."""
    import jwt

    secret = "test-secret-not-a-credential"
    now = int(time.time())
    ahead = JWT_CLOCK_SKEW_LEEWAY_SECONDS - 5
    token = jwt.encode(
        {"exp": now + 3600, "iat": now + ahead, "nbf": now + ahead},
        secret,
        algorithm="HS256",
    )
    jwt.decode(
        token,
        secret,
        algorithms=["HS256"],
        leeway=JWT_CLOCK_SKEW_LEEWAY_SECONDS,
        options={"verify_aud": False},
    )


def test_leeway_does_not_rescue_a_bad_signature() -> None:
    """Temporal tolerance must not become general tolerance. A forged token is rejected
    regardless of how fresh its claims look — the leeway touches exp/iat/nbf and nothing
    else."""
    import jwt

    now = int(time.time())
    token = jwt.encode(
        {"exp": now + 3600, "iat": now, "nbf": now}, "the-wrong-key", algorithm="HS256"
    )
    with pytest.raises(jwt.InvalidTokenError):
        jwt.decode(
            token,
            "test-secret-not-a-credential",
            algorithms=["HS256"],
            leeway=JWT_CLOCK_SKEW_LEEWAY_SECONDS,
            options={"verify_aud": False},
        )
