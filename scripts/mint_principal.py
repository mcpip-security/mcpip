#!/usr/bin/env python3
"""
MCPIP client identity — mint a signed principal JWT for an agent / tenant.

The production analog of the sandbox ``/v1/dev/token`` forge: the identity provider
signs a short-lived EdDSA JWT scoping an agent to a tenant plus its entitlements
(capability UUIDs / a compartment), which the gateway then VERIFIES against the IdP
public key (``MCPIP_JWT_PUBLIC_KEY_PATH``). Identity is sovereign — it comes only
from this signed token; nothing in a tool-call payload can influence it.

The claim shape mirrors exactly what ``auth/token_resolver.py`` requires: the eight
mandatory claims (``exp/iat/nbf/iss/aud/tenant_id/agent_id/role``) plus the optional
UUID-identified ``capabilities`` / ``compartment``, and an optional ``cnf.jkt``
sender-constraint + ``act.sub`` delegation actor.

Discipline:
  * The IdP PRIVATE key is READ from ``--idp-key`` and used only in memory; its bytes
    are NEVER printed or logged. Only the resulting token (public-by-nature, signed)
    is emitted.
  * ``role`` authorizes NOTHING (it is descriptive) — entitlements are the capability
    UUIDs / compartment, exactly as the gateway enforces.
  * Tokens are short-lived by default (1h); ``--ttl`` bounds the blast radius of a
    leaked token. For fleets, prefer ephemeral per-session keys + sender-constraint
    (see docs/INTEGRATIONS.md) over long-lived bearer tokens.
"""

from __future__ import annotations

import argparse
import sys
import time
import uuid
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key


def _load_idp_key(path: str) -> Ed25519PrivateKey:
    loaded = load_pem_private_key(Path(path).read_bytes(), password=None)
    if not isinstance(loaded, Ed25519PrivateKey):
        raise SystemExit("IdP signing key must be an Ed25519 private key")
    return loaded


def _uuid_or_die(value: str, label: str) -> str:
    try:
        uuid.UUID(value)
    except ValueError:
        raise SystemExit(f"{label} must be a well-formed UUID: {value!r}")
    return value


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Mint a signed MCPIP principal JWT (EdDSA).")
    p.add_argument("--idp-key", required=True, help="path to the IdP Ed25519 PRIVATE key (PKCS8 PEM)")
    p.add_argument("--tenant", required=True, help="tenant_id claim")
    p.add_argument("--agent", required=True, help="agent_id claim")
    p.add_argument("--role", default="ops", help="role claim (DESCRIPTIVE ONLY — authorizes nothing)")
    p.add_argument("--issuer", required=True, help="iss claim — MUST match MCPIP_JWT_ISSUER")
    p.add_argument("--audience", required=True, help="aud claim — MUST match MCPIP_JWT_AUDIENCE")
    p.add_argument("--ttl", type=int, default=3600, help="lifetime in seconds (default 3600)")
    p.add_argument("--capability", action="append", default=[], metavar="UUID",
                   help="capability UUID entitlement (repeatable, max 32)")
    p.add_argument("--compartment", default=None, metavar="UUID", help="compartment UUID scope")
    p.add_argument("--cnf-jkt", default=None, help="RFC-7638 JWK thumbprint for a sender-constrained token")
    p.add_argument("--act-sub", default=None, help="RFC-8693 delegation actor (human principal)")
    p.add_argument("--kid", default=None, help="key id header (required by a JWKS-backed gateway)")
    p.add_argument("--out", default=None, help="write the token to this file (0600) instead of stdout")
    args = p.parse_args(argv)

    if args.ttl <= 0:
        raise SystemExit("--ttl must be positive")
    caps = [_uuid_or_die(c, "capability") for c in args.capability]
    if len(caps) > 32:
        raise SystemExit("at most 32 capabilities (matches the gateway's MAX_CAPABILITIES)")
    compartment = _uuid_or_die(args.compartment, "compartment") if args.compartment else None

    key = _load_idp_key(args.idp_key)
    now = int(time.time())
    claims: dict[str, object] = {
        "iss": args.issuer,
        "aud": args.audience,
        "tenant_id": args.tenant,
        "agent_id": args.agent,
        "role": args.role,
        "exp": now + args.ttl,
        "iat": now,
        "nbf": now,
        "jti": uuid.uuid4().hex,
    }
    if caps:
        claims["capabilities"] = caps
    if compartment is not None:
        claims["compartment"] = compartment
    if args.cnf_jkt:
        claims["cnf"] = {"jkt": args.cnf_jkt}
    if args.act_sub:
        claims["act"] = {"sub": args.act_sub}

    headers = {"kid": args.kid} if args.kid else None
    token = jwt.encode(claims, key, algorithm="EdDSA", headers=headers)

    if args.out:
        out = Path(args.out)
        out.write_text(token)
        out.chmod(0o600)
        print(f"token written 0600 to {out} (exp in {args.ttl}s)", file=sys.stderr)
    else:
        print(token)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
