#!/usr/bin/env python3
"""
MCPIP — DynamoDB WRITE live-fire (RUN THIS ON YOUR OWN MACHINE, WITH YOUR OWN AWS CREDS).

This is the real-account counterpart to ``scripts/dynamodb_vend_demo.py`` (which proves
the authorize + step-up + audit half against a real pipeline with a *fake* credential).
Here we exercise the OTHER half — MCPIP's real ``CloudBroker`` vend against a *real*
AWS account — and prove the property that actually bounds an agent's blast radius:

    the vended credential is SHORT-LIVED and LEAST-PRIVILEGE. It can do exactly one
    thing (PutItem on one table) and nothing else — no read, no other table, no S3.

Put the two scripts together and you have the full production path end to end:

    gateway authorizes (entitlement + payload-bound step-up) → WORM-logs the ALLOW →
    broker vends a short-lived, write-scoped STS credential → the agent signs ONE
    DynamoDB PutItem with it → the credential expires.

────────────────────────────────────────────────────────────────────────────────────
WHAT MCPIP DOES — AND DOES NOT — DO (read this before you draw conclusions):

  * MCPIP AUTHORIZES the call (identity + compartment + payload-bound PIN), AUDITS it
    (signed WORM record written BEFORE anything is vended), and VENDS a per-call,
    short-lived, scope-reduced credential. Stop the skill or revoke the principal and
    the next vend is denied.
  * MCPIP DOES NOT proxy the DynamoDB request or inspect the item you PutItem. It is an
    authorization gateway, not a data-plane content filter. If you need to keep PII out
    of a table, that is a DATA-LAYER control (schema validation, a resource policy, a
    VPC endpoint policy) — do NOT expect this gateway to read your payload and block it.
    The control MCPIP gives you is the credential's least-privilege boundary, proved
    below: the agent simply cannot reach anything the role does not allow.
────────────────────────────────────────────────────────────────────────────────────

SAFETY / PREREQS
  * Uses YOUR default AWS credential chain (env vars, profile, SSO). Use a NON-production
    account. Rotate any key you have ever pasted into a chat.
  * Needs: python3, boto3 (`pip install boto3`), and MCPIP importable from repo root.
  * Creates a role + one on-demand table, both prefixed ``mcpip-live-fire`` — `teardown`
    deletes exactly what `provision` created, nothing else.

USAGE (from the repo root, with your creds exported):

    python scripts/dynamodb_live_fire.py provision      # create table + least-priv role
    # (optional) start a sandbox gateway so `run` drives the REAL authorize+audit half:
    #   ./scripts/quickstart_demo.sh
    python scripts/dynamodb_live_fire.py run             # authorize → vend(real STS) → prove
    python scripts/dynamodb_live_fire.py teardown        # delete everything it created

    Flags:  --region us-east-1   --table mcpip-live-fire   --role mcpip-eng-dynamodb-write
            --gateway http://localhost:8080   (--no-gateway to skip the ceremony half)
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import urllib.error
import urllib.request
import uuid
from pathlib import Path
from typing import Any, Optional

# Make MCPIP importable when run from the repo root (so the vend is the REAL broker code).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

TENANT = "mcpip-inc"
TEAM_ENGINEERING = "e0900000-0000-4000-8000-e0900000e090"
SKILL = "skill_aws_dynamodb"
ENV_ID = "aws-eng-dynamodb-write"

_TTY = sys.stdout.isatty()
BOLD = "\033[1m" if _TTY else ""
DIM = "\033[2m" if _TTY else ""
GREEN = "\033[32m" if _TTY else ""
RED = "\033[31m" if _TTY else ""
YELLOW = "\033[33m" if _TTY else ""
CYAN = "\033[36m" if _TTY else ""
RESET = "\033[0m" if _TTY else ""


def _say(msg: str) -> None:
    print(f"{BOLD}◐ {msg}{RESET}")


def _ok(msg: str) -> None:
    print(f"    {GREEN}✓{RESET} {msg}")


def _warn(msg: str) -> None:
    print(f"    {YELLOW}‼ {msg}{RESET}")


def _die(msg: str) -> None:
    print(f"{RED}✕ {msg}{RESET}", file=sys.stderr)
    raise SystemExit(1)


def _import_boto3() -> Any:
    try:
        import boto3  # type: ignore[import-untyped]

        return boto3
    except ImportError:
        _die("boto3 is required for the live-fire — install it:  pip install boto3")


def _table_arn(region: str, account: str, table: str) -> str:
    return f"arn:aws:dynamodb:{region}:{account}:table/{table}"


def _role_arn(account: str, role: str) -> str:
    return f"arn:aws:iam::{account}:role/{role}"


# --- provision --------------------------------------------------------------------

def cmd_provision(args: argparse.Namespace) -> int:
    boto3 = _import_boto3()
    from botocore.exceptions import ClientError  # type: ignore[import-untyped]

    sts = boto3.client("sts", region_name=args.region)
    account = sts.get_caller_identity()["Account"]
    _say(f"provisioning in account {account} · region {args.region}")

    # 1) DynamoDB table (on-demand) — the ONE resource the vended credential may write.
    ddb = boto3.client("dynamodb", region_name=args.region)
    try:
        ddb.create_table(
            TableName=args.table,
            BillingMode="PAY_PER_REQUEST",
            AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"}],
            KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}],
        )
        _ok(f"creating table {args.table} …")
        ddb.get_waiter("table_exists").wait(TableName=args.table)
        _ok("table ACTIVE")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceInUseException":
            _ok(f"table {args.table} already exists — reusing")
        else:
            raise

    # 2) Least-privilege role: trust the account (so the gateway host identity can assume
    #    it) and grant EXACTLY dynamodb:PutItem on the one table — nothing else.
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"AWS": f"arn:aws:iam::{account}:root"},
            "Action": "sts:AssumeRole",
        }],
    }
    policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Sid": "PutItemOneTableOnly",
            "Effect": "Allow",
            "Action": "dynamodb:PutItem",
            "Resource": _table_arn(args.region, account, args.table),
        }],
    }
    iam = boto3.client("iam")
    try:
        iam.create_role(
            RoleName=args.role,
            AssumeRolePolicyDocument=json.dumps(trust),
            Description="MCPIP live-fire - least-privilege DynamoDB PutItem (one table).",
            MaxSessionDuration=3600,
        )
        _ok(f"creating role {args.role} …")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "EntityAlreadyExists":
            _ok(f"role {args.role} already exists — updating its policy")
            iam.update_assume_role_policy(RoleName=args.role, PolicyDocument=json.dumps(trust))
        else:
            raise
    iam.put_role_policy(
        RoleName=args.role, PolicyName="mcpip-putitem-one-table", PolicyDocument=json.dumps(policy)
    )
    _ok("attached least-privilege policy: dynamodb:PutItem on one table, nothing else")

    print()
    _say("provisioned — role ARN:")
    print(f"    {CYAN}{_role_arn(account, args.role)}{RESET}")
    print(f"{DIM}Next:  python scripts/dynamodb_live_fire.py run --region {args.region}{RESET}")
    return 0


# --- the gateway authorize + step-up ceremony (the audit half) ---------------------

def _gw(base: str, path: str, *, method: str, body: Optional[dict[str, Any]], token: Optional[str]) -> tuple[int, dict[str, Any]]:
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(f"{base}{path}", data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read() or b"{}")
    except urllib.error.HTTPError as exc:
        try:
            return exc.code, json.loads(exc.read() or b"{}")
        except Exception:  # noqa: BLE001
            return exc.code, {}
    except urllib.error.URLError:
        return 0, {}


def _authorize_via_gateway(base: str, item: dict[str, Any], table: str) -> bool:
    """Drive the REAL pipeline: mint eng identity → stage step-up → complete → ALLOW.

    Returns True iff the gateway committed an ALLOW receipt (and thus WORM-logged it).
    This is the authorize+audit half; the real STS vend happens after, in `run`.
    """
    _say("authorize + audit — routing the write through the MCPIP pipeline")
    st, tok = _gw(base, "/v1/dev/token", method="POST",
                  body={"tenant_id": TENANT, "agent_id": "agent-eng-ddb-livefire", "compartment": TEAM_ENGINEERING},
                  token=None)
    if st != 200:
        _warn(f"gateway did not mint a token (HTTP {st}) — is it in SANDBOX mode? Skipping ceremony.")
        return False
    token = str(tok.get("jwt") or tok.get("token"))
    call = {
        "source_format": "mcp_jsonrpc",
        "tool_call": {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                      "params": {"name": SKILL, "arguments": {"table": table, "item": item}}},
    }
    st, staged = _gw(base, "/v1/authorize", method="POST", body=call, token=token)
    if st != 202 or not staged.get("challenge_id"):
        _warn(f"expected a step-up challenge (202), got HTTP {st}: {staged}")
        return False
    challenge_id = str(staged["challenge_id"])
    _ok("gateway staged a payload-bound step-up (the write demands a PIN)")
    st, otp_body = _gw(base, f"/v1/authenticator/{challenge_id}", method="GET", body=None, token=token)
    if st != 200 or not otp_body.get("otp"):
        _warn(f"could not fetch the sandbox OTP (HTTP {st})")
        return False
    completed = dict(call)
    completed["pin"] = str(otp_body["otp"])
    completed["challenge_id"] = challenge_id
    st, receipt = _gw(base, "/v1/authorize", method="POST", body=completed, token=token)
    if st == 200 and receipt.get("decision") == "allow":
        _ok(f"ALLOW — committed to WORM (worm #{receipt.get('worm_sequence')}) BEFORE any credential is vended")
        return True
    _warn(f"gateway did not ALLOW (HTTP {st}): {receipt}")
    return False


# --- run: real STS vend (MCPIP broker) + least-privilege proof ---------------------

def cmd_run(args: argparse.Namespace) -> int:
    boto3 = _import_boto3()
    from botocore.exceptions import ClientError  # type: ignore[import-untyped]
    from services.cloud_broker import CloudBroker, CloudEnvironment

    sts = boto3.client("sts", region_name=args.region)
    account = sts.get_caller_identity()["Account"]
    role_arn = _role_arn(account, args.role)
    item = {"pk": {"S": f"livefire-{uuid.uuid4().hex[:8]}"}, "note": {"S": "written via an MCPIP-vended, least-privilege credential"}}
    # Plain-dict item for the gateway ceremony (the pipeline is payload-agnostic; it only
    # binds the payload into the PIN lock — it does not read fields).
    plain_item = {"pk": item["pk"]["S"], "note": item["note"]["S"]}

    # ── The audit half: authorize through the real pipeline (optional but faithful). ──
    if args.gateway and not args.no_gateway:
        allowed = _authorize_via_gateway(args.gateway.rstrip("/"), plain_item, args.table)
        if not allowed:
            _die("gateway did not authorize the write — refusing to vend (fail closed). "
                 "Start a sandbox gateway (./scripts/quickstart_demo.sh) or pass --no-gateway.")
        print()
    else:
        _warn("skipping the gateway authorize+audit half (--no-gateway) — vending directly. "
              "In production the gateway ALWAYS authorizes first; see dynamodb_vend_demo.py.")

    # ── The cloud half: MCPIP's REAL broker assumes the role via STS (host identity). ──
    _say("vend — MCPIP's broker mints a short-lived, write-scoped credential (real STS)")
    env = CloudEnvironment(
        env_id=ENV_ID, provider="aws", role=role_arn, region=args.region,
        compartment=TEAM_ENGINEERING, session_ttl=900,
    )
    broker = CloudBroker(sandbox_mode=False)  # PRODUCTION vend path — real sts:AssumeRole.
    try:
        vended = asyncio.run(broker.vend(env, request_nonce=uuid.uuid4().hex))
    except Exception as exc:  # noqa: BLE001 — surface the AWS error honestly.
        _die(f"real STS vend failed: {exc}\n"
             f"  Check that {role_arn} exists (run `provision`) and your creds may assume it.")
    _ok(f"vended: {vended.fingerprint}")
    _ok(f"short-lived — expires in {vended.expires_in}s; provider={vended.provider}; simulated={vended.simulated}")
    if vended.simulated:
        _die("broker returned a SIMULATED credential — you are in sandbox mode, not real vend.")
    # The secret is the deliverable to the agent; the operator-visible fingerprint is safe.
    _ok("the fingerprint above is what WORM/operators see — the secret material is redacted from it")

    session = boto3.Session(
        aws_access_key_id=vended.material["access_key_id"],
        aws_secret_access_key=vended.material["secret_access_key"],
        aws_session_token=vended.material["session_token"],
        region_name=args.region,
    )

    print()
    _say("prove the boundary — the vended credential can do EXACTLY one thing")
    # (1) The one allowed action: PutItem to the one table → SUCCEEDS.
    ddb = session.client("dynamodb")
    try:
        ddb.put_item(TableName=args.table, Item=item)
        _ok(f"PutItem → {args.table}  ALLOWED (the authorized write succeeded)")
    except ClientError as exc:
        _die(f"PutItem unexpectedly failed: {exc.response['Error']['Code']} — check the role policy")

    failures = 0
    # (2) Read the SAME table → DENIED (only PutItem was granted; the agent cannot exfiltrate).
    try:
        ddb.get_item(TableName=args.table, Key={"pk": item["pk"]})
        _warn("GetItem on the same table SUCCEEDED — least-privilege is NOT holding (expected AccessDenied)")
        failures += 1
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("AccessDeniedException", "AccessDenied"):
            _ok("GetItem (read) on the same table  DENIED — the credential writes but cannot read back")
        else:
            _warn(f"GetItem failed with unexpected code {code} (expected AccessDenied)")
            failures += 1
    # (3) Reach a different AWS service (S3) → DENIED (no blast radius beyond the role).
    try:
        session.client("s3").list_buckets()
        _warn("s3:ListBuckets SUCCEEDED — least-privilege is NOT holding (expected AccessDenied)")
        failures += 1
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code in ("AccessDenied", "AccessDeniedException"):
            _ok("s3:ListBuckets  DENIED — the credential cannot touch any other service")
        else:
            _warn(f"s3:ListBuckets failed with unexpected code {code} (expected AccessDenied)")
            failures += 1

    print()
    if failures == 0:
        print(f"{GREEN}{BOLD}✓ Live-fire held: an authorized, audited, least-privilege write — and nothing more.{RESET}")
        print(f"{DIM}The agent never held a standing key. MCPIP authorized + audited the call, then vended a")
        print(f"credential that could write one row to one table and could neither read it back nor reach")
        print(f"any other resource. That least-privilege boundary — not payload inspection — is the control.{RESET}")
        print(f"{DIM}Clean up:  python scripts/dynamodb_live_fire.py teardown --region {args.region}{RESET}")
        return 0
    print(f"{RED}{BOLD}‼ {failures} boundary check(s) did not hold — inspect the role policy above.{RESET}")
    return 1


# --- teardown ---------------------------------------------------------------------

def cmd_teardown(args: argparse.Namespace) -> int:
    boto3 = _import_boto3()
    from botocore.exceptions import ClientError  # type: ignore[import-untyped]

    _say("teardown — deleting exactly what provision created")
    iam = boto3.client("iam")
    try:
        iam.delete_role_policy(RoleName=args.role, PolicyName="mcpip-putitem-one-table")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            _warn(f"delete_role_policy: {exc.response['Error']['Code']}")
    try:
        iam.delete_role(RoleName=args.role)
        _ok(f"deleted role {args.role}")
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "NoSuchEntity":
            _ok(f"role {args.role} already gone")
        else:
            _warn(f"delete_role: {code}")

    ddb = boto3.client("dynamodb", region_name=args.region)
    try:
        ddb.delete_table(TableName=args.table)
        _ok(f"deleting table {args.table} …")
        ddb.get_waiter("table_not_exists").wait(TableName=args.table)
        _ok("table deleted")
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            _ok(f"table {args.table} already gone")
        else:
            _warn(f"delete_table: {exc.response['Error']['Code']}")
    print()
    _say("teardown complete")
    return 0


def main() -> int:
    # Flags live on a shared parent attached to each SUBcommand, so the documented
    # order (`... provision --region us-east-1`) parses.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--region", default="us-east-1")
    common.add_argument("--table", default="mcpip-live-fire")
    common.add_argument("--role", default="mcpip-eng-dynamodb-write")
    common.add_argument("--gateway", default="http://localhost:8080",
                        help="sandbox gateway base URL for the authorize+audit half")
    common.add_argument("--no-gateway", action="store_true",
                        help="skip the gateway ceremony and vend directly (less faithful)")
    parser = argparse.ArgumentParser(description="MCPIP DynamoDB write live-fire (run locally, own creds).")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("provision", parents=[common], help="create the table + least-privilege role")
    sub.add_parser("run", parents=[common], help="authorize (gateway) → vend (real STS) → prove least-privilege")
    sub.add_parser("teardown", parents=[common], help="delete everything provision created")
    args = parser.parse_args()

    if args.cmd == "provision":
        return cmd_provision(args)
    if args.cmd == "run":
        return cmd_run(args)
    if args.cmd == "teardown":
        return cmd_teardown(args)
    parser.print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
