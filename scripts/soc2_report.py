#!/usr/bin/env python3
"""
MCPIP — historical SOC 2 evidence report.

    ◐ "A point-in-time attestation says the ledger is intact NOW. An auditor asks
      what happened over the PERIOD. This walks the whole decision history,
      aggregates the behaviour, and ties every number back to a record an auditor
      can pull individually."

``/v1/admin/compliance/evidence`` already emits a portable bundle: the signed WORM
attestation, the live ``verify_chain`` verdict, the running version + release
provenance, and a static control mapping. What it does not do is cover a *period* —
and a SOC 2 Type II engagement is about a period, not an instant.

This script closes that gap by composing surfaces the gateway already exposes:

  * ``GET /v1/admin/decisions``          date-ranged, cursor-paged decision history
  * ``GET /v1/audit/attestation``        signed Merkle root + epoch head + verdict
  * ``GET /v1/admin/compliance/evidence`` control mapping + provenance
  * ``GET /v1/version`` / ``/v1/license``  what was running, under what entitlement

and emits a report where **every aggregate is traceable**: each figure names the
`worm_sequence` range and correlation ids behind it, so "22 denials" is never a
number you have to trust — it is 22 records you can fetch by id.

DISCIPLINE (mirrors ``services/compliance_evidence.py``):
  * EVIDENCE, NEVER CERTIFICATION. Nothing here asserts a control passed, an
    auditor signed off, or a report was issued. It states what the gateway
    observed and which clause that observation is evidence FOR.
  * NO FABRICATION. Every figure is computed from rows the gateway returned. A
    window with no traffic reports zero and says so; it never interpolates.
  * NO SECRETS, NO TOPOLOGY. The decision projection is the gateway's own strict
    whitelist — no target, no payload, no credential. This script never widens it.
  * COVERAGE IS STATED, NOT ASSUMED. The decision history is a bounded scan over
    the durable event buffer, NOT the authoritative record. When the scan is
    truncated or the window predates the buffer, the report says so rather than
    implying completeness. The authoritative record remains the signed epoch
    chain (``mcpip export-audit --verify``).

Usage:

    python3 scripts/soc2_report.py --gateway http://127.0.0.1:8080 \\
        --token-file operator.jwt --days 90 --out report.md --json report.json

The token must carry ``CAP_DIRECTORY_ADMIN``; every read used here is admin-gated.
"""

from __future__ import annotations

import argparse
import collections
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

TIMEOUT_S = 30
PAGE_LIMIT = 200
#: Hard stop so a pathological history cannot spin forever. Truncation is REPORTED.
MAX_PAGES = 2000


# --------------------------------------------------------------------------
# Transport
# --------------------------------------------------------------------------


def _get(base: str, path: str, token: str, params: Optional[dict[str, Any]] = None) -> Any:
    """One admin GET. Returns the decoded body, or None when the read is unavailable."""
    url = f"{base.rstrip('/')}{path}"
    if params:
        url = f"{url}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT_S) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        # 403 here means the token lacks the capability; 404 means the surface is
        # not mounted on this build. Both are reported, never silently zeroed.
        return {"__error__": exc.code, "__path__": path}
    except Exception as exc:  # noqa: BLE001 — network/parse; reported, not raised.
        return {"__error__": str(exc), "__path__": path}


def _err(obj: Any) -> Optional[str]:
    if isinstance(obj, dict) and "__error__" in obj:
        return f"{obj['__path__']} -> {obj['__error__']}"
    return None


# --------------------------------------------------------------------------
# History walk
# --------------------------------------------------------------------------


def _iso_ms(epoch_ms: int) -> str:
    return datetime.fromtimestamp(epoch_ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def fetch_history(base: str, token: str, from_ms: int, to_ms: int) -> tuple[list[dict], dict]:
    """
    Page the decision history for the window.

    Returns ``(rows, coverage)``. ``coverage`` records how the walk terminated so the
    report can state completeness honestly:

      ``exhausted``      the gateway ASSERTED there is no more (``exhausted: true``)
      ``page_cap``       we stopped at MAX_PAGES
      ``cursor_lost``    paging stopped without that assertion — indeterminate
      ``error``          a read failed

    ``exhausted`` used to be the INITIAL value, so every termination that was not an
    error inherited it: a page that merely omitted ``next_cursor`` — an older gateway,
    a proxy dropping a field, an empty batch mid-walk — produced a report stating
    "every record the durable buffer holds for this window is included" that nothing
    had ever attested. Completeness is now an assertion, never a default; anything
    else is ``cursor_lost``, which reads as a lower bound.

    ``retention_floor_ms`` is carried out too, and it matters more than the walk. The
    event buffer is TRIMMED. Walking it to exhaustion says nothing about records
    evicted before the walk began, so a period that starts before the oldest row still
    held is partially retained no matter how cleanly the paging terminated — and that,
    not the paging, is the way this report could most plausibly overstate a period.
    """
    rows: list[dict] = []
    cursor: Optional[str] = None
    pages = 0
    coverage: dict[str, Any] = {
        "terminated": "cursor_lost",
        "pages": 0,
        "scanned": 0,
        "error": None,
        "retention_floor_ms": None,
    }

    while pages < MAX_PAGES:
        params: dict[str, Any] = {"limit": PAGE_LIMIT, "from_ms": from_ms, "to_ms": to_ms}
        if cursor:
            params["cursor"] = cursor
        page = _get(base, "/v1/admin/decisions", token, params)
        err = _err(page)
        if err:
            coverage["terminated"] = "error"
            coverage["error"] = err
            break
        batch = page.get("decisions") or []
        rows.extend(batch)
        coverage["scanned"] += int(page.get("scanned") or len(batch))
        pages += 1
        floor = page.get("retention_floor_ms")
        if isinstance(floor, int):
            # Newest-first paging: the last page read is the closest to the horizon.
            coverage["retention_floor_ms"] = floor
        if page.get("exhausted") is True:
            coverage["terminated"] = "exhausted"
            break
        cursor = page.get("next_cursor")
        if not cursor or not batch:
            break  # stays cursor_lost — the gateway never said the range was drained
    else:
        coverage["terminated"] = "page_cap"

    coverage["pages"] = pages
    return rows, coverage


# --------------------------------------------------------------------------
# Aggregation — every bucket keeps the ids that produced it
# --------------------------------------------------------------------------


def aggregate(rows: list[dict]) -> dict[str, Any]:
    """
    Reduce the history to the facets an auditor asks about, keeping traceability:
    each bucket carries its `worm_sequence` range and a sample of correlation ids,
    so any figure can be re-fetched record by record.
    """

    def bucket() -> dict[str, Any]:
        return {"count": 0, "seq_min": None, "seq_max": None, "sample_correlation_ids": []}

    def add(b: dict[str, Any], row: dict) -> None:
        b["count"] += 1
        seq = row.get("worm_sequence")
        if isinstance(seq, int):
            b["seq_min"] = seq if b["seq_min"] is None else min(b["seq_min"], seq)
            b["seq_max"] = seq if b["seq_max"] is None else max(b["seq_max"], seq)
        cid = row.get("correlation_id")
        if cid and len(b["sample_correlation_ids"]) < 5:
            b["sample_correlation_ids"].append(cid)

    by_decision: dict[str, dict] = collections.defaultdict(bucket)
    by_deny: dict[str, dict] = collections.defaultdict(bucket)
    by_agent: dict[str, dict] = collections.defaultdict(bucket)
    by_alias: dict[str, dict] = collections.defaultdict(bucket)
    by_risk: dict[str, dict] = collections.defaultdict(bucket)
    by_class: dict[str, dict] = collections.defaultdict(bucket)
    by_format: dict[str, dict] = collections.defaultdict(bucket)

    seq_min: Optional[int] = None
    seq_max: Optional[int] = None
    ts_min: Optional[int] = None
    ts_max: Optional[int] = None

    for row in rows:
        add(by_decision[str(row.get("decision"))], row)
        if row.get("deny_reason"):
            add(by_deny[str(row["deny_reason"])], row)
        add(by_agent[str(row.get("agent_id"))], row)
        add(by_alias[str(row.get("alias"))], row)
        add(by_risk[str(row.get("risk_tier"))], row)
        add(by_class[str(row.get("classification"))], row)
        add(by_format[str(row.get("source_format"))], row)

        seq = row.get("worm_sequence")
        if isinstance(seq, int):
            seq_min = seq if seq_min is None else min(seq_min, seq)
            seq_max = seq if seq_max is None else max(seq_max, seq)
        ts = row.get("timestamp_ns")
        if isinstance(ts, int):
            ts_min = ts if ts_min is None else min(ts_min, ts)
            ts_max = ts if ts_max is None else max(ts_max, ts)

    return {
        "total": len(rows),
        "worm_sequence_range": [seq_min, seq_max],
        "timestamp_ns_range": [ts_min, ts_max],
        "by_decision": dict(by_decision),
        "by_deny_reason": dict(by_deny),
        "by_agent": dict(by_agent),
        "by_alias": dict(by_alias),
        "by_risk_tier": dict(by_risk),
        "by_classification": dict(by_class),
        "by_source_format": dict(by_format),
    }


#: Which observed behaviour is evidence FOR which SOC 2 Trust Services Criterion.
#: Phrased as evidence, never as a pass — the certification is an external process.
CONTROL_EVIDENCE: tuple[tuple[str, str, str], ...] = (
    ("CC6.1", "Logical access — every action carries a verified identity",
     "Each decision row names the `agent_id` the gateway VERIFIED from a signed "
     "principal token. Rows with no verified identity cannot exist: identity "
     "resolution precedes the decision."),
    ("CC6.7", "Restricted access to sensitive data",
     "`classification` and `risk_tier` per decision show which calls touched "
     "restricted surfaces and how they were gated."),
    ("CC7.2", "Monitoring for anomalies",
     "Deny-reason distribution over the period; each reason bucket is traceable "
     "to individual records by correlation id."),
    ("CC7.3", "Evaluation of security events",
     "`unknown_alias`, `principal_revoked` and step-up failures are recorded per "
     "occurrence rather than summarised, so each is individually reviewable."),
    ("CC8.1", "Change management",
     "Admin actions (alias registration, revocation, reactivation) are written to "
     "the same WORM ledger as authorization decisions, by the same actor identity."),
    ("A1.2", "Availability / durability commitments",
     "Every allow is written fsync-durable to the audit buffer BEFORE it is "
     "returned (write-before-execute); the gateway refuses to boot without that "
     "Redis posture."),
    ("C1.1", "Confidentiality of information",
     "The decision projection is a strict whitelist — no target, payload, or "
     "credential appears in the ledger or in this report."),
    ("CC4.1", "Ongoing evaluation",
     "The signed epoch chain is re-verified continuously; the attestation below "
     "carries the verdict for the period end."),
)


# --------------------------------------------------------------------------
# Rendering
# --------------------------------------------------------------------------


def _rows(title: str, buckets: dict[str, dict], total: int, limit: int = 15) -> list[str]:
    if not buckets:
        return [f"### {title}", "", "_No records in the period._", ""]
    out = [f"### {title}", "",
           "| value | count | share | worm_sequence range | sample correlation ids |",
           "|---|---:|---:|---|---|"]
    ordered = sorted(buckets.items(), key=lambda kv: kv[1]["count"], reverse=True)
    for key, b in ordered[:limit]:
        share = f"{(100.0 * b['count'] / total):.1f}%" if total else "—"
        rng = (f"{b['seq_min']}–{b['seq_max']}"
               if b["seq_min"] is not None else "—")
        ids = ", ".join(f"`{c[:12]}…`" for c in b["sample_correlation_ids"]) or "—"
        out.append(f"| `{key}` | {b['count']} | {share} | {rng} | {ids} |")
    if len(ordered) > limit:
        out.append(f"| _…{len(ordered) - limit} more_ | | | | |")
    out.append("")
    return out


def render(report: dict[str, Any]) -> str:
    agg = report["aggregate"]
    att = report.get("attestation") or {}
    cov = report["coverage"]
    total = agg["total"]
    L: list[str] = []

    L += [
        "# SOC 2 evidence report — observed period",
        "",
        "> **This is evidence, not a certification.** It reports what the MCPIP "
        "gateway observed and recorded over the period, and states which Trust "
        "Services Criterion each observation provides evidence FOR. It asserts no "
        "SOC 2 report, no auditor opinion, and no control 'pass' — those are "
        "external third-party processes this software cannot produce.",
        "",
        "## Period and scope",
        "",
        "| field | value |",
        "|---|---|",
        f"| Period start | `{report['window']['from_iso']}` |",
        f"| Period end | `{report['window']['to_iso']}` |",
        f"| Gateway | `{report['gateway']}` |",
        f"| Tenant | `{report.get('tenant') or '—'}` |",
        f"| Running version | `{report.get('version') or '—'}` |",
        f"| Entitlement | `{report.get('license_tier') or '—'}` "
        f"(`{report.get('license_id') or '—'}`) |",
        f"| Decisions in period | **{total}** |",
        f"| worm_sequence range | `{agg['worm_sequence_range'][0]}`–`{agg['worm_sequence_range'][1]}` |",
        "",
    ]

    # Coverage is stated before any figure, so no number is read as complete
    # when the underlying scan was not.
    L += ["## Coverage of this report", ""]
    if cov["terminated"] == "exhausted":
        L += [f"The gateway reported the range drained — {cov['pages']} page(s), "
              f"{cov['scanned']} row(s) scanned. Every record the durable buffer STILL "
              "HOLDS for this window is included (see the retention horizon below).", ""]
    elif cov["terminated"] == "page_cap":
        L += [f"**Truncated.** The walk stopped at the {MAX_PAGES}-page safety cap after "
              f"{cov['scanned']} rows. Figures below cover the newest records only and "
              "are a LOWER BOUND. Narrow the window and re-run for full coverage.", ""]
    elif cov["terminated"] == "cursor_lost":
        L += [f"**Indeterminate.** Paging stopped after {cov['pages']} page(s) / "
              f"{cov['scanned']} row(s) without the gateway asserting the range was "
              "drained. Figures below are a LOWER BOUND and must not be presented as a "
              "period total.", ""]
    else:
        L += [f"**Incomplete.** The history read failed (`{cov['error']}`). Figures below "
              "cover only what was retrieved and must not be treated as the period total.", ""]

    # Retention is the completeness question the paging cannot answer: the event buffer
    # is trimmed, so a clean walk over what remains says nothing about what was evicted
    # before the walk started.
    floor = cov.get("retention_floor_ms")
    from_ms = report["window"]["from_ms"]
    from_iso = report["window"]["from_iso"]
    L += ["### Retention horizon", ""]
    if not isinstance(floor, int):
        L += ["**Unknown.** The oldest retained record could not be determined, so this "
              "report cannot demonstrate that the period is fully retained. Treat the "
              "figures as a lower bound for any part of the window older than the "
              "buffer's trim.", ""]
    elif floor > from_ms:
        L += [f"**Partially retained.** The oldest record the buffer still holds is "
              f"`{_iso_ms(floor)}`, which is AFTER the period start `{from_iso}`. "
              "Decisions from the earlier part of this period have been trimmed and are "
              "not counted below. For that span the signed epoch chain — not this "
              "report — is the record.", ""]
    else:
        L += [f"The buffer retains back to `{_iso_ms(floor)}`, at or before the period "
              f"start `{from_iso}`: no part of this window was trimmed before the walk.", ""]

    L += ["The decision history is a bounded scan over the durable event buffer, not the "
          "authoritative record. The authoritative record is the signed epoch chain; verify "
          "it independently with `mcpip export-audit --verify --pubkey <worm pubkey>`.", ""]

    # Signed commitment for the period end.
    L += ["## Signed ledger commitment (period end)", ""]
    if att and not _err(att):
        L += [
            "| field | value |",
            "|---|---|",
            f"| Chain intact | **{att.get('intact')}** |",
            f"| First bad epoch | `{att.get('first_bad_epoch')}` |",
            f"| Epoch | `{att.get('epoch')}` |",
            f"| End sequence | `{att.get('end_seq')}` |",
            f"| Merkle root | `{att.get('merkle_root')}` |",
            f"| Epoch hash | `{att.get('epoch_hash')}` |",
            f"| Signature | `{str(att.get('signature'))[:64]}…` |",
            f"| Signing key id | `{att.get('signing_key_id')}` |",
            f"| Anchor epoch | `{att.get('anchor_epoch')}` |",
            "",
            "An auditor can re-derive the Merkle root from the exported events and check "
            "the signature against the published WORM public key without trusting this "
            "report or the gateway that produced it.",
            "",
        ]
        if att.get("intact") is False:
            L += ["> **The chain did not verify.** `intact=false` means the ledger no longer "
                  "reconciles against its signed epoch head — records were altered or removed "
                  "outside the gateway. Every figure in this report is suspect until that is "
                  "explained.", ""]
    else:
        L += ["_Attestation unavailable — the report cannot bind these figures to a signed "
              "commitment. Investigate before relying on it._", ""]

    # Behaviour.
    L += ["## What happened", ""]
    if total == 0:
        L += ["No decisions were recorded in this window. This is reported as observed; "
              "nothing is interpolated.", ""]
    L += _rows("Outcomes", agg["by_decision"], total)
    L += _rows("Denial reasons", agg["by_deny_reason"], total)
    L += _rows("Per agent identity", agg["by_agent"], total)
    L += _rows("Per alias", agg["by_alias"], total)
    L += _rows("Per risk tier", agg["by_risk_tier"], total)
    L += _rows("Per classification", agg["by_classification"], total)
    L += _rows("Per declared wire format", agg["by_source_format"], total)

    # Control mapping.
    L += ["## Criterion → evidence in this period", "",
          "| criterion | what it asks | evidence observed here |", "|---|---|---|"]
    for code, asks, why in CONTROL_EVIDENCE:
        L.append(f"| **{code}** | {asks} | {why} |")
    L += ["",
          "Each row states that the mechanism PROVIDES EVIDENCE FOR the clause. None "
          "asserts the clause is satisfied — that determination belongs to an auditor.", ""]

    # Traceability instructions: the whole point of the exercise.
    L += [
        "## Tracing any figure back",
        "",
        "Every count above carries the `worm_sequence` range and sample correlation ids "
        "that produced it. To go from a number to the underlying records:",
        "",
        "```bash",
        "# 1. the individual decisions behind a bucket (same whitelist projection)",
        "curl -H \"Authorization: Bearer $OPERATOR\" \\",
        "  '<gateway>/v1/admin/decisions?deny_reason=unknown_alias&from_ms=<start>&to_ms=<end>'",
        "",
        "# 2. the signed commitment covering them",
        "curl -H \"Authorization: Bearer $OPERATOR\" '<gateway>/v1/audit/attestation'",
        "",
        "# 3. independent verification, offline, without trusting the gateway",
        "mcpip export-audit --verify --pubkey worm_signing_ed25519.pub.pem",
        "```",
        "",
        "A figure that cannot be reproduced by step 1, over a chain that fails step 3, is "
        "not evidence. Both are checkable by a party who trusts neither this report nor "
        "the gateway that produced it.",
        "",
    ]

    if report.get("errors"):
        L += ["## Reads that failed", ""]
        for e in report["errors"]:
            L.append(f"- `{e}`")
        L += ["", "These surfaces were unavailable; anything they would have contributed is "
                  "absent from this report rather than estimated.", ""]

    L += ["---", "",
          f"Generated `{report['generated_at']}` by `scripts/soc2_report.py` against "
          f"`{report['gateway']}`. Evidence, not certification.", ""]
    return "\n".join(L)


# --------------------------------------------------------------------------
# Entry point
# --------------------------------------------------------------------------


def main() -> int:
    p = argparse.ArgumentParser(description="Historical SOC 2 evidence report from a live MCPIP gateway")
    p.add_argument("--gateway", required=True, help="gateway base URL")
    tok = p.add_mutually_exclusive_group(required=True)
    tok.add_argument("--token-file", help="file holding an operator bearer (CAP_DIRECTORY_ADMIN)")
    tok.add_argument("--token", help="operator bearer inline (prefer --token-file)")
    p.add_argument("--days", type=int, default=90, help="period length in days (default 90)")
    p.add_argument("--from-ms", type=int, default=None, help="explicit window start (epoch ms)")
    p.add_argument("--to-ms", type=int, default=None, help="explicit window end (epoch ms)")
    p.add_argument("--out", default=None, help="write the Markdown report here (default: stdout)")
    p.add_argument("--json", dest="json_out", default=None, help="also write the raw report JSON here")
    args = p.parse_args()

    token = args.token
    if args.token_file:
        with open(args.token_file, encoding="utf-8") as fh:
            token = fh.read().strip()
    if not token:
        print("empty token", file=sys.stderr)
        return 2

    now = datetime.now(timezone.utc)
    to_ms = args.to_ms if args.to_ms is not None else int(now.timestamp() * 1000)
    from_ms = (args.from_ms if args.from_ms is not None
               else int((now - timedelta(days=args.days)).timestamp() * 1000))

    base = args.gateway
    errors: list[str] = []

    rows, coverage = fetch_history(base, token, from_ms, to_ms)
    if coverage["error"]:
        errors.append(coverage["error"])

    attestation = _get(base, "/v1/audit/attestation", token)
    if _err(attestation):
        errors.append(_err(attestation) or "")
        attestation = {}

    version = _get(base, "/v1/version", token)
    license_info = _get(base, "/v1/license", token)
    evidence = _get(base, "/v1/admin/compliance/evidence", token)
    for obj in (version, license_info, evidence):
        e = _err(obj)
        if e:
            errors.append(e)

    report: dict[str, Any] = {
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gateway": base,
        "window": {
            "from_ms": from_ms,
            "to_ms": to_ms,
            "from_iso": datetime.fromtimestamp(from_ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "to_iso": datetime.fromtimestamp(to_ms / 1000, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "tenant": (rows[0].get("tenant_id") if rows else None),
        "version": (version or {}).get("running") if isinstance(version, dict) else None,
        "license_tier": (license_info or {}).get("tier") if isinstance(license_info, dict) else None,
        "license_id": (license_info or {}).get("license_id") if isinstance(license_info, dict) else None,
        "coverage": coverage,
        "attestation": attestation,
        "compliance_bundle": evidence if not _err(evidence) else None,
        "aggregate": aggregate(rows),
        "errors": [e for e in errors if e],
    }

    markdown = render(report)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as fh:
            fh.write(markdown)
        print(f"report -> {args.out}  ({report['aggregate']['total']} decisions, "
              f"coverage={coverage['terminated']})")
    else:
        print(markdown)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, sort_keys=True)
        print(f"raw    -> {args.json_out}")

    # A chain that does not verify is an audit finding, not a successful run.
    if isinstance(attestation, dict) and attestation.get("intact") is False:
        print("WARNING: audit chain did NOT verify (intact=false)", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
