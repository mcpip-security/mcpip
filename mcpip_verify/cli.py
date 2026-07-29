"""
``mcpip`` CLI — READ-ONLY release verification + audit export.

Subcommands
-----------
``mcpip verify --manifest PATH --pubkey PATH [--base-dir PATH]``
    Verify a signed release manifest + every listed artifact on disk.

``mcpip verify bundle BUNDLE.tar.gz --pubkey PATH``
    Verify an offline air-gap bundle end-to-end with NO network.

``mcpip export-audit --redis-url URL --out FILE [--verify --pubkey PATH]``
    Read-only export of the WORM audit stream + epoch headers to JSONL.
    ``--verify`` independently re-verifies the whole signed chain — Merkle
    roots, ``epoch_hash``, ``prev_epoch_hash`` linkage, the Ed25519 epoch
    signatures (against ``--pubkey``, the WORM public key), and the
    out-of-tamper-domain anchor low-watermark (``--anchor-path``). It fails
    closed: ``--verify`` without ``--pubkey`` is refused rather than reporting
    a verdict no signature backed.

Fail-closed contract: on ANY RELEASE verification failure this program prints
exactly ``verification failed`` to stderr (opaque — no reason, no path, no hash)
and returns exit code 2. Success prints ``verified: mcpip <version> (<n>
artifacts)`` and returns 0. ``export-audit --verify`` is the one operator-facing
exception to that opacity — it names the failed integrity CHECK and the first bad
epoch, because the operator running it is the one triaging the incident (no agent
ever sees this output) — and also returns 2. The tool never writes anywhere except
the explicit ``--out`` file of ``export-audit`` and never self-updates anything.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Optional, Sequence

from mcpip_verify.verifier import (
    VerificationError,
    load_manifest,
    verify_artifacts,
    verify_bundle,
    verify_manifest_signature,
)

_OPAQUE_FAILURE = "verification failed"

__all__ = ["main"]


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="mcpip", description="MCPIP release verification (read-only)"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    verify = sub.add_parser("verify", help="verify a release manifest or bundle")
    verify.add_argument(
        "target",
        nargs="*",
        default=[],
        help="'bundle BUNDLE.tar.gz' (or a bundle path) for bundle mode; "
        "empty for manifest mode",
    )
    verify.add_argument("--manifest", default=None, help="release manifest JSON")
    verify.add_argument(
        "--pubkey", required=True, help="release root PUBLIC key (PEM)"
    )
    verify.add_argument(
        "--base-dir", default=".", help="root the manifest paths resolve against"
    )

    export = sub.add_parser(
        "export-audit", help="read-only WORM audit export to JSONL"
    )
    export.add_argument("--redis-url", default="redis://localhost:63790/0")
    export.add_argument("--out", required=True, help="output JSONL path")
    export.add_argument(
        "--verify",
        action="store_true",
        help="independently re-verify the exported chain (requires --pubkey)",
    )
    export.add_argument(
        "--pubkey",
        default=None,
        help="WORM epoch-signing PUBLIC key (PEM) — "
        "worm_signing_ed25519.pub.pem from the key ceremony",
    )
    export.add_argument(
        "--anchor-path",
        default=None,
        help="out-of-tamper-domain anchor file (default: MCPIP_WORM_ANCHOR_PATH, "
        "else <MCPIP_WORM_PATH>.anchor)",
    )
    export.add_argument(
        "--require-anchor",
        action="store_true",
        help="fail when no signed anchor watermark is found (continuous checks)",
    )
    return parser


def _bundle_path_from_target(target: list[str]) -> Optional[Path]:
    """Accept `verify bundle X.tar.gz` and `verify X.tar.gz`; None = manifest mode."""
    if not target:
        return None
    if len(target) == 2 and target[0] == "bundle":
        return Path(target[1])
    if len(target) == 1 and target[0] != "bundle":
        return Path(target[0])
    raise VerificationError("bad arguments")


def _summarize(manifest: dict[str, object]) -> str:
    version = manifest.get("version")
    artifacts = manifest.get("artifacts")
    count = len(artifacts) if isinstance(artifacts, list) else 0
    return f"verified: mcpip {version} ({count} artifacts)"


def _run_verify(args: argparse.Namespace) -> int:
    pubkey_pem = Path(args.pubkey).read_bytes()
    bundle = _bundle_path_from_target(list(args.target))
    if bundle is not None:
        verify_bundle(bundle, pubkey_pem)
        # Re-read only the manifest member for the summary line (cheap).
        import json
        import tarfile

        with tarfile.open(bundle, mode="r:gz") as archive:
            names = [
                n for n in archive.getnames() if n.endswith("/manifest.json")
            ]
            extracted = archive.extractfile(names[0]) if names else None
            if extracted is None:
                raise VerificationError("bad bundle layout")
            manifest_obj = json.loads(extracted.read().decode("utf-8"))
        if not isinstance(manifest_obj, dict):
            raise VerificationError("bad bundle layout")
        print(_summarize(manifest_obj))
        return 0
    if args.manifest is None:
        raise VerificationError("no manifest given")
    manifest = load_manifest(Path(args.manifest))
    verify_manifest_signature(manifest, pubkey_pem)
    verify_artifacts(manifest, Path(args.base_dir))
    print(_summarize(manifest))
    return 0


def _run_export_audit(args: argparse.Namespace) -> int:
    # Local import keeps `mcpip verify` free of any redis dependency.
    from mcpip_verify.audit_export import export_audit

    pubkey_pem = Path(args.pubkey).read_bytes() if args.pubkey else None
    result = export_audit(
        args.redis_url,
        Path(args.out),
        bool(args.verify),
        public_key_pem=pubkey_pem,
        anchor_path=args.anchor_path,
        require_anchor=bool(args.require_anchor),
    )
    print(f"exported: {result.events} events, {result.epochs} epochs -> {args.out}")
    if args.verify:
        # Both verdict lines NAME the checks: an operator must never have to guess
        # which proofs a green run actually computed (or a red run failed).
        if not result.intact:
            position = (
                "" if result.first_bad_epoch is None
                else f" at epoch {result.first_bad_epoch}"
            )
            print(
                f"audit chain: TAMPERED — {result.failed_check} failed{position}",
                file=sys.stderr,
            )
            return 2
        anchor = (
            f", anchor low-watermark epoch {result.anchor_epoch} matched"
            if result.anchor_epoch is not None
            else ""
        )
        print(
            f"audit chain: intact — {result.verified_epochs} epochs fully verified, "
            f"{result.signature_only_epochs} signature-only (events trimmed){anchor}"
        )
        print(f"  checked: {', '.join(result.checks_performed)}")
        for skipped in result.checks_not_performed:
            print(f"  NOT checked: {skipped}")
    return 0


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "export-audit" and args.verify and not args.pubkey:
        # Fail closed on the USAGE, not with a green verdict: without the WORM
        # public key the epoch signatures cannot be checked at all.
        parser.error("--verify requires --pubkey (the WORM public key PEM)")
    try:
        if args.command == "verify":
            return _run_verify(args)
        return _run_export_audit(args)
    except Exception:  # noqa: BLE001 — opaque fail-closed by design.
        print(_OPAQUE_FAILURE, file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
