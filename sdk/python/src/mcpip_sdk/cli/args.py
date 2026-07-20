"""
mcpip_sdk.cli.args — ``--arg k=v`` parsing with EXPLICIT typed coercion, plus
the ``@file`` / stdin loaders for whole-document inputs.

Type inference is a security hazard here: the gateway locks a step-up against
the EXACT arguments it first saw, so silently coercing a ZIP code ``"01234"``
to an int or ``"true"`` to a bool would change the payload the lock binds. So
the default is ALWAYS string; a caller opts into another JSON type with an
explicit prefix (``int:`` / ``float:`` / ``bool:`` / ``json:`` / ``str:``).
There is no bare-value inference.
"""

from __future__ import annotations

import json
import sys
from typing import Any

from mcpip_sdk.cli.errors import CLIConfigError


def coerce_value(raw: str) -> Any:
    """
    Coerce one ``--arg`` value string per its explicit prefix.

    * ``str:foo``   → ``"foo"`` (also the DEFAULT for an unprefixed value)
    * ``int:42``    → ``42``
    * ``float:1.5`` → ``1.5``
    * ``bool:true`` → ``True`` (accepts true/false/1/0/yes/no, case-insensitive)
    * ``json:{...}``→ the parsed JSON value (object/array/number/…)

    A bad literal for a declared prefix is a usage error (``CLIConfigError`` →
    exit 8), never a silent fallback that would drift the payload.
    """
    for prefix, converter in (
        ("str:", _as_str),
        ("int:", _as_int),
        ("float:", _as_float),
        ("bool:", _as_bool),
        ("json:", _as_json),
    ):
        if raw.startswith(prefix):
            return converter(raw[len(prefix):])
    # No prefix → string verbatim (no inference — safest, and the lock-stable
    # default).
    return raw


def _as_str(body: str) -> str:
    return body


def _as_int(body: str) -> int:
    try:
        return int(body, 10)
    except ValueError as exc:
        raise CLIConfigError(f"--arg int: value is not an integer: {body!r}") from exc


def _as_float(body: str) -> float:
    try:
        return float(body)
    except ValueError as exc:
        raise CLIConfigError(f"--arg float: value is not a number: {body!r}") from exc


def _as_bool(body: str) -> bool:
    lowered = body.strip().lower()
    if lowered in ("true", "1", "yes", "on"):
        return True
    if lowered in ("false", "0", "no", "off"):
        return False
    raise CLIConfigError(f"--arg bool: value is not a boolean: {body!r}")


def _as_json(body: str) -> Any:
    try:
        return json.loads(body)
    except ValueError as exc:
        raise CLIConfigError(f"--arg json: value is not valid JSON: {body!r}") from exc


def collect_args(pairs: list[str] | None) -> dict[str, Any]:
    """
    Fold repeated ``--arg key=value`` flags into one arguments dict.

    The key is everything before the FIRST ``=``; the value (which may itself
    contain ``=``) is coerced by :func:`coerce_value`. A later key overrides an
    earlier one. A pair with no ``=`` is a usage error.
    """
    result: dict[str, Any] = {}
    for pair in pairs or []:
        if "=" not in pair:
            raise CLIConfigError(
                f"--arg must be key=value (missing '='): {pair!r}"
            )
        key, _, value = pair.partition("=")
        if not key:
            raise CLIConfigError(f"--arg has an empty key: {pair!r}")
        result[key] = coerce_value(value)
    return result


def load_document(spec: str) -> Any:
    """
    Load a whole JSON document from a ``@path`` reference, ``-`` (stdin), or a
    literal JSON string. Used by ``--tool-call`` / ``--context`` / ``--file`` /
    ``--manifest`` / ``--material-file`` inputs.
    """
    if spec == "-":
        text = sys.stdin.read()
    elif spec.startswith("@"):
        path = spec[1:]
        try:
            with open(path, "r", encoding="utf-8") as handle:
                text = handle.read()
        except OSError as exc:
            raise CLIConfigError(f"cannot read {path!r}: {exc.strerror}") from exc
    else:
        text = spec
    try:
        return json.loads(text)
    except ValueError as exc:
        raise CLIConfigError(f"input is not valid JSON: {spec!r}") from exc


__all__ = ["coerce_value", "collect_args", "load_document"]
