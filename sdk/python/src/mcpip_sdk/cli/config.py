"""
mcpip_sdk.cli.config — kubeconfig-shaped contexts + hardened on-disk state.

The config file (``~/.mcpip/config.toml`` by default) holds a ``current-context``
plus named ``[context.NAME]`` tables. Each context carries a ``base_url``, a
``sandbox`` bool, and a TOKEN-SOURCE REFERENCE (``env:VARNAME`` | ``file:PATH`` |
``cmd:'...'``) — deliberately NOT a literal JWT. Storing a bearer inline would
leak it into a file the CLI cannot guarantee stays private; a literal token only
ever enters through a token-source FILE the CLI itself writes 0600.

Security posture (fail-closed, never best-effort):

* Every secret-bearing file (the config, and any token store the CLI writes) is
  created ``O_EXCL`` with mode ``0600``. On every read the CLI stats the file and
  REFUSES (``CLIConfigError`` → exit 8) if it is group- or world-readable/writable.
* Writes are atomic: a temp file is created ``O_EXCL 0600`` in the SAME directory,
  written, fsync'd, then ``os.replace``-d over the target (never a partial file,
  never a window at a wider mode).
* A referenced token FILE must itself be 0600 or the read fails closed.
"""

from __future__ import annotations

import os
import stat
import sys
from dataclasses import dataclass, field, replace
from typing import Any, Final

# ``tomllib`` is stdlib only from 3.11 (PEP 680). The distribution floor is 3.10
# (pyproject ``requires-python = ">=3.10"``), so on 3.10 fall back to the ``tomli``
# backport (a conditional dependency, pinned to ``python_version < '3.11'``). Both
# expose the identical ``load`` / ``TOMLDecodeError`` surface used below.
if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - exercised only on the 3.10 floor
    import tomli as tomllib

from mcpip_sdk.cli.errors import CLIConfigError

_DEFAULT_BASE_URL: Final[str] = "http://localhost:8080"
_TOKEN_SOURCE_SCHEMES: Final[tuple[str, ...]] = ("env:", "file:", "cmd:")


# ---------------------------------------------------------------------------
# Path resolution.
# ---------------------------------------------------------------------------


def config_home() -> str:
    """The directory holding CLI state (``MCPIP_CONFIG_HOME`` or ``~/.mcpip``)."""
    override = os.environ.get("MCPIP_CONFIG_HOME")
    if override:
        return os.path.abspath(os.path.expanduser(override))
    return os.path.abspath(os.path.expanduser(os.path.join("~", ".mcpip")))


def config_path() -> str:
    """The config file path. ``MCPIP_CONFIG`` names an EXACT file; otherwise it
    is ``config.toml`` under :func:`config_home`."""
    override = os.environ.get("MCPIP_CONFIG")
    if override:
        return os.path.abspath(os.path.expanduser(override))
    return os.path.join(config_home(), "config.toml")


def staged_dir() -> str:
    """Per-user directory holding 0600 staged step-up envelopes."""
    return os.path.join(config_home(), "staged")


def default_token_path(context_name: str) -> str:
    """Default 0600 token-store path for a context's minted dev token."""
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in context_name)
    return os.path.join(config_home(), "tokens", f"{safe or 'default'}.jwt")


# ---------------------------------------------------------------------------
# Hardened file primitives.
# ---------------------------------------------------------------------------


def _refuse_if_accessible(path: str) -> None:
    """Fail closed if ``path`` is group- or world-accessible in any way."""
    try:
        mode = os.stat(path).st_mode
    except OSError as exc:
        raise CLIConfigError(f"cannot stat {path!r}: {exc.strerror}") from exc
    if mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise CLIConfigError(
            f"refusing to use {path!r}: it is group/world-accessible "
            f"(mode {stat.S_IMODE(mode):04o}); run `chmod 600 {path}`"
        )


def read_secret_file(path: str) -> str:
    """Read a 0600-guarded secret file (a token store), failing closed on lax
    permissions. Returns the stripped contents."""
    _refuse_if_accessible(path)
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return handle.read().strip()
    except OSError as exc:
        raise CLIConfigError(f"cannot read {path!r}: {exc.strerror}") from exc


def _ensure_dir(path: str) -> None:
    directory = os.path.dirname(path) or "."
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
    except OSError as exc:
        raise CLIConfigError(
            f"cannot create directory {directory!r}: {exc.strerror}"
        ) from exc


def write_secret_file(path: str, content: str, *, exclusive: bool) -> None:
    """
    Write ``content`` to ``path`` at mode 0600.

    ``exclusive=True`` refuses to overwrite an existing file (``O_EXCL`` — for
    ``--out`` targets the user must not clobber). ``exclusive=False`` performs an
    ATOMIC replace: a temp file is created ``O_EXCL 0600`` in the same directory,
    written, fsync'd, then ``os.replace``-d over the target — so a rotating token
    store is never briefly world-readable and never left partially written.
    """
    _ensure_dir(path)
    if exclusive:
        _atomic_create(path, content)
        return
    tmp = f"{path}.tmp.{os.getpid()}"
    try:
        _atomic_create(tmp, content)
        os.replace(tmp, path)
    finally:
        try:
            os.remove(tmp)
        except FileNotFoundError:
            pass


def _atomic_create(path: str, content: str) -> None:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise CLIConfigError(
            f"refusing to overwrite existing file {path!r}"
        ) from exc
    except OSError as exc:
        raise CLIConfigError(f"cannot create {path!r}: {exc.strerror}") from exc
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
    except OSError as exc:
        raise CLIConfigError(f"cannot write {path!r}: {exc.strerror}") from exc


# ---------------------------------------------------------------------------
# Context / Config model.
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Context:
    """One named gateway target — base_url, sandbox flag, token-source REF."""

    name: str
    base_url: str = _DEFAULT_BASE_URL
    sandbox: bool = False
    token_source: str | None = None
    # Stable session identity minted once per context and stamped into every
    # dev token, so the WORM chain attributes this context's calls to ONE
    # session instead of collapsing all local processes into the bare agent_id.
    # A UUID reference, not a secret. None → legacy context, no claim stamped.
    session_id: str | None = None


@dataclass(frozen=True)
class Config:
    """The whole config document: a current-context pointer + named contexts."""

    current_context: str | None = None
    contexts: dict[str, Context] = field(default_factory=dict)

    def context(self, name: str) -> Context:
        try:
            return self.contexts[name]
        except KeyError:
            raise CLIConfigError(f"no such context: {name!r}") from None


def validate_token_source(ref: str) -> str:
    """Reject anything that is not an ``env:`` / ``file:`` / ``cmd:`` reference —
    in particular a literal JWT, which must never be inlined into config."""
    if not any(ref.startswith(scheme) for scheme in _TOKEN_SOURCE_SCHEMES):
        raise CLIConfigError(
            "token-source must be one of env:VARNAME | file:PATH | cmd:'...'; "
            "a literal token is refused here (it would leak into the config file)"
        )
    return ref


def load() -> Config:
    """Load the config, failing closed on lax permissions. A missing file is an
    empty config (a real, valid state — nothing configured yet)."""
    path = config_path()
    if not os.path.exists(path):
        return Config()
    _refuse_if_accessible(path)
    try:
        with open(path, "rb") as handle:
            raw = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise CLIConfigError(f"cannot parse config {path!r}: {exc}") from exc
    return _from_toml(raw)


def _from_toml(raw: dict[str, Any]) -> Config:
    contexts: dict[str, Context] = {}
    context_tables = raw.get("context")
    if isinstance(context_tables, dict):
        for name, table in context_tables.items():
            if not isinstance(table, dict):
                continue
            base_url = table.get("base_url")
            sandbox = table.get("sandbox")
            token_source = table.get("token-source")
            session_id = table.get("session-id")
            contexts[name] = Context(
                name=name,
                base_url=base_url if isinstance(base_url, str) else _DEFAULT_BASE_URL,
                sandbox=bool(sandbox) if isinstance(sandbox, bool) else False,
                token_source=token_source if isinstance(token_source, str) else None,
                session_id=session_id if isinstance(session_id, str) else None,
            )
    current = raw.get("current-context")
    return Config(
        current_context=current if isinstance(current, str) else None,
        contexts=contexts,
    )


def save(config: Config) -> None:
    """Atomically write the config at mode 0600."""
    write_secret_file(config_path(), _to_toml(config), exclusive=False)


def _to_toml(config: Config) -> str:
    """Serialize the constrained config shape (only str/bool values) to TOML.

    The stdlib has no TOML writer; this hand-rolled emitter is safe precisely
    because the schema is closed — a current-context string and per-context
    tables of a URL string, a bool, and a token-source REFERENCE string (never a
    secret value)."""
    lines: list[str] = [
        "# MCPIP CLI config — managed by `mcpip login` / `mcpip context` /",
        "# `mcpip config`. Mode 0600; a token-source is a REFERENCE, never a token.",
    ]
    if config.current_context is not None:
        lines.append(f"current-context = {_toml_str(config.current_context)}")
    for name in sorted(config.contexts):
        ctx = config.contexts[name]
        lines.append("")
        lines.append(f"[context.{_toml_key(name)}]")
        lines.append(f"base_url = {_toml_str(ctx.base_url)}")
        lines.append(f"sandbox = {'true' if ctx.sandbox else 'false'}")
        if ctx.token_source is not None:
            lines.append(f"token-source = {_toml_str(ctx.token_source)}")
        if ctx.session_id is not None:
            lines.append(f"session-id = {_toml_str(ctx.session_id)}")
    return "\n".join(lines) + "\n"


def _toml_str(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _toml_key(name: str) -> str:
    if name and all(c.isalnum() or c in "-_" for c in name):
        return name
    return _toml_str(name)


# ---------------------------------------------------------------------------
# Precedence resolution (flags > env > file > built-in default).
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Resolved:
    """The effective gateway target for one invocation."""

    base_url: str
    sandbox: bool
    context_name: str | None
    token_source: str | None  # the context's token-source ref (fallback only)


def resolve(
    config: Config,
    *,
    gateway: str | None,
    context: str | None,
    sandbox: bool | None,
    strict: bool = True,
) -> Resolved:
    """
    Fold flags, environment, and config into one effective target.

    ``strict`` (the default for gateway commands) makes an explicitly-requested
    context that does not exist a hard error (exit 8). The config-management
    commands pass ``strict=False`` because ``login`` / ``context set`` legitimately
    NAME a context that does not exist yet (they are about to create it).
    """
    ctx_name = (
        context
        or os.environ.get("MCPIP_CONTEXT")
        or config.current_context
    )
    ctx: Context | None = None
    if ctx_name is not None and ctx_name in config.contexts:
        ctx = config.contexts[ctx_name]
    elif strict and ctx_name is not None and (
        context or os.environ.get("MCPIP_CONTEXT")
    ):
        # An explicitly-requested context that does not exist is an error;
        # a stale current-context pointer degrades silently to defaults.
        raise CLIConfigError(f"no such context: {ctx_name!r}")

    base_url = (
        gateway
        or os.environ.get("MCPIP_GATEWAY")
        or (ctx.base_url if ctx is not None else None)
        or _DEFAULT_BASE_URL
    )

    if sandbox is not None:
        effective_sandbox = sandbox
    elif "MCPIP_SANDBOX" in os.environ:
        effective_sandbox = _env_bool(os.environ["MCPIP_SANDBOX"])
    elif ctx is not None:
        effective_sandbox = ctx.sandbox
    else:
        effective_sandbox = False

    return Resolved(
        base_url=base_url,
        sandbox=effective_sandbox,
        context_name=ctx_name,
        token_source=ctx.token_source if ctx is not None else None,
    )


def _env_bool(value: str) -> bool:
    return value.strip().lower() in ("1", "true", "yes", "on")


# ---------------------------------------------------------------------------
# Keyed get/set/unset for `mcpip config`.
# ---------------------------------------------------------------------------


def config_get(config: Config, key: str) -> str | None:
    """Read one dotted config key (``current-context`` or
    ``context.NAME.{base_url,sandbox,token-source}``)."""
    if key == "current-context":
        return config.current_context
    name, attr = _split_context_key(key)
    ctx = config.contexts.get(name)
    if ctx is None:
        return None
    if attr == "base_url":
        return ctx.base_url
    if attr == "sandbox":
        return "true" if ctx.sandbox else "false"
    if attr == "token-source":
        return ctx.token_source
    raise CLIConfigError(f"unknown config key: {key!r}")


def config_set(config: Config, key: str, value: str) -> Config:
    """Set one dotted config key, returning a new Config. Refuses a literal JWT
    in a token-source field."""
    if key == "current-context":
        if value not in config.contexts:
            raise CLIConfigError(f"no such context: {value!r}")
        return replace(config, current_context=value)
    name, attr = _split_context_key(key)
    ctx = config.contexts.get(name) or Context(name=name)
    if attr == "base_url":
        ctx = replace(ctx, base_url=value)
    elif attr == "sandbox":
        ctx = replace(ctx, sandbox=_env_bool(value))
    elif attr == "token-source":
        ctx = replace(ctx, token_source=validate_token_source(value))
    else:
        raise CLIConfigError(f"unknown config key: {key!r}")
    contexts = dict(config.contexts)
    contexts[name] = ctx
    return replace(config, contexts=contexts)


def config_unset(config: Config, key: str) -> Config:
    """Remove one dotted config key, returning a new Config."""
    if key == "current-context":
        return replace(config, current_context=None)
    name, attr = _split_context_key(key)
    ctx = config.contexts.get(name)
    if ctx is None:
        return config
    if attr == "token-source":
        ctx = replace(ctx, token_source=None)
    elif attr == "sandbox":
        ctx = replace(ctx, sandbox=False)
    elif attr == "base_url":
        ctx = replace(ctx, base_url=_DEFAULT_BASE_URL)
    else:
        raise CLIConfigError(f"unknown config key: {key!r}")
    contexts = dict(config.contexts)
    contexts[name] = ctx
    return replace(config, contexts=contexts)


def _split_context_key(key: str) -> tuple[str, str]:
    parts = key.split(".")
    if len(parts) != 3 or parts[0] != "context":
        raise CLIConfigError(
            f"unknown config key: {key!r} "
            "(use current-context or context.NAME.{base_url,sandbox,token-source})"
        )
    return parts[1], parts[2]


def redact(key: str, value: str | None) -> str | None:
    """Redact a secret-bearing config value for display. A token-source is a
    REFERENCE, so it is safe to show; but if a token-source ever named a literal
    (it cannot, we validate on write), it would be masked here as defense in
    depth."""
    if value is None:
        return None
    if key.endswith("token-source") and not any(
        value.startswith(s) for s in _TOKEN_SOURCE_SCHEMES
    ):
        return "<redacted>"
    return value


def stderr_note(message: str) -> None:
    """A non-secret advisory line to stderr (kept off stdout so ``--json`` stays
    machine-parseable)."""
    print(message, file=sys.stderr)


__all__ = [
    "Context",
    "Config",
    "Resolved",
    "config_home",
    "config_path",
    "staged_dir",
    "default_token_path",
    "read_secret_file",
    "write_secret_file",
    "validate_token_source",
    "load",
    "save",
    "resolve",
    "config_get",
    "config_set",
    "config_unset",
    "redact",
    "stderr_note",
]
