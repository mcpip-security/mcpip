"""
MCPIP V2 — Service: the community-extension manifest schema (``mcpip-extension/1``).

    ◐ "A community skill is declarative data — a new opaque name onto a cloud_rest
       target, nothing more. The manifest is the contract a reviewer signs off on."

Phase 1 of the author-your-own extensibility feature ships COMMUNITY SKILLS only: a
Contributor (any authenticated principal) submits an ``mcpip-extension/1`` manifest that
describes a NEW opaque ``alias → target`` binding; a Reviewer holding
``CAP_CATALOG_REVIEWER`` approves it, and it is minted through the SAME hardened overlay
path an operator ``register_skill`` uses (``services/catalog_overlay.py``). The manifest
is inert, declarative data — it can only ever ADD a new alias onto a ``cloud_rest``
target and inherits every overlay constraint (additive-only, ``cloud_rest``-only,
``restricted``⇒``pin_required``, bounded).

Phase 2 (community GATES, ``kind='gate'``) adds a SECOND strict manifest variant here —
:class:`GateManifest` — validated as pure DATA only: the strict schema shape,
``reject_unsafe_string`` on every human-readable field, an identity-shaped-key hard-deny on
``id``/``author``, the ``referenced_context_fields`` ⊆ fixed ``GATE_CONTEXT_FIELDS``
whitelist rule, ``max_cost`` ≤ ``MAX_GATE_COST``, and the same ``sha256`` self-pin. It does
NOT parse or lint the CEL ``source``: the CEL parse/lint/evaluate RUNTIME (and the static
cost/whitelist PROVER a gate APPROVAL requires) is a DEFERRED owner dependency decision
(``docs/build/EXTENSIBILITY.md §8``) — so a gate can be submitted + schema-validated + stored
PENDING now, but can never be APPROVED until an engine is registered (no
approve-without-proof). The two kinds are routed by :func:`manifest_kind` and never share a
code path: a skill manifest still parses through :func:`parse_manifest` (``kind='skill'``
ONLY — a gate manifest is refused there), a gate through :func:`parse_gate_manifest`.

Validation layers (all fail-closed; a rejection surfaces to the agent/reviewer only as
an opaque ``MCPIPDenied`` + ``correlation_id`` — never a concrete reason):
  * strict Pydantic (``extra='forbid'``, exact ``schema``/``kind``/``transport`` literals);
  * every human field (``id``/``author``/``alias``/``target``) run through
    ``interfaces.reject_unsafe_string`` (NFC + control/bidi/zero-width reject) — the same
    MCP-tool-description-poisoning countermeasure the ingress path uses;
  * an identity-shaped-key HARD DENY: ``id``/``author``/``alias`` are folded with the
    bridge's ``_identity_fold`` (NFKC + ``Cf``-strip + casefold) and rejected if they
    land in ``_FORBIDDEN_IDENTITY_KEYS`` (so ``alias='role'`` / ``author='tenant_id'`` /
    homoglyph or bidi variants all trip), mirroring the argument identity-injection guard;
  * a ``sha256`` SELF-PIN: the manifest carries its own digest over the canonical
    manifest bytes (``core.integrity.canonical_manifest_bytes`` — sort_keys/compact,
    dropping ``sha256``+``signature``), verified self-consistent at parse. That pinned
    digest is the rug-pull defense: it is re-verified at approve and on every boot-load,
    so any post-approval edit changes the digest and the entry is refused.

The AUTHORITATIVE per-skill validity rule (``alias`` charset, risk/classification enum
membership, target length/newline, ``restricted``⇒``pin_required``) stays the SINGLE
source of truth ``app.main._overlay_skill_invalid`` — the shared predicate ``register_skill``
already enforces — and is re-run by the submit and approve handlers over the parsed
manifest. This module does NOT import it (that predicate lives in the edge app; importing
it here would be a cycle), so the schema restates only the coarse enum SHAPE as strict
Literals and lets ``_overlay_skill_invalid`` remain the one authority for the cross-field
rules. The digest discipline is DISTINCT from the payload-lock ``canonical_json`` — a
skill is declarative data and no gate/lock hash is ever recomputed from a manifest.
"""

from __future__ import annotations

import json
from typing import Any, Final, Literal, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from core.integrity import canonical_manifest_bytes
from interfaces import (
    GATE_CONTEXT_FIELDS,
    MAX_GATE_COST,
    MAX_PUBLISHER_NAMESPACE_LEN,
    MAX_REGISTRY_META_BYTES,
    MAX_REGISTRY_REMOTES,
    MAX_STRING_LEN,
    constant_time_equals,
    reject_unsafe_string,
    sha256_hex,
)

# The one schema tag every submitted/stored manifest must carry (mirrors the policy
# store's ``mcpip-policy/1`` and the directory store's ``mcpip-directory/1`` discipline).
# A bump means a breaking manifest-shape change.
EXTENSION_SCHEMA: Final[str] = "mcpip-extension/1"

# Human free-text fields folded + identity-checked. ``target`` is validated for charset
# safety too but is a system identifier (a cloud_rest URL/endpoint), not identity-shaped,
# so it is NOT run through the identity fold — only ``id``/``author``/``alias`` are.
_HUMAN_FIELDS: Final[tuple[str, ...]] = ("id", "author", "alias", "target")
_IDENTITY_CHECKED_FIELDS: Final[tuple[str, ...]] = ("id", "author", "alias")


class ExtensionManifestError(ValueError):
    """The submitted manifest is malformed, unsafe, or fails its own sha256 self-pin.

    Carries NO detail across the agent/reviewer wire — the caller maps it to an opaque
    ``MCPIPDenied`` + ``correlation_id`` and records the concrete cause in WORM only.
    """


class ExtensionManifest(BaseModel):
    """A strict ``mcpip-extension/1`` community-SKILL manifest (Phase 1).

    Every field is required and closed (``extra='forbid'``). ``schema``/``kind``/
    ``transport`` are exact literals; ``risk_tier``/``classification`` restate the
    overlay enum SHAPE (the authoritative cross-field rule stays ``_overlay_skill_invalid``).
    The ``sha256`` self-pin is verified self-consistent at construction.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # The schema tag + extension kind. Phase 1 is skills ONLY — ``kind='gate'`` is
    # refused here (community gates are Phase 2, gated on the deferred CEL runtime).
    schema_: Literal["mcpip-extension/1"] = Field(alias="schema")
    kind: Literal["skill"]

    # Operator-facing metadata labels ONLY — never trusted for authorization or
    # de-duplication (the authoritative keys are the server-minted submission_id and the
    # alias; the actor recorded to WORM is the submitter's JWT agent_id).
    id: str = Field(min_length=1)
    author: str = Field(min_length=1)

    # The manifest's self-digest (rug-pull pin) over ``canonical_manifest_bytes`` — see
    # the module docstring. Verified self-consistent below and re-verified at approve/load.
    sha256: str = Field(min_length=64, max_length=64)

    # The skill itself: a NEW opaque alias onto a cloud_rest target. Transport is pinned
    # to the literal ``cloud_rest`` — the community path can never reach a privileged
    # transport (legacy_mainframe / grant_issue / cloud_iam), exactly like the overlay.
    alias: str = Field(min_length=1)
    target: str = Field(min_length=1)
    transport: Literal["cloud_rest"]
    risk_tier: Literal["auto", "pin_required"]
    classification: Literal["unclassified", "restricted"]

    @field_validator("id", "author", "alias", "target")
    @classmethod
    def _charset_safe(cls, value: str) -> str:
        """NFC-normalize + reject control/bidi/zero-width in every human field."""
        try:
            return reject_unsafe_string(value, "manifest")
        except ValueError as exc:
            raise ValueError("unsafe character in manifest field") from exc

    @field_validator("id", "author", "alias")
    @classmethod
    def _not_identity_shaped(cls, value: str) -> str:
        """Hard-deny an identity/capability-shaped label (``role``/``tenant_id``/…).

        Folded with the bridge's ``_identity_fold`` (NFKC + ``Cf``-strip + casefold) so a
        homoglyph or bidi variant trips too — the same membership test the argument
        identity-injection guard uses. Imported lazily to avoid a package-load cycle.
        """
        from bridge.intent_parser import _FORBIDDEN_IDENTITY_KEYS, _identity_fold

        if _identity_fold(value) in _FORBIDDEN_IDENTITY_KEYS:
            raise ValueError("identity-shaped value in manifest field")
        return value

    @field_validator("sha256")
    @classmethod
    def _lower_hex(cls, value: str) -> str:
        """A digest is lowercase hex — reject anything else before the self-pin check."""
        lowered = value.lower()
        if any(ch not in "0123456789abcdef" for ch in lowered):
            raise ValueError("sha256 is not lowercase hex")
        return lowered

    def _digest_source(self) -> dict[str, Any]:
        """The substantive manifest mapping the ``sha256`` digest is taken over.

        Uses the wire aliases (``schema`` not ``schema_``) so the digest is over the
        exact JSON a Contributor authored; ``canonical_manifest_bytes`` drops ``sha256``
        and the reserved ``signature`` itself.
        """
        return self.model_dump(by_alias=True)

    def computed_sha256(self) -> str:
        """Recompute the manifest self-digest over the canonical manifest bytes."""
        return sha256_hex(canonical_manifest_bytes(self._digest_source()))

    def canonical_dict(self) -> dict[str, Any]:
        """The full manifest (with its verified ``sha256``) for persistence, by alias."""
        return self.model_dump(by_alias=True)


def parse_manifest(raw: Any) -> ExtensionManifest:
    """
    Parse + validate one submitted manifest, fail-closed.

    Runs the strict Pydantic model (schema/kind/transport literals, ``extra='forbid'``,
    charset + identity-shape guards) THEN verifies the ``sha256`` SELF-PIN: the declared
    digest must equal the digest recomputed over the canonical manifest bytes, compared
    constant-time. A manifest whose declared ``sha256`` does not match its own content is
    refused here — so the pinned value that flows to the store is always self-consistent,
    and any later edit (to the manifest OR its overlay fields) is caught at approve/load.

    Raises ``ExtensionManifestError`` on any failure — the caller maps it to an opaque
    deny and records the concrete cause in WORM only.
    """
    if not isinstance(raw, dict):
        raise ExtensionManifestError("manifest is not a JSON object")
    try:
        manifest = ExtensionManifest.model_validate(raw)
    except ValidationError as exc:
        raise ExtensionManifestError("manifest failed schema validation") from exc
    if not constant_time_equals(manifest.sha256, manifest.computed_sha256()):
        raise ExtensionManifestError("manifest sha256 self-pin mismatch")
    return manifest


def verify_manifest_pin(canonical: dict[str, Any]) -> Optional[ExtensionManifest]:
    """
    Re-verify a STORED canonical manifest at boot-load (rug-pull defense).

    Re-parses the stored mapping through ``parse_manifest`` — which re-runs every schema/
    charset/identity guard AND the ``sha256`` self-pin — and returns the manifest iff it
    still validates. Returns ``None`` on ANY failure so the hydrator can SKIP a tampered
    entry (load refused → re-review required), never raising into boot. Because the digest
    is taken over the manifest content, any post-approval edit to the stored manifest
    changes the recomputed digest and this returns ``None``.
    """
    try:
        return parse_manifest(canonical)
    except ExtensionManifestError:
        return None


class GateManifest(BaseModel):
    """A strict ``mcpip-extension/1`` community-GATE manifest (Phase 2).

    A gate is a DENY-ONLY declarative CEL predicate evaluated at pipeline step 4c′ — NOT a
    skill, NOT an alias→target binding, and it can never reach a transport. This model
    validates it as pure DATA only: the strict schema/kind/language literals
    (``extra='forbid'``), ``reject_unsafe_string`` on every human-readable field
    (``id``/``author``/``source``), an identity-shaped-key hard-deny on ``id``/``author``,
    the ``referenced_context_fields`` ⊆ fixed ``GATE_CONTEXT_FIELDS`` whitelist rule,
    ``max_cost`` ≤ ``MAX_GATE_COST``, and the same ``sha256`` self-pin discipline as the
    skill manifest. It deliberately does NOT parse/lint the CEL ``source`` — that, and the
    static cost/whitelist PROVER a gate APPROVAL requires, needs the DEFERRED CEL runtime
    (``docs/build/EXTENSIBILITY.md §8``). So a gate manifest can be submitted + schema-validated +
    stored, but can never be approved/enforced until an engine is registered.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    # Schema tag + kind. This variant is ``kind='gate'`` ONLY — a skill manifest is refused
    # here (it routes through ``ExtensionManifest``/``parse_manifest`` instead).
    schema_: Literal["mcpip-extension/1"] = Field(alias="schema")
    kind: Literal["gate"]

    # Operator/reviewer-facing metadata labels ONLY — never trusted for authorization; the
    # actor recorded to WORM is the submitter's JWT ``agent_id``, not the ``author`` label.
    id: str = Field(min_length=1)
    author: str = Field(min_length=1)

    # The manifest's self-digest (rug-pull pin) over ``canonical_manifest_bytes`` — verified
    # self-consistent at parse and re-verified whenever the stored manifest is re-parsed.
    sha256: str = Field(min_length=64, max_length=64)

    # The declarative gate. ``language`` is pinned to the literal ``cel`` — the ONLY
    # substrate the design adopts (arbitrary code — WASM/Python — is rejected by
    # construction). ``source`` is the CEL predicate text (validated for charset safety
    # here, NOT parsed — the CEL runtime is deferred). ``referenced_context_fields`` MUST be
    # a subset of the fixed ``GATE_CONTEXT_FIELDS`` whitelist, so a gate can never name a
    # non-whitelisted (e.g. target/secret) field. ``max_cost`` is the declared STATIC CEL
    # cost the (deferred) prover must confirm, bounded by ``MAX_GATE_COST``.
    language: Literal["cel"]
    source: str = Field(min_length=1, max_length=MAX_STRING_LEN)
    referenced_context_fields: list[str] = Field(
        default_factory=list, max_length=len(GATE_CONTEXT_FIELDS)
    )
    max_cost: int = Field(ge=1, le=MAX_GATE_COST)

    @field_validator("id", "author", "source")
    @classmethod
    def _charset_safe(cls, value: str) -> str:
        """NFC-normalize + reject control/bidi/zero-width in every human-readable field.

        Applied to ``source`` too: the CEL text is a reviewer-read field and a prime
        MCP-poisoning vector (a bidi/zero-width trick could make a reviewer misread the
        predicate), so it is charset-scrubbed like any other human field. (This also keeps
        ``source`` single-line/control-free — CEL predicates are single expressions.)
        """
        try:
            return reject_unsafe_string(value, "gate_manifest")
        except ValueError as exc:
            raise ValueError("unsafe character in gate manifest field") from exc

    @field_validator("id", "author")
    @classmethod
    def _not_identity_shaped(cls, value: str) -> str:
        """Hard-deny an identity/capability-shaped label (``role``/``tenant_id``/…).

        Folded with the bridge's ``_identity_fold`` so a homoglyph/bidi variant trips too —
        the same membership test the argument identity-injection guard uses. ``source`` is
        NOT identity-folded: it is a whole CEL expression, not a single identity label, and
        the field references it may name are already constrained to the non-identity
        ``GATE_CONTEXT_FIELDS`` whitelist by ``referenced_context_fields``.
        """
        from bridge.intent_parser import _FORBIDDEN_IDENTITY_KEYS, _identity_fold

        if _identity_fold(value) in _FORBIDDEN_IDENTITY_KEYS:
            raise ValueError("identity-shaped value in gate manifest field")
        return value

    @field_validator("referenced_context_fields")
    @classmethod
    def _fields_whitelisted(cls, value: list[str]) -> list[str]:
        """Every referenced field MUST be in the fixed whitelist, with no duplicates.

        This is the DATA half of the "whitelisted read-only context" guarantee: the
        manifest may only DECLARE fields drawn from ``GATE_CONTEXT_FIELDS`` (alias,
        risk_tier, transport_class, classification) — never ``target``, a secret, or
        topology. The deferred CEL runtime enforces the matching guarantee over the AST at
        approval (a gate whose source references a non-declared/non-whitelisted field is
        refused there); here we bound what the manifest is permitted to claim.
        """
        seen: set[str] = set()
        for field in value:
            if field not in GATE_CONTEXT_FIELDS:
                raise ValueError(
                    "referenced_context_fields must be a subset of the gate whitelist"
                )
            if field in seen:
                raise ValueError("duplicate referenced context field")
            seen.add(field)
        return value

    @field_validator("sha256")
    @classmethod
    def _lower_hex(cls, value: str) -> str:
        """A digest is lowercase hex — reject anything else before the self-pin check."""
        lowered = value.lower()
        if any(ch not in "0123456789abcdef" for ch in lowered):
            raise ValueError("sha256 is not lowercase hex")
        return lowered

    def _digest_source(self) -> dict[str, Any]:
        """The substantive manifest mapping the ``sha256`` digest is taken over.

        Uses the wire aliases (``schema`` not ``schema_``); ``canonical_manifest_bytes``
        drops ``sha256`` and the reserved ``signature`` itself.
        """
        return self.model_dump(by_alias=True)

    def computed_sha256(self) -> str:
        """Recompute the manifest self-digest over the canonical manifest bytes."""
        return sha256_hex(canonical_manifest_bytes(self._digest_source()))

    def canonical_dict(self) -> dict[str, Any]:
        """The full manifest (with its verified ``sha256``) for persistence, by alias."""
        return self.model_dump(by_alias=True)


def parse_gate_manifest(raw: Any) -> GateManifest:
    """
    Parse + validate one submitted GATE manifest, fail-closed.

    Runs the strict :class:`GateManifest` model (schema/kind/language literals,
    ``extra='forbid'``, charset + identity-shape guards, whitelist-subset + ``max_cost``
    bound) THEN verifies the ``sha256`` SELF-PIN constant-time — identical discipline to
    :func:`parse_manifest` for skills. It performs NO CEL parse/lint (the runtime is
    deferred), so importing/calling it never requires ``celpy``.

    Raises :class:`ExtensionManifestError` on any failure — the caller maps it to an opaque
    deny and records the concrete cause in WORM only.
    """
    if not isinstance(raw, dict):
        raise ExtensionManifestError("gate manifest is not a JSON object")
    try:
        manifest = GateManifest.model_validate(raw)
    except ValidationError as exc:
        raise ExtensionManifestError("gate manifest failed schema validation") from exc
    if not constant_time_equals(manifest.sha256, manifest.computed_sha256()):
        raise ExtensionManifestError("gate manifest sha256 self-pin mismatch")
    return manifest


def manifest_kind(raw: Any) -> Optional[str]:
    """
    Peek at a manifest's declared ``kind`` for routing — WITHOUT trusting it.

    Returns the ``kind`` string if ``raw`` is a mapping carrying a string ``kind``, else
    None. This is ONLY a router hint: each kind's handler then fully validates the manifest
    fail-closed (``parse_manifest`` for skills, ``parse_gate_manifest`` for gates), so a
    spoofed/absent/misspelled ``kind`` can never smuggle an unvalidated manifest through —
    it merely selects which strict validator refuses it.
    """
    if isinstance(raw, dict):
        kind = raw.get("kind")
        if isinstance(kind, str):
            return kind
    return None


# ===========================================================================
# Phase 3a — registry-sourced skill governance (X3).
#
# A skill sourced from an MCP-Registry ``server.json`` is governed as a FIRST-CLASS
# community extension by PROJECTING it into the already-hardened Phase-1 overlay path —
# never a parallel mint path. A registry submission is an ``mcpip-extension/1`` manifest
# with ``kind='registry_server'`` that carries the MCPIP-side opaque ``alias`` + reviewer/
# submitter-declared ``risk_tier``/``classification`` + a ``sha256`` self-pin, and EMBEDS
# the pasted server.json under ``server``. The manifest exposes ``.alias/.target/
# .transport(='cloud_rest')/.risk_tier/.classification`` accessors so it drops into the
# SAME ``_overlay_skill_invalid`` + ``_apply_overlay_skill`` (HSETNX additive-only) +
# ``_community_pin_valid`` machinery the community-skill flow uses, UNCHANGED.
#
# It is a pure SEAM against the registry v0.1 freeze: the submitter/reviewer PASTE the
# server.json in — MCPIP never network-fetches a live registry on any path. The cloud_rest
# TARGET is derived from the single required ``remotes[]`` entry whose type is a remote
# HTTP transport (``sse``/``streamable-http``) and whose ``url`` is https; a server.json
# with ONLY local ``packages`` (npm/pypi/docker/stdio) and no remote is REFUSED (a local/
# stdio MCP server can never become a governed cloud_rest alias — consistent with the
# connector-purity / no-subprocess posture). The server.json's own ``_meta`` provenance is
# RECORDED to WORM for audit but NEVER trusted for authorization (the official registry is
# preview/unsigned) — the verified-publisher decision rides the reviewer-pinned allow-list
# only (see ``services/registry_publishers.py``).
# ===========================================================================

# Remote-HTTP transport types in an MCP-Registry server.json ``remotes[]`` entry. ONLY
# these two (each over https) can back a governed cloud_rest alias — a local/stdio package
# entry never yields a remote target.
_REMOTE_HTTP_TYPES: Final[tuple[str, ...]] = ("sse", "streamable-http")


def publisher_namespace(name: str) -> str:
    """Return the publisher NAMESPACE (reverse-DNS prefix) of a server.json ``name``.

    An MCP-Registry name is ``namespace/name`` (e.g. ``io.github.owner/my-server``); the
    namespace is everything before the FIRST ``/``. A name without a ``/`` has no namespace
    and returns the whole string (the strict model refuses such a name upstream, so callers
    that reach an approve/boot path always see a real reverse-DNS namespace here).
    """
    return name.split("/", 1)[0]


class RegistryRemote(BaseModel):
    """One ``remotes[]`` entry of an embedded server.json (a transport endpoint).

    Tolerant of the real registry shape (``extra='allow'`` — a live entry may carry
    ``headers``/auth hints we neither trust nor surface, preserved only so the manifest
    ``sha256`` self-pin covers the whole pasted document). ``type``/``url`` are the two
    fields the target derivation reads; both are charset-scrubbed (so ``url`` cannot carry
    a control/bidi/newline character into a reviewer-read or WORM-recorded field).
    """

    model_config = ConfigDict(extra="allow", frozen=True)

    type: str = Field(min_length=1)
    url: str = Field(min_length=1)

    @field_validator("type", "url")
    @classmethod
    def _charset_safe(cls, value: str) -> str:
        try:
            return reject_unsafe_string(value, "registry_remote")
        except ValueError as exc:
            raise ValueError("unsafe character in registry remote field") from exc

    def is_remote_https(self) -> bool:
        """True iff this is a remote-HTTP transport (sse/streamable-http) over https."""
        return self.type in _REMOTE_HTTP_TYPES and self.url.lower().startswith("https://")


class RegistryServerJson(BaseModel):
    """A pasted MCP-Registry ``server.json`` embedded in a registry-server manifest.

    Tolerant of the real (preview) registry shape (``extra='allow'`` — it may carry
    ``status``/``packages``/``repository``/``$schema``/… which we neither validate nor
    trust, preserved only so the ``sha256`` self-pin covers the whole pasted document), but
    STRICT on the fields governance reads: ``name`` (reverse-DNS ``namespace/name``),
    ``description``, ``version``, an optional ``_meta`` provenance mapping, and a bounded
    ``remotes[]`` list. Every human field is ``reject_unsafe_string``-scrubbed; the server
    ``name`` AND its parsed publisher namespace are ``_identity_fold`` hard-denied (so a
    ``role``/``tenant_id`` homoglyph/bidi namespace trips). The single required remote-HTTP
    https entry is enforced at validation — a local/stdio-only doc is REFUSED here.
    """

    model_config = ConfigDict(extra="allow", frozen=True, populate_by_name=True)

    name: str = Field(min_length=1)
    description: str = Field(min_length=1)
    version: str = Field(min_length=1)
    # ``_meta`` is the registry's provenance envelope — RECORDED to WORM, NEVER trusted for
    # authorization. Aliased because a leading-underscore attribute name is reserved in
    # pydantic. Optional (a hand-pasted doc may omit it) and left as an opaque mapping.
    meta_: Optional[dict[str, Any]] = Field(default=None, alias="_meta")
    remotes: list[RegistryRemote] = Field(
        default_factory=list, max_length=MAX_REGISTRY_REMOTES
    )

    @field_validator("name", "description", "version")
    @classmethod
    def _charset_safe(cls, value: str) -> str:
        try:
            return reject_unsafe_string(value, "registry_server")
        except ValueError as exc:
            raise ValueError("unsafe character in server.json field") from exc

    @field_validator("meta_")
    @classmethod
    def _scrub_meta(cls, value: Optional[dict[str, Any]]) -> Optional[dict[str, Any]]:
        """Charset-scrub + size-bound the ``_meta`` provenance envelope.

        ``_meta`` is recorded to WORM and shown to the reviewer but never trusted for
        authorization; without this it was the ONE human-readable surface that escaped the
        ``reject_unsafe_string`` + size discipline every other manifest field pays, so an
        untrusted registry document could smuggle bidi/format marks or an unbounded blob into
        the audit log. Bound the whole envelope by serialized bytes (which also bounds nesting
        depth, keeping the recursion safe) and reject any unsafe string key or value.
        """
        if value is None:
            return None
        try:
            size = len(json.dumps(value, ensure_ascii=False).encode("utf-8"))
        except (TypeError, ValueError) as exc:
            raise ValueError("server.json _meta is not JSON-serializable") from exc
        if size > MAX_REGISTRY_META_BYTES:
            raise ValueError("server.json _meta exceeds the size ceiling")

        def _scrub(node: Any) -> None:
            if isinstance(node, str):
                reject_unsafe_string(node, "registry_meta")
            elif isinstance(node, dict):
                for key, sub in node.items():
                    if isinstance(key, str):
                        reject_unsafe_string(key, "registry_meta_key")
                    _scrub(sub)
            elif isinstance(node, (list, tuple)):
                for sub in node:
                    _scrub(sub)

        try:
            _scrub(value)
        except ValueError as exc:
            raise ValueError("unsafe character in server.json _meta") from exc
        return value

    @model_validator(mode="after")
    def _validate_shape(self) -> "RegistryServerJson":
        """Enforce the reverse-DNS namespace, identity-fold hard-deny, and single remote."""
        from bridge.intent_parser import _FORBIDDEN_IDENTITY_KEYS, _identity_fold

        if "/" not in self.name:
            raise ValueError("server name must be reverse-DNS 'namespace/name'")
        namespace = self.name.split("/", 1)[0]
        name_part = self.name.split("/", 1)[1]
        if not namespace or not name_part:
            raise ValueError("server name namespace and name must be non-empty")
        if len(namespace) > MAX_PUBLISHER_NAMESPACE_LEN:
            raise ValueError("publisher namespace exceeds the length cap")
        # Identity-fold hard-deny on the whole name, its namespace, and its name part — so
        # a ``role``/``tenant_id`` (or a homoglyph/bidi variant) namespace/name is refused,
        # mirroring the argument identity-injection guard.
        for candidate in (self.name, namespace, name_part):
            if _identity_fold(candidate) in _FORBIDDEN_IDENTITY_KEYS:
                raise ValueError("identity-shaped value in server name")
        # Exactly one remote-HTTP https entry — this both refuses a local/stdio-only doc
        # (no remote target) and keeps the derived target unambiguous.
        self._require_single_remote_target()
        return self

    def _remote_targets(self) -> list[str]:
        return [r.url for r in self.remotes if r.is_remote_https()]

    def _require_single_remote_target(self) -> str:
        targets = self._remote_targets()
        if len(targets) != 1:
            raise ValueError(
                "server.json must carry exactly one remote-HTTP https transport"
            )
        return targets[0]

    def remote_target(self) -> str:
        """The single qualifying remote-HTTP https URL (the derived cloud_rest target)."""
        return self._require_single_remote_target()

    def namespace(self) -> str:
        """The publisher namespace (reverse-DNS prefix of ``name``)."""
        return publisher_namespace(self.name)


class RegistryServerManifest(BaseModel):
    """A strict ``mcpip-extension/1`` registry-server manifest (``kind='registry_server'``).

    Wraps the MCPIP-side opaque ``alias`` + reviewer/submitter-declared ``risk_tier``/
    ``classification`` + a ``sha256`` self-pin over an EMBEDDED :class:`RegistryServerJson`.
    ``transport`` is NOT a field — the projection hardcodes ``cloud_rest`` (so a privileged
    transport is structurally unreachable, exactly like the skill overlay); ``target`` is
    NOT a field — it is DERIVED from the embedded server's single remote-HTTP https entry.
    The ``.alias/.target/.transport/.risk_tier/.classification`` accessors let this model
    drop into ``_overlay_skill_invalid`` / ``_apply_overlay_skill`` / ``_community_pin_valid``
    UNCHANGED. Identity-shaped ``id``/``author``/``alias`` (and the server name/namespace,
    checked in the embedded model) are hard-denied.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_: Literal["mcpip-extension/1"] = Field(alias="schema")
    kind: Literal["registry_server"]

    # Operator/reviewer-facing metadata labels ONLY — never trusted for authorization; the
    # actor recorded to WORM is the submitter's JWT ``agent_id``, not the ``author`` label.
    id: str = Field(min_length=1)
    author: str = Field(min_length=1)

    # The manifest self-digest (rug-pull pin) over ``canonical_manifest_bytes`` — verified
    # self-consistent at parse and re-verified at approve + on every boot-load.
    sha256: str = Field(min_length=64, max_length=64)

    # The MCPIP-side opaque alias the governed skill mints as (never the server name).
    alias: str = Field(min_length=1)
    risk_tier: Literal["auto", "pin_required"]
    classification: Literal["unclassified", "restricted"]

    # The pasted MCP-Registry server.json (validated + provenance-bearing, target-derived).
    server: RegistryServerJson

    @field_validator("id", "author", "alias")
    @classmethod
    def _charset_safe(cls, value: str) -> str:
        try:
            return reject_unsafe_string(value, "registry_manifest")
        except ValueError as exc:
            raise ValueError("unsafe character in registry manifest field") from exc

    @field_validator("id", "author", "alias")
    @classmethod
    def _not_identity_shaped(cls, value: str) -> str:
        from bridge.intent_parser import _FORBIDDEN_IDENTITY_KEYS, _identity_fold

        if _identity_fold(value) in _FORBIDDEN_IDENTITY_KEYS:
            raise ValueError("identity-shaped value in registry manifest field")
        return value

    @field_validator("sha256")
    @classmethod
    def _lower_hex(cls, value: str) -> str:
        lowered = value.lower()
        if any(ch not in "0123456789abcdef" for ch in lowered):
            raise ValueError("sha256 is not lowercase hex")
        return lowered

    # -- Projected overlay accessors (identical shape to a skill manifest). --------------

    @property
    def target(self) -> str:
        """The derived cloud_rest target — the embedded server's single remote https URL."""
        return self.server.remote_target()

    @property
    def transport(self) -> str:
        """Always ``cloud_rest`` — the projection never emits a transport field, so a
        privileged transport (legacy_mainframe/grant_issue/cloud_iam) is unreachable."""
        return "cloud_rest"

    @property
    def publisher(self) -> str:
        """The publisher namespace parsed from the embedded server name (allow-list key)."""
        return self.server.namespace()

    def provenance(self) -> Optional[dict[str, Any]]:
        """The server.json ``_meta`` provenance — recorded to WORM, NEVER trusted for authz."""
        return self.server.meta_

    def _digest_source(self) -> dict[str, Any]:
        return self.model_dump(by_alias=True)

    def computed_sha256(self) -> str:
        """Recompute the manifest self-digest over the canonical manifest bytes."""
        return sha256_hex(canonical_manifest_bytes(self._digest_source()))

    def canonical_dict(self) -> dict[str, Any]:
        """The full manifest (with its verified ``sha256``) for persistence, by alias."""
        return self.model_dump(by_alias=True)


def parse_registry_manifest(raw: Any) -> RegistryServerManifest:
    """
    Parse + validate one submitted registry-server manifest, fail-closed.

    Runs the strict :class:`RegistryServerManifest` model (schema/kind literals,
    ``extra='forbid'``, charset + identity-shape guards, the embedded server.json's
    reverse-DNS/single-remote/identity rules) THEN verifies the ``sha256`` SELF-PIN
    constant-time — identical discipline to :func:`parse_manifest`. It performs NO network
    fetch and imports no CEL runtime.

    Raises :class:`ExtensionManifestError` on any failure — the caller maps it to an opaque
    deny and records the concrete cause in WORM only.
    """
    if not isinstance(raw, dict):
        raise ExtensionManifestError("registry manifest is not a JSON object")
    try:
        manifest = RegistryServerManifest.model_validate(raw)
    except ValidationError as exc:
        raise ExtensionManifestError("registry manifest failed schema validation") from exc
    if not constant_time_equals(manifest.sha256, manifest.computed_sha256()):
        raise ExtensionManifestError("registry manifest sha256 self-pin mismatch")
    return manifest


def verify_registry_manifest_pin(
    canonical: dict[str, Any],
) -> Optional[RegistryServerManifest]:
    """
    Re-verify a STORED registry-server manifest at boot-load (rug-pull defense).

    Re-parses the stored mapping through :func:`parse_registry_manifest` — re-running every
    schema/charset/identity guard, the embedded-server rules, AND the ``sha256`` self-pin —
    and returns the manifest iff it still validates, else ``None`` so the hydrator SKIPS a
    tampered entry (load refused → re-review required), never raising into boot.
    """
    try:
        return parse_registry_manifest(canonical)
    except ExtensionManifestError:
        return None


__all__ = [
    "EXTENSION_SCHEMA",
    "ExtensionManifest",
    "ExtensionManifestError",
    "GateManifest",
    "RegistryRemote",
    "RegistryServerJson",
    "RegistryServerManifest",
    "parse_manifest",
    "parse_gate_manifest",
    "parse_registry_manifest",
    "manifest_kind",
    "verify_manifest_pin",
    "verify_registry_manifest_pin",
    "publisher_namespace",
]
