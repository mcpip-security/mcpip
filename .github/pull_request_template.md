<!--
Change-management record (SOC 2 CC8.1). Fill every section.
Keep it factual; describe the diff, not intentions. Do NOT paste secrets,
tokens, env values, or internal hostnames.
-->

## What & why

<!-- One paragraph: what this change does and the reason for it. -->

## Invariant impact

<!--
Does this touch any of the security-critical paths? Check what applies and,
for anything checked, state how the invariant is preserved (see .github/CONTRIBUTING.md §3).
-->

- [ ] Identity / JWT / capabilities (`auth/`)
- [ ] Canonicalization / payload lock / Rust parity (`interfaces.py`, `auth/pin_validator.py`, `bridge/fastwalk.py`, `rust/`)
- [ ] WORM ledger / write-before-execute / redaction (`audit/`)
- [ ] Connector registry hash-pin (`bridge/connectors/registry.py`)
- [ ] Boot integrity / licensing / config (`core/`)
- [ ] Secret / credential handling (`services/secret_vault.py`, `forensic_store.py`, `cloud_broker.py`, `authn_channel.py`)
- [ ] None of the above (no security-critical path touched)

## Testing

<!-- Commands run and their result (e.g. `pytest -q`, `mypy --strict`, console build). -->

## Docs

- [ ] Updated `docs/` if operator/compliance-facing behavior changed, or N/A.
