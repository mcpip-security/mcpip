"""
MCPIP — the release tag guard, and the workflow that depends on it.

A release workflow is handed exactly one instruction: a tag. Nothing else tells it
what to publish. So the failure that costs the most is the cheapest to make — tag
``sdk-py-v0.2.0`` while the manifest still reads ``0.1.0``, and the workflow
happily republishes ``0.1.0``. PyPI then refuses the real ``0.1.0`` forever,
because a version number is spent the moment it is uploaded.

``scripts/check_release_tag.py`` runs before any build step. These tests pin its
behaviour, and pin the two structural properties of ``release.yml`` that make it
safe: every publishing job waits on the guard, and no job pastes a workflow
expression into a shell script body.
"""

from __future__ import annotations

import importlib.util
import json
import os
import re
import subprocess
import sys

import pytest

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_GUARD = os.path.join(_REPO_ROOT, "scripts", "check_release_tag.py")
_WORKFLOW = os.path.join(_REPO_ROOT, ".github", "workflows", "release.yml")


def _load_guard():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("check_release_tag", _GUARD)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


guard = _load_guard()


def _version(rel: str) -> str:
    path = os.path.join(_REPO_ROOT, rel)
    if rel.endswith(".json"):
        with open(path, encoding="utf-8") as handle:
            return str(json.load(handle)["version"])
    with open(path, encoding="utf-8") as handle:
        text = handle.read()
    if rel.endswith(".toml"):
        match = re.search(r'^\s*version\s*=\s*"([^"]+)"', text, re.MULTILINE)
        assert match is not None
        return match.group(1)
    return text.strip()


# Every tag train this repository cuts, paired with the manifest it must match.
_TRAINS = [
    ("v", "VERSION"),
    ("sdk-py-v", "sdk/python/pyproject.toml"),
    ("sdk-ts-v", "sdk/typescript/package.json"),
    ("desktop-v", "dashboard/package.json"),
]


@pytest.mark.parametrize("prefix,manifest", _TRAINS)
def test_the_tag_that_matches_todays_manifest_passes(prefix: str, manifest: str) -> None:
    """The tag a release engineer would cut right now must be accepted."""
    ok, message = guard.check(f"{prefix}{_version(manifest)}")
    assert ok, message


@pytest.mark.parametrize("prefix,manifest", _TRAINS)
def test_a_tag_ahead_of_its_manifest_is_refused(prefix: str, manifest: str) -> None:
    """The actual accident: tag bumped, manifest forgotten."""
    current = _version(manifest)
    major, minor, patch = (int(part) for part in current.split("-")[0].split(".")[:3])
    ok, message = guard.check(f"{prefix}{major}.{minor}.{patch + 1}")
    assert not ok
    assert manifest in message, "the failure must name the file that needs bumping"


@pytest.mark.parametrize(
    "tag",
    [
        "v3.0",  # not MAJOR.MINOR.PATCH
        "v3.0.0.1",
        "release-3.0.0",  # not a train this repo cuts
        "3.0.0",  # missing the prefix entirely
        "",
        "v",
    ],
)
def test_malformed_tags_are_refused_without_raising(tag: str) -> None:
    ok, _ = guard.check(tag)
    assert not ok


def test_the_guard_is_runnable_as_a_command_and_sets_exit_status() -> None:
    """The workflow calls it as a script; a non-zero exit is the whole contract."""
    good = subprocess.run(
        [sys.executable, _GUARD, f"v{_version('VERSION')}"], capture_output=True, text=True
    )
    assert good.returncode == 0, good.stderr
    bad = subprocess.run(
        [sys.executable, _GUARD, "v999.999.999"], capture_output=True, text=True
    )
    assert bad.returncode == 1
    assert "VERSION" in bad.stderr


# ---------------------------------------------------------------------------
# Structural properties of the workflow itself.
# ---------------------------------------------------------------------------


def _workflow() -> dict:
    yaml = pytest.importorskip("yaml")
    with open(_WORKFLOW, encoding="utf-8") as handle:
        return dict(yaml.safe_load(handle))


def test_every_publishing_job_waits_on_the_guard() -> None:
    """A job that can publish must not be reachable before the tag is checked."""
    jobs = _workflow()["jobs"]
    for name, job in jobs.items():
        if name == "guard":
            continue
        needs = job.get("needs")
        needs = [needs] if isinstance(needs, str) else list(needs or [])
        assert "guard" in needs, (
            f"job {name!r} does not need the tag guard, so a tag that disagrees with "
            "its manifest would still reach it"
        )


def test_no_job_interpolates_a_workflow_expression_into_a_shell_body() -> None:
    """``${{ }}`` pasted into `run:` is command injection in a token-holding job.

    Values must arrive through `env:` instead. The two exceptions are the `if:`
    conditionals and `env:` blocks themselves, which are not shell.
    """
    yaml = pytest.importorskip("yaml")
    with open(_WORKFLOW, encoding="utf-8") as handle:
        spec = yaml.safe_load(handle)

    offenders: list[str] = []
    for job_name, job in spec["jobs"].items():
        for step in job.get("steps", []):
            script = step.get("run")
            if not script:
                continue
            for expression in re.findall(r"\$\{\{[^}]*\}\}", script):
                # `github.token` piped straight into `docker login --password-stdin`
                # is the documented GHCR pattern and carries no attacker-controlled
                # text; everything else must come through env.
                if "github.token" in expression:
                    continue
                offenders.append(f"{job_name} / {step.get('name', '?')}: {expression}")
    assert not offenders, "pass these through env: instead —\n  " + "\n  ".join(offenders)


def test_the_gateway_release_is_drafted_never_published() -> None:
    """An MCPIP release is signed with an offline key CI does not hold.

    If this workflow ever publishes a release outright it has silently redefined
    what a release means — see docs/operate/RELEASE.md.
    """
    jobs = _workflow()["jobs"]
    steps = jobs["release"]["steps"]
    create = [s for s in steps if "gh release create" in (s.get("run") or "")]
    assert create, "the release job no longer creates a release"
    for step in create:
        assert "--draft" in step["run"], (
            "the gateway release must stay a draft until the owner attaches the "
            "offline-signed manifest"
        )
