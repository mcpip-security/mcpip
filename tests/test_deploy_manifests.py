"""
MCPIP — the deployment manifests, checked against the rules a schema cannot state.

    ◐ "`kubeconform -strict` says the ConfigMap is well-formed. The API server says
       the key is illegal. Both are right."

A repository-wide path sweep once rewrote the Redis ConfigMap's data key from
``redis.conf`` to ``deploy/redis.conf`` — the file had moved, and the key looked like
a path. It is not a path. It is a projected filename, the container starts
``redis-server /etc/redis/redis.conf``, and ``/`` is not legal in a ConfigMap key, so
the manifest was rejected outright by the API server and the whole Redis tier would
not start.

Nothing in CI saw it. ``kubeconform -strict`` still passes on that manifest today —
verified — because the OpenAPI schema types ``data`` as ``additionalProperties:
string`` and models neither the key charset nor what the key is *for*. Schema
validation answers "is this shaped like a ConfigMap"; it cannot answer "does the
thing that mounts it find what it asks for". So kubeconform is in CI for the errors
it does catch, and this file carries the two rules it structurally cannot:

  * **key charset** — ConfigMap/Secret keys are filenames, not paths
  * **projection agreement** — every path a container reads out of a mounted
    ConfigMap/Secret must exist as a key in it

The second is the general form of the bug. It also covers the gateway's key mount:
``MCPIP_JWT_PUBLIC_KEY_PATH=/etc/mcpip/keys/jwt_public.pem`` is only correct because
the ``mcpip-keys`` Secret happens to carry a ``jwt_public.pem`` key, and nothing
previously connected those two facts.
"""

from __future__ import annotations

import pathlib
import re
from typing import Any, Iterator

import pytest
import yaml

_REPO = pathlib.Path(__file__).resolve().parent.parent
_K8S = _REPO / "deploy" / "k8s"
_CHART = _REPO / "deploy" / "chart" / "templates"

#: Kubernetes requires ConfigMap/Secret keys to be a valid "config map key": one or
#: more of alphanumeric, '-', '_' or '.'. Notably NOT '/', and not '.' or '..' alone.
_KEY = re.compile(r"^[-._a-zA-Z0-9]+$")

_PODDED = {"Deployment", "StatefulSet", "DaemonSet", "Job", "ReplicaSet"}


def _documents() -> Iterator[tuple[pathlib.Path, dict[str, Any]]]:
    for path in sorted(_K8S.glob("*.yaml")):
        for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")):
            if isinstance(doc, dict) and doc.get("kind"):
                yield path, doc


@pytest.fixture(scope="module")
def documents() -> list[tuple[pathlib.Path, dict[str, Any]]]:
    docs = list(_documents())
    assert docs, "no manifests parsed — the deploy tree moved and this test went blind"
    return docs


@pytest.fixture(scope="module")
def by_name(documents) -> dict[tuple[str, str], dict[str, Any]]:
    return {(d["kind"], d["metadata"]["name"]): d for _, d in documents}


def _keys_of(doc: dict[str, Any]) -> set[str]:
    return set(doc.get("data") or {}) | set(doc.get("stringData") or {})


class TestKeysAreFilenamesNotPaths:
    """The rule the API server enforces and the OpenAPI schema does not."""

    def test_every_configmap_and_secret_key_is_a_legal_key(self, documents) -> None:
        bad: list[str] = []
        for path, doc in documents:
            if doc["kind"] not in ("ConfigMap", "Secret"):
                continue
            for key in _keys_of(doc):
                if not _KEY.fullmatch(key) or key in (".", ".."):
                    bad.append(f"{path.name}: {doc['metadata']['name']} -> {key!r}")
        assert not bad, (
            "ConfigMap/Secret keys must match [-._a-zA-Z0-9]+ (they become filenames "
            f"when projected; the API server rejects the object otherwise): {bad}"
        )


class TestWhatIsMountedIsWhatIsRead:
    """Projection agreement: the mount, the key, and the path that reads it.

    Modelled the way the kubelet does it — a volume without ``items`` projects every
    key as ``<mountPath>/<key>``; with ``items`` it projects only the listed ones, at
    their ``path``. A reference under a mount point that resolves to no projected file
    is a container that will fail at startup on a file that is not there.
    """

    @staticmethod
    def _projected(volume: dict[str, Any], by_name) -> tuple[set[str], str] | None:
        for kind, field, ref in (
            ("ConfigMap", "configMap", "name"),
            ("Secret", "secret", "secretName"),
        ):
            source = volume.get(field)
            if not source:
                continue
            target = by_name.get((kind, source.get(ref)))
            if target is None:
                return None  # externally provisioned — nothing to check against
            if source.get("items"):
                return {i["path"] for i in source["items"]}, source[ref]
            return _keys_of(target), source[ref]
        return None

    @staticmethod
    def _referenced_paths(container: dict[str, Any]) -> Iterator[str]:
        for token in list(container.get("command") or []) + list(container.get("args") or []):
            if isinstance(token, str) and token.startswith("/"):
                yield token
        for env in container.get("env") or []:
            value = env.get("value")
            if isinstance(value, str) and value.startswith("/"):
                yield value

    def test_no_container_reads_a_path_the_mount_does_not_project(
        self, documents, by_name
    ) -> None:
        missing: list[str] = []
        for path, doc in documents:
            if doc["kind"] not in _PODDED:
                continue
            pod = doc["spec"]["template"]["spec"]
            volumes = {v["name"]: v for v in pod.get("volumes") or []}
            containers = list(pod.get("containers") or []) + list(pod.get("initContainers") or [])
            for container in containers:
                for mount in container.get("volumeMounts") or []:
                    projection = self._projected(volumes.get(mount["name"], {}), by_name)
                    if projection is None:
                        continue
                    files, source = projection
                    prefix = mount["mountPath"].rstrip("/") + "/"
                    for reference in self._referenced_paths(container):
                        if not reference.startswith(prefix):
                            continue
                        relative = reference[len(prefix):]
                        if relative not in files:
                            missing.append(
                                f"{path.name}: {container['name']} reads {reference} "
                                f"but {source} projects {sorted(files)}"
                            )
        assert not missing, (
            "container reads a file its mounted ConfigMap/Secret does not project: "
            f"{missing}"
        )

    def test_the_gateway_env_paths_resolve_into_the_keys_secret(self, by_name) -> None:
        """The specific instance worth naming: env vars pointing into the key mount.

        These are read at boot by ``core.config``; a mismatch is a fail-closed refusal
        to start, which is correct behaviour and a terrible way to find out.
        """
        secret = by_name[("Secret", "mcpip-keys")]
        config = by_name[("ConfigMap", "mcpip-gateway-config")]
        keys = _keys_of(secret)
        for name, value in (config.get("data") or {}).items():
            if isinstance(value, str) and value.startswith("/etc/mcpip/keys/"):
                assert value.rsplit("/", 1)[1] in keys, (
                    f"{name}={value} but the mcpip-keys Secret carries {sorted(keys)}"
                )


class TestTheChartAndTheRawManifestsDoNotDrift:
    """Two copies of the same Redis posture. One got fixed once and the other did not.

    The chart is templated, so it cannot be parsed as YAML — but the ``data:`` block of
    the Redis ConfigMap is entirely literal in both, which is exactly the part that
    must agree. Comparing the literal body catches a one-sided edit without needing
    Helm on the runner.
    """

    @staticmethod
    def _data_block(text: str) -> str:
        lines = text.splitlines()
        start = next(i for i, line in enumerate(lines) if line.rstrip() == "data:")
        body: list[str] = []
        for line in lines[start + 1:]:
            if line.strip() and not line.startswith((" ", "\t")):
                break
            if line.lstrip().startswith("{{"):
                continue
            body.append(line.rstrip())
        return "\n".join(body).rstrip()

    def test_the_redis_config_is_identical_in_both(self) -> None:
        raw = self._data_block((_K8S / "redis-configmap.yaml").read_text(encoding="utf-8"))
        chart = self._data_block((_CHART / "redis-configmap.yaml").read_text(encoding="utf-8"))
        assert raw, "the data: block did not parse — the check would pass vacuously"
        assert raw == chart, (
            "deploy/k8s and deploy/chart disagree on the Redis WORM durability profile; "
            "the gateway asserts this posture at boot, so a drifted chart is a "
            "deployment that refuses to start"
        )

    def test_the_durability_posture_is_actually_present(self) -> None:
        """Guards the comparison above: two identically-wrong copies would still match."""
        raw = self._data_block((_K8S / "redis-configmap.yaml").read_text(encoding="utf-8"))
        assert "redis.conf: |" in raw
        assert "appendfsync always" in raw, "assert_persistence_posture will refuse this"
        assert "maxmemory-policy noeviction" in raw


class TestTheChartCanRender:
    """A static stand-in for ``helm template``, for machines without Helm.

    CI runs the real renderer (``.github/workflows/ci.yml``, manifests job) and that
    is the authority. These two checks cover the failure modes that make a chart fail
    to render at all, so a contributor editing a template finds out from ``pytest``
    rather than from a red badge — and so this suite is not silently blind to the
    chart just because Helm is not installed.
    """

    _INCLUDE = re.compile(r'{{-?\s*include\s+"([^"]+)"')
    _DEFINE = re.compile(r'{{-?\s*define\s+"([^"]+)"')
    _VALUE = re.compile(r"\.Values\.([A-Za-z0-9_.]+)")

    def test_every_include_resolves_to_a_defined_helper(self) -> None:
        defined = set(self._DEFINE.findall((_CHART / "_helpers.tpl").read_text(encoding="utf-8")))
        undefined: dict[str, str] = {}
        for path in sorted(_CHART.iterdir()):
            for name in self._INCLUDE.findall(path.read_text(encoding="utf-8")):
                if name not in defined:
                    undefined[name] = path.name
        assert not undefined, f"template calls an undefined helper: {undefined}"

    def test_every_values_reference_exists_in_values_yaml(self) -> None:
        """A missing value renders as empty, not as an error — worse than a crash.

        ``{{ .Values.redis.image.tag }}`` against a values file that lost ``tag``
        produces ``image: redis:`` and a chart that installs something unintended.
        """
        values = yaml.safe_load((_CHART.parent / "values.yaml").read_text(encoding="utf-8"))

        def present(dotted: str) -> bool:
            node: Any = values
            for part in dotted.split("."):
                if not isinstance(node, dict) or part not in node:
                    return False
                node = node[part]
            return True

        referenced: set[str] = set()
        for path in sorted(_CHART.iterdir()):
            referenced |= {
                ref.rstrip(".") for ref in self._VALUE.findall(path.read_text(encoding="utf-8"))
            }
        assert referenced, "no .Values references found — the check would pass vacuously"
        missing = sorted(ref for ref in referenced if not present(ref))
        assert not missing, f"templates read values absent from values.yaml: {missing}"
