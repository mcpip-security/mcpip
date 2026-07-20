# syntax=docker/dockerfile:1.7
# =============================================================================
# MCPIP — The Authorization Layer for Autonomous AI
# "AI Reasons. MCPIP Authorizes. Systems Execute."
#
# Multi-stage image:
#   * builder  — python:3.12-slim, resolves requirements.txt into an isolated
#                virtualenv at /opt/venv (no build toolchain leaks downstream).
#   * runtime  — python:3.12-slim, non-root, copies ONLY the venv + app source.
#
# Runtime base choice — why not distroless?
#   gcr.io/distroless/python3-debian12 ships CPython 3.11 (Debian bookworm).
#   The venv is built against 3.12, so its pyvenv.cfg / ABI would be a mismatch
#   there and would NOT run cleanly. We therefore run on the matching
#   python:3.12-slim base, which keeps the 3.12 venv fully portable across the
#   stage boundary. No secrets are baked in; identity keypairs are generated at
#   runtime by the gateway (see token_resolver / main.py).
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1 — builder: create a self-contained virtualenv with pinned deps.
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS builder

# Deterministic, quiet builds; never emit .pyc during dependency resolution.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_ROOT_USER_ACTION=ignore

# Build the venv at a fixed prefix so the runtime stage can copy it verbatim.
ENV VIRTUAL_ENV=/opt/venv
RUN python3.12 -m venv "${VIRTUAL_ENV}"
# Activate the venv for every subsequent RUN by putting its bin first on PATH.
ENV PATH="${VIRTUAL_ENV}/bin:${PATH}"

WORKDIR /build

# Copy only the dependency manifest first — maximises Docker layer cache reuse
# so application edits never invalidate the (slow) dependency install layer.
COPY requirements.txt ./
RUN python -m pip install --upgrade pip \
 && python -m pip install --require-virtualenv -r requirements.txt

# -----------------------------------------------------------------------------
# Stage 2 — runtime: minimal, non-root, venv + app only.
# -----------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# --- OCI image metadata (see https://github.com/opencontainers/image-spec) ---
LABEL org.opencontainers.image.title="MCPIP — The Authorization Layer for Autonomous AI" \
      org.opencontainers.image.description="Authorize every AI action before execution. Bridge, Obfuscator, Auth (canonical payload lock), Audit (Ed25519 WORM)." \
      org.opencontainers.image.documentation="https://github.com/mcpip/mcpip-genesis/blob/main/README.md" \
      org.opencontainers.image.source="https://github.com/mcpip/mcpip-genesis" \
      org.opencontainers.image.url="https://github.com/mcpip/mcpip-genesis" \
      org.opencontainers.image.vendor="MCPIP" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.base.name="docker.io/library/python:3.12-slim" \
      com.mcpip.philosophy="AI Reasons. MCPIP Authorizes. Systems Execute." \
      com.mcpip.tagline="Authorize every AI action before execution." \
      com.mcpip.glyph="◐"

# Runtime environment:
#   * PYTHONDONTWRITEBYTECODE — no .pyc writes (required under read-only rootfs).
#   * PYTHONUNBUFFERED        — flush logs immediately for container log capture.
#   * PATH                    — prepend the copied venv so `python` == venv python.
#   * MCPIP_REDIS_URL         — sensible in-cluster default (compose service name).
#   * MCPIP_WORM_PATH         — WORM log lands in a dedicated, mountable data dir.
#   * MCPIP_SANDBOX_MODE      — FALSE (secure-by-default). The shipped image never
#       ships the sandbox affordances (unauthenticated dev-token minter + staged-OTP
#       disclosure); with this false and no real PEM paths the gateway fails CLOSED at
#       boot, so a deployment that forgets to configure identity/audit keys refuses to
#       start rather than exposing a bypass. Opt INTO the demo explicitly with
#       `-e MCPIP_SANDBOX_MODE=true` (see docker-compose.yml for the demo posture).
#   * MCPIP_WORKERS           — uvicorn worker processes. The app is fully STATELESS
#       (all synchronization state — payload locks, grants, the WORM buffer/epoch chain —
#       lives in Redis; epoch closes are serialized by a Redis lock and emit is atomic),
#       so it scales horizontally by process. A single worker is CPU-bound on one core
#       (~850 authorize/sec) and refuses connections under burst concurrency; run
#       ~1–2 workers per available core behind a load balancer. Override per host.
#   * MCPIP_BACKLOG           — listen backlog so burst connections QUEUE instead of
#       being refused with ConnectError at the accept path. NOTE: the kernel silently
#       CLAMPS this to `net.core.somaxconn` (Linux) / `kern.ipc.somaxconn` (macOS). The
#       default is often 128, so a `--backlog 2048` is a no-op until you also raise the
#       sysctl (e.g. `sysctl -w net.core.somaxconn=2048`, or a k8s sysctl/initContainer).
#       App-layer admission (MCPIP_MAX_IN_FLIGHT) bounds WORK-in-flight regardless, but the
#       ~0-drop / bounded-tail guarantee under a 2k-10k connection STORM also needs this
#       kernel backlog raised PLUS an L4/L7 load balancer and horizontal nodes — a single
#       co-located box with somaxconn=128 cannot demonstrate it (accept-queue overflow is
#       refused by the kernel before app-layer shedding can run). See README "Scaling".
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONFAULTHANDLER=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}" \
    MCPIP_REDIS_URL="redis://redis:6379/0" \
    MCPIP_WORM_PATH="/var/lib/mcpip/mcpip_worm.jsonl" \
    MCPIP_SANDBOX_MODE=false \
    MCPIP_API_PORT=8080 \
    MCPIP_WORKERS=4 \
    MCPIP_BACKLOG=2048 \
    PROMETHEUS_MULTIPROC_DIR=/tmp/prometheus

# Create a dedicated non-root system identity and the writable WORM data dir.
# Named-volume mounts inherit this ownership on first init, so the gateway can
# append to the WORM log even under a read-only root filesystem.
RUN groupadd --system --gid 10001 mcpip \
 && useradd --system --uid 10001 --gid mcpip --home-dir /app --no-create-home --shell /usr/sbin/nologin mcpip \
 && install -d -o mcpip -g mcpip -m 0750 /app /var/lib/mcpip

# Copy the fully-resolved virtualenv from the builder (no compilers in runtime).
COPY --from=builder --chown=mcpip:mcpip /opt/venv /opt/venv

WORKDIR /app

# Copy the application source only. Non-app artefacts (git, docs, infra files,
# secrets, WORM logs, venvs) are excluded via .dockerignore.
COPY --chown=mcpip:mcpip . /app

# Drop to the unprivileged runtime identity for good.
USER mcpip

# The gateway serves the FastAPI authorization API on 8080.
EXPOSE 8080

# Image-level liveness self-check: hit GET /healthz with the stdlib (curl is
# absent in -slim). docker-compose layers an identical service-level check on top.
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD ["python", "-c", "import urllib.request,sys; sys.exit(0) if urllib.request.urlopen('http://127.0.0.1:8080/healthz',timeout=3).status==200 else sys.exit(1)"]

# Default: serve the long-lived authorization API (uvicorn app.main:app) with multiple
# stateless workers and a deep accept backlog (shell form so the MCPIP_* knobs above are
# honored). The self-verifying 10-gate demo remains runnable by overriding CMD, e.g.
#     docker run --rm -e MCPIP_REDIS_URL=redis://host.docker.internal:63790/0 \
#       mcpip-gateway:v2 python main.py
#
# Performance tier (no security property is weakened):
#   * --loop uvloop            — pin the high-performance libuv event loop. app.main also
#       installs uvloop as the policy at import (clean fallback to stdlib asyncio); a host
#       lacking uvloop should use `--loop auto` (uvicorn auto-detects, then falls back).
#   * --http httptools         — the fast C HTTP parser (ships in uvicorn[standard]).
#   * --workers / --backlog    — horizontal + backlog half of the load-shed fix. The app
#       is fully STATELESS (payload locks, grants, WORM buffer/epoch chain, rate counters
#       all live in Redis; epoch closes are Redis-lock-serialized; emit is atomic Lua), so
#       it scales by process and by node. Run MCPIP_WORKERS ~= 1-2 x cores per node behind
#       an L4/L7 load balancer and add nodes for more throughput. Each worker holds its own
#       BlockingConnectionPool (redis_max_connections=64) and its own MCPIP_MAX_IN_FLIGHT
#       admission bound; keep workers x max_in_flight <= shared Redis maxclients headroom.
#       --backlog 2048 lets momentary bursts QUEUE at the kernel accept layer (never
#       ConnectError), while MCPIP_MAX_IN_FLIGHT sheds sustained overload with a fast 503
#       and bounded p99. See core/config.py (max_in_flight / request_timeout_s /
#       shed_retry_after_s) and app.main.EdgeGateMiddleware.
#   * --timeout-keep-alive 15  — reclaim idle keep-alive sockets under burst.
CMD ["sh", "-c", "mkdir -p \"${PROMETHEUS_MULTIPROC_DIR:-/tmp/prometheus}\" && exec uvicorn app.main:app --host 0.0.0.0 --port ${MCPIP_API_PORT:-8080} --workers ${MCPIP_WORKERS:-4} --backlog ${MCPIP_BACKLOG:-2048} --loop uvloop --http httptools --timeout-keep-alive 15"]
