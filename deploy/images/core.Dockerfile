# syntax=docker/dockerfile:1.7

ARG PYTHON_IMAGE=python:3.12.13-slim-trixie@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36
ARG UV_IMAGE=ghcr.io/astral-sh/uv:0.11.32@sha256:df4cae8f3a96d175e2e5f992e597550000edbe78fdc2594d5cd8de1a217f504c

FROM ${UV_IMAGE} AS uv

FROM ${PYTHON_IMAGE} AS builder
COPY --from=uv /uv /usr/local/bin/uv
WORKDIR /build
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project

FROM ${PYTHON_IMAGE} AS runtime
LABEL org.opencontainers.image.title="AGmind SAIS Core" \
      org.opencontainers.image.description="Unprivileged deterministic PCC control plane" \
      org.opencontainers.image.version="0.1.0"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH=/app/core \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/nonexistent

COPY --from=builder --chown=0:0 /build/.venv /opt/venv
COPY --chown=0:0 core/agmind_immune /app/core/agmind_immune
COPY --chown=0:0 contracts/v1 /app/contracts/v1
COPY --chown=0:0 contracts/v2 /app/contracts/v2
# Create the parent directories 0755 FIRST. A bare COPY --chmod=0444 into a
# not-yet-existing path stamps that same 0444 onto the directories it implicitly
# creates, leaving them non-traversable (dr--r--r--); the non-root USER below
# then cannot enter them to read the 0444 files inside. The root Dockerfile
# already does this; the production image must match.
RUN install -d -o root -g root -m 0755 /usr/share/agmind-sais /etc/falco /etc/falco/rules.d
COPY --chown=0:0 --chmod=0444 policies/pcc.rego /usr/share/agmind-sais/pcc.rego
COPY --chown=0:0 --chmod=0444 contracts/v1/ipv4-special-use.csv /usr/share/agmind-sais/ipv4-special-use.csv
COPY --chown=0:0 --chmod=0444 deploy/falco/rules.d/agmind-pcc.yaml /etc/falco/rules.d/agmind-pcc.yaml

WORKDIR /app
USER 65532:65532
EXPOSE 8787
HEALTHCHECK --interval=10s --timeout=3s --start-period=20s --retries=6 \
  CMD ["/opt/venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8787/ready', timeout=2).read(4096)"]
ENTRYPOINT ["/opt/venv/bin/python", "-m", "agmind_immune.main"]
