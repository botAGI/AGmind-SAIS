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
LABEL org.opencontainers.image.title="AGmind SAIS Falco adapter" \
      org.opencontainers.image.description="Bounded redacting Falco-to-observer bridge" \
      org.opencontainers.image.version="0.1.0"

ENV PATH="/opt/venv/bin:${PATH}" \
    PYTHONPATH=/app \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOME=/nonexistent

COPY --from=builder --chown=0:0 /build/.venv /opt/venv
COPY --chown=0:0 core/agmind_immune/__init__.py /app/agmind_immune/__init__.py
COPY --chown=0:0 core/agmind_immune/canonicaljson.py /app/agmind_immune/canonicaljson.py
COPY --chown=0:0 core/agmind_immune/contracts.py /app/agmind_immune/contracts.py
COPY --chown=0:0 core/agmind_immune/falco_adapter /app/agmind_immune/falco_adapter

WORKDIR /app
USER 65532:65532
EXPOSE 8765
HEALTHCHECK --interval=5s --timeout=3s --start-period=15s --retries=6 \
  CMD ["/opt/venv/bin/python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/ready', timeout=2).read(4096)"]
ENTRYPOINT ["/opt/venv/bin/python", "-m", "agmind_immune.falco_adapter.main"]
