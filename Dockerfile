# AGmind-SAIS: Security AI Sensor
# Многоступенчатая сборка для минимального размера образа

ARG PYTHON_IMAGE=python:3.12.13-slim-trixie@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

# ===== Stage 1: Build =====
FROM ${PYTHON_IMAGE} AS builder

WORKDIR /build

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Копируем и устанавливаем зависимости
COPY requirements.txt .
RUN python -m venv /opt/agmind-venv && \
    /opt/agmind-venv/bin/pip install --no-cache-dir -r requirements.txt

# ===== Stage 2: Runtime =====
FROM ${PYTHON_IMAGE}

# Метки
LABEL org.opencontainers.image.title="AGmind-SAIS"
LABEL org.opencontainers.image.description="Security AI Sensor — автономный контейнер безопасности с ML-ядром"
LABEL org.opencontainers.image.version="0.1.0"
LABEL org.opencontainers.image.authors="Gbot"

# Системные зависимости для мониторинга
RUN apt-get update && apt-get install -y --no-install-recommends \
    procps \
    lsof \
    net-tools \
    iproute2 \
    curl \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

# Копируем root-owned virtualenv из builder
COPY --from=builder /opt/agmind-venv /opt/agmind-venv
ENV PATH="/opt/agmind-venv/bin:${PATH}"

# Создаём пользователя (не root)
RUN useradd -m -s /bin/bash sais && \
    mkdir -p /var/log/sais /var/log/sais/ledger /app && \
    chown -R sais:sais /var/log/sais /app

# Фиксированный root-owned detector bundle для Core
RUN install -d -o root -g root -m 0755 /etc/falco /etc/falco/rules.d
COPY --chown=0:0 --chmod=0444 deploy/falco/rules.d/agmind-pcc.yaml \
  /etc/falco/rules.d/agmind-pcc.yaml

# Фиксированный root-owned special-use registry для PCC authority
RUN install -d -o root -g root -m 0755 /usr/share/agmind-sais
COPY --chown=0:0 --chmod=0444 contracts/v1/ipv4-special-use.csv \
  /usr/share/agmind-sais/ipv4-special-use.csv

# Fixed root-owned manual-only OPA policy bytes for Core identity binding
COPY --chown=0:0 --chmod=0444 policies/pcc.rego /usr/share/agmind-sais/pcc.rego
RUN test "$(sha256sum /usr/share/agmind-sais/pcc.rego | cut -d ' ' -f 1)" = \
  "472ca6f13cee7962693c68c95688a49242300109b136640817f37c43bc27f1f7"

# Копируем приложение
COPY --chown=sais:sais . /app/
WORKDIR /app

# Права на исполнение
RUN chmod +x main.py

# Порт
EXPOSE 8080

# Healthcheck
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Запуск от непривилегированного пользователя
USER sais

# Entrypoint
CMD ["python3", "main.py"]
