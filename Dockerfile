# AGmind-SAIS: Security AI Sensor
# Многоступенчатая сборка для минимального размера образа

# ===== Stage 1: Build =====
FROM python:3.12-slim AS builder

WORKDIR /build

# Устанавливаем системные зависимости
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libffi-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Копируем и устанавливаем зависимости
COPY requirements.txt .
RUN pip install --no-cache-dir --user -r requirements.txt

# ===== Stage 2: Runtime =====
FROM python:3.12-slim

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

# Копируем Python-пакеты из builder
COPY --from=builder /root/.local /root/.local
ENV PATH=/root/.local/bin:$PATH

# Создаём пользователя (не root)
RUN useradd -m -s /bin/bash sais && \
    mkdir -p /var/log/sais /var/log/sais/ledger /app && \
    chown -R sais:sais /var/log/sais /app

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
