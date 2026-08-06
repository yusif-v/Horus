# ── Build stage ──────────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN pip install --no-cache-dir --prefix=/install flask>=3.0 gunicorn>=21.0 pyyaml

COPY . /build/src
RUN pip install --no-cache-dir --prefix=/install -e /build/src

# ── Runtime stage ───────────────────────────────────────────────────────
FROM python:3.12-slim

# Non-root user for container security
RUN groupadd --gid 1000 horus && \
    useradd --uid 1000 --gid horus --create-home --shell /bin/bash horus

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy application code
COPY --chown=horus:horus . /app

# Persistent state: SQLite DB, JSON state, reports
RUN mkdir -p /app/state /app/reports && chown -R horus:horus /app
VOLUME ["/app/state", "/app/reports"]

# Health check — verifies the web endpoint responds
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD ["python3", "-c", "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/health')"]

USER horus

EXPOSE 8080

# SIGTERM propagates cleanly to gunicorn workers
STOPSIGNAL SIGTERM

ENTRYPOINT ["python", "-m", "horus", "--server", "--config", "/app/horus.yaml"]
