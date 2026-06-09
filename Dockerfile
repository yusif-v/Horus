FROM python:3.12-slim

WORKDIR /app

# Install server deps (PyYAML, gunicorn) + pip-install horus
RUN pip install --no-cache-dir flask>=3.0 gunicorn>=21.0 pyyaml

COPY . .

# Install horus package in editable mode
RUN pip install --no-cache-dir -e .

# Persistent state: SQLite DB, JSON state, reports
VOLUME ["/app/state", "/app/reports"]

EXPOSE 8080

# SIGTERM propagates cleanly to gunicorn workers
STOPSIGNAL SIGTERM

ENTRYPOINT ["python", "-m", "horus", "--server"]
