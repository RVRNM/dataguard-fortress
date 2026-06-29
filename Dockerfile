# syntax=docker/dockerfile:1
# DataGuard Fortress — Production Dockerfile
# Build: docker build -t dataguard-fortress:v0.2 .
# Run:   docker run -p 8080:8080 -v $(pwd)/config.yaml:/app/config.yaml:ro dataguard-fortress:v0.2

# ── Stage 1: Builder ──────────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc libffi-dev \
    && rm -rf /var/lib/apt/lists/*

ENV PIP_NO_CACHE_DIR=1
COPY pyproject.toml .
RUN pip install --upgrade pip && pip install .

# ── Stage 2: Runtime ─────────────────────────────────────────────────────
FROM python:3.12-slim AS runtime

# Security: non-root user
RUN groupadd -r dataguard && useradd -r -g dataguard -d /app dataguard

RUN apt-get update && apt-get install -y --no-install-recommends curl tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local /usr/local

WORKDIR /app
COPY src/ src/

RUN mkdir -p /app/logs && chown -R dataguard:dataguard /app
USER dataguard

HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -fs http://localhost:8080/healthz || exit 1

EXPOSE 8080

LABEL org.opencontainers.image.title="DataGuard Fortress" \
      org.opencontainers.image.description="Privacy proxy for AI agents" \
      org.opencontainers.image.licenses="Apache-2.0" \
      version="0.2.0"

ENTRYPOINT ["tini", "--"]
CMD ["python", "-m", "src.main", "--host", "0.0.0.0", "--port", "8080"]
