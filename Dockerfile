# syntax=docker/dockerfile:1
# Farrier engine + API. Data (SQLite, sealed keys, master.key, change packs) lives in /data.
FROM python:3.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FARRIER_DATA=/data

WORKDIR /app
COPY pyproject.toml README.md ./
COPY farrier ./farrier
RUN pip install --no-cache-dir . \
 && useradd --system --uid 10001 farrier \
 && mkdir -p /data && chown farrier /data

USER 10001
VOLUME ["/data"]
EXPOSE 8740
# FARRIER_API_TOKEN is required: serve refuses a non-loopback bind without it.
CMD ["farrier", "serve", "--host", "0.0.0.0", "--port", "8740"]

HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8740/healthz')" || exit 1
