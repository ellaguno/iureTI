# iureTI Discovery — imagen de la sonda
# Requiere red del host para ver la LAN (ARP, mDNS, SSDP):
#   docker run -d --name iureti --network host --restart unless-stopped \
#     -v iureti-data:/data ghcr.io/ellaguno/iureti:latest
FROM python:3.12-slim

LABEL org.opencontainers.image.title="iureTI Discovery" \
      org.opencontainers.image.source="https://github.com/ellaguno/iureTI" \
      org.opencontainers.image.licenses="Apache-2.0"

RUN apt-get update \
 && apt-get install -y --no-install-recommends iputils-ping iproute2 \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --home-dir /data --shell /usr/sbin/nologin iureti \
 && mkdir -p /data && chown iureti:iureti /data

COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml uv.lock README.md LICENSE NOTICE ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev && rm /usr/local/bin/uv

ENV PATH=/app/.venv/bin:$PATH \
    IURETI_DB=/data/iureti.db \
    IURETI_CACHE_DIR=/data/cache \
    IURETI_INSTALL=docker \
    IURETI_HOST=127.0.0.1 \
    IURETI_PORT=8765 \
    PYTHONUNBUFFERED=1

USER iureti
VOLUME /data
EXPOSE 8765
HEALTHCHECK --interval=60s --timeout=5s CMD python -c "import urllib.request,os; urllib.request.urlopen(f'http://127.0.0.1:{os.environ[\"IURETI_PORT\"]}/api/status', timeout=4)" || exit 1
CMD ["iureti-discovery", "serve", "--agent"]
