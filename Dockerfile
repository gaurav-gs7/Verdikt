FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    VERDIKT_PROJECT_ROOT=/app

WORKDIR /app

COPY pyproject.toml README.md ./
COPY config ./config
COPY scripts ./scripts
COPY src ./src

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir '.[mcp,observability,auth,redis,aws]' \
    && groupadd --gid 10001 verdikt \
    && useradd --uid 10001 --gid verdikt --no-create-home --shell /usr/sbin/nologin verdikt \
    && mkdir -p /app/data \
    && chown verdikt:verdikt /app/data

EXPOSE 8080

USER 10001:10001

HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
  CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).read()"]

CMD ["./scripts/docker_entrypoint.sh"]
