FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app/src

WORKDIR /app

COPY pyproject.toml README.md ./
COPY config ./config
COPY scripts ./scripts
COPY src ./src

RUN python -m pip install --no-cache-dir --upgrade pip \
    && python -m pip install --no-cache-dir -e '.[mcp,observability,auth,redis,aws]'

EXPOSE 8080

CMD ["./scripts/docker_entrypoint.sh"]
