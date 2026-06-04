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
    && python -m pip install --no-cache-dir -e .

EXPOSE 8080

CMD ["python", "-m", "mcp_guard.cli", "dashboard", "--host", "0.0.0.0", "--port", "8080"]

