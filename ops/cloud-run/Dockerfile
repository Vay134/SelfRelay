# syntax=docker/dockerfile:1

# Keep the Python patch release pinned so the tested runtime is reproducible.
FROM python:3.12.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

RUN groupadd --gid 10001 application \
    && useradd --uid 10001 --gid application --create-home --shell /usr/sbin/nologin application

COPY pyproject.toml uv.lock ./
RUN python -m pip install --no-cache-dir uv==0.8.15 \
    && uv sync --frozen --no-dev --no-install-project

COPY app ./app

USER application

EXPOSE 8080

CMD ["sh", "-c", "exec .venv/bin/uvicorn app.main:app --host 0.0.0.0 --port \"${PORT:-8080}\" --workers 1"]
