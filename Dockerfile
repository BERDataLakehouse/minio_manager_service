FROM python:3.13-slim

WORKDIR /app

# Install system dependencies and MinIO mc client
RUN apt-get update && apt-get install -y \
    build-essential \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install MinIO mc client
ENV MC_VERSION=2025-05-21T01-59-54Z
ENV MC_PATH=/usr/local/bin/mc
RUN wget -O ${MC_PATH} https://dl.min.io/client/mc/release/linux-amd64/archive/mc.RELEASE.${MC_VERSION} && \
    chmod +x ${MC_PATH}

# Install uv and Python dependencies
RUN pip3 install --upgrade pip && \
    pip3 install uv
COPY pyproject.toml uv.lock .python-version ./
RUN uv sync --locked --inexact --no-dev

COPY alembic.ini alembic.ini
COPY migrations/ migrations/
COPY src/ src/
COPY scripts/ scripts/

EXPOSE 8000

CMD ["uv", "run", "uvicorn", "--host", "0.0.0.0", "--port", "8000", "--factory", "src.main:create_application"]