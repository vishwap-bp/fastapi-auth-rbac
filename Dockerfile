# ---------------------------------------------------------------
# fastapi-auth-rbac — Dockerfile
# ---------------------------------------------------------------
FROM python:3.11-slim AS base

# Prevents Python from writing .pyc files and enables unbuffered output
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install system dependencies required by psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# ---------------------------------------------------------------
# Dependencies layer — cached unless requirements.txt changes
# ---------------------------------------------------------------
FROM base AS deps

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ---------------------------------------------------------------
# Final image
# ---------------------------------------------------------------
FROM deps AS final

COPY . .

# Run as non-root user for security
RUN useradd --create-home appuser && chown -R appuser /app
USER appuser

EXPOSE 8000

# Runs Alembic migrations then starts Uvicorn
CMD ["sh", "-c", "alembic upgrade head && uvicorn example.main:app --host 0.0.0.0 --port 8000"]
