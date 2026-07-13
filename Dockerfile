# Sysmon Hunter — container image
#
# Multi-stage, for one reason that matters in a security tool: the final image
# should carry the application and nothing else. Build tooling, compilers and
# package caches are attack surface and dead weight. They live in the builder
# stage and never reach the image that runs.

# ----------------------------------------------------------------------------
# Stage 1: build the dependency tree
# ----------------------------------------------------------------------------
FROM python:3.12-slim AS builder

# Install into a virtualenv rather than the system Python. Copying a single
# self-contained directory to the runtime stage is far simpler than trying to
# replicate a system-wide install across images.
ENV VIRTUAL_ENV=/opt/venv
RUN python -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

WORKDIR /build

# Copy only the requirements first. Docker caches layers, so as long as the
# dependencies do not change, editing application code does not trigger a
# reinstall -- which is the difference between a two-second rebuild and a
# two-minute one.
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# ----------------------------------------------------------------------------
# Stage 2: the runtime image
# ----------------------------------------------------------------------------
FROM python:3.12-slim AS runtime

# Run as an unprivileged user. A detection engine ingesting untrusted telemetry
# from endpoints has no business running as root: if a parsing bug is ever
# exploitable, the blast radius should be one unprivileged process.
RUN useradd --create-home --shell /bin/bash hunter

ENV VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

COPY --from=builder $VIRTUAL_ENV $VIRTUAL_ENV

WORKDIR /app

# Copy the application. .dockerignore keeps the venv, the local database, git
# history and test caches out -- see that file for the full list.
COPY --chown=hunter:hunter backend/ ./backend/
COPY --chown=hunter:hunter frontend/ ./frontend/
COPY --chown=hunter:hunter rules/ ./rules/
COPY --chown=hunter:hunter migrations/ ./migrations/
COPY --chown=hunter:hunter scripts/ ./scripts/
COPY --chown=hunter:hunter alembic.ini ./

# The database lives on a volume, so it survives a container rebuild. Create the
# directory with the right owner now; a volume mounted over a root-owned path
# leaves the unprivileged user unable to write to it.
RUN mkdir -p /app/data && chown hunter:hunter /app/data

USER hunter

EXPOSE 8000

# Health check hits /health, which reports rule count and engine state -- so a
# container that is listening but has loaded zero rules still reads as unhealthy
# to an orchestrator, rather than passing a naive port check.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=3).status == 200 else 1)"

# Migrations run before the server starts. Alembic owns the schema, so a
# container that boots against an out-of-date database must bring it up to date
# rather than failing -- or worse, silently querying a table that lacks a column.
CMD ["sh", "-c", "python -m alembic upgrade head && exec python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000"]