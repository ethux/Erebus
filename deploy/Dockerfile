# Erebus deployable gateway - self-hosted image (008 FR-013, research R9).
#
# Builds a slim Python 3.12 image that installs the package with the gateway extra and runs
# the `erebus-gateway` console script (uvicorn). The entrypoint validates configuration and
# probes critical dependencies, exiting non-zero before binding on any failure (FR-009).
#
# Required environment at run time (supply via --env-file / compose env_file; see
# deploy/gateway.env.example): EREBUS_PG_DSN, EREBUS_GATEWAY_MASTER_KEY,
# EREBUS_GATEWAY_PROVIDER. No secrets are baked into the image (do not COPY a filled-in env).
#
# Build from the repository root:  docker build -f deploy/Dockerfile -t erebus-gateway .
FROM python:3.12-slim

# Predictable Python runtime: no .pyc files, unbuffered stdout/stderr so logs stream out,
# and pip without an on-disk cache to keep the image slim.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Copy the project source and install the package with the gateway extra (FastAPI, uvicorn,
# psycopg, psycopg-pool, httpx, cryptography). The build context is the repository root.
COPY . /app
RUN pip install '.[gateway]'

# The gateway listens on 8080 by default (EREBUS_GATEWAY_PORT).
EXPOSE 8080

# Run as a non-root user; no secrets are present in the image.
RUN useradd --create-home --uid 10001 erebus
USER erebus

# `erebus-gateway` -> erebus.gateway.server:main (config validation + dependency probe,
# idempotent migrations, then uvicorn). Required env must be supplied at run time.
ENTRYPOINT ["erebus-gateway"]
