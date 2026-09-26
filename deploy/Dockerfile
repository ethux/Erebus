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
# Published as ghcr.io/ethux/erebus-gateway (core AGPL-3.0, pro/ Elastic-2.0).
FROM python:3.12-slim

# Predictable Python runtime: no .pyc files, unbuffered stdout/stderr so logs stream out,
# and pip without an on-disk cache to keep the image slim.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

# Copy the project source (.dockerignore keeps env files, keys and dev dirs out) and install
# the gateway extra plus erebus-pro. The build context is the repository root.
COPY . /app
# CPU-only torch first: the PyPI default pulls multi-GB CUDA libraries the gateway never uses.
RUN pip install --index-url https://download.pytorch.org/whl/cpu torch \
 && pip install '.[gateway]' ./pro

# The gateway listens on 8080 by default (EREBUS_GATEWAY_PORT).
EXPOSE 8080

# Run as a non-root user; no secrets are present in the image.
RUN useradd --create-home --uid 10001 erebus
USER erebus

# `erebus-gateway` -> erebus.gateway.server:main (config validation + dependency probe,
# idempotent migrations, then uvicorn). Required env must be supplied at run time.
ENTRYPOINT ["erebus-gateway"]
