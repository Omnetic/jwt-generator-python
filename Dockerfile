# syntax=docker/dockerfile:1
FROM python:3.13-alpine

# uv binary from the official image (parallels the PHP image pinning composer:2).
COPY --from=ghcr.io/astral-sh/uv:0.11.31 /uv /uvx /usr/local/bin/

# git lets uv fetch any VCS-sourced package. cryptography installs from prebuilt
# musllinux wheels, so no Rust/build toolchain is needed.
RUN apk add --no-cache git

ENV UV_CACHE_DIR=/tmp/uv-cache \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_LINK_MODE=copy \
    PATH="/opt/venv/bin:$PATH"

WORKDIR /app

CMD ["python", "--version"]
