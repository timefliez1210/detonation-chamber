# syntax=docker/dockerfile:1
FROM rust:1.80-slim-bookworm AS builder

WORKDIR /app

# Install build deps
RUN apt-get update && apt-get install -y \
    pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for layer caching
COPY Cargo.toml Cargo.lock ./
COPY src/ src/
COPY SKILL.md ./
COPY pi-extension/ pi-extension/

# Build
RUN cargo build --release && \
    strip target/release/detonate

# Runtime stage
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Optional: install pi + ollama for built-in LLM support
# RUN curl -fsSL https://pi.sh/install | sh

COPY --from=builder /app/target/release/detonate /usr/local/bin/detonate
COPY SKILL.md /opt/detonate/SKILL.md
COPY pi-extension/ /opt/detonate/pi-extension/

ENTRYPOINT ["detonate"]
