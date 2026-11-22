# syntax=docker/dockerfile:1
FROM rust:1-slim-bookworm AS builder
WORKDIR /app
RUN apt-get update && apt-get install -y pkg-config libssl-dev && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml ./
COPY src/ src/
COPY daas/ daas/
COPY tests/ tests/
RUN cargo build --release --bin detonate && strip target/release/detonate

FROM node:22-bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        bubblewrap ca-certificates curl git python3 \
    && rm -rf /var/lib/apt/lists/*
# Pi coding agent (the detonation agent)
RUN npm install -g @earendil-works/pi-coding-agent && npm cache clean --force
# Optional Google Antigravity CLI (`agy`) for `--agent antigravity`:
#   docker build --build-arg INSTALL_AGY=1 -t detonate .
ARG INSTALL_AGY=0
RUN if [ "$INSTALL_AGY" = "1" ]; then \
        curl -fsSL https://antigravity.google/cli/install.sh | bash -s -- --dir /usr/local/bin \
        && rm -rf /root/.cache/antigravity; \
    fi
COPY --from=builder /app/target/release/detonate /usr/local/bin/detonate
COPY SKILL.md /opt/detonate/SKILL.md
COPY pi-extension/ /opt/detonate/pi-extension/
WORKDIR /work
# bubblewrap needs unprivileged user namespaces inside the container, e.g.:
#   docker run --rm --security-opt seccomp=unconfined --security-opt apparmor=unconfined \
#     --env-file .env -i detonate --output human < payload.txt
ENTRYPOINT ["detonate"]
