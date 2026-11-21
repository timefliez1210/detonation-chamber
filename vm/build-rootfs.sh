#!/usr/bin/env bash
# Build vm_assets/rootfs.ext4 for `detonate --firecracker` using Docker.
# No root privileges on the host are required.
set -euo pipefail
cd "$(dirname "$0")"
OUT=../vm_assets
mkdir -p "$OUT"
# Use the same Pi version as the host by default, so both isolation modes run
# the same agent. Override with PI_VERSION=x.y.z (or "latest").
PI_VERSION=${PI_VERSION:-$(pi --version 2>/dev/null || echo latest)}
echo "building rootfs with pi@$PI_VERSION"
docker build -f Dockerfile.rootfs --target image --build-arg PI_VERSION="$PI_VERSION" -t detonate-vm-rootfs .
cid=$(docker create detonate-vm-rootfs)
trap 'docker rm -f "$cid" >/dev/null' EXIT
docker cp "$cid:/out/rootfs.ext4" "$OUT/rootfs.ext4"
echo "wrote $OUT/rootfs.ext4"
