#!/usr/bin/env bash
# Download the Firecracker binary (checksum-verified) and a guest kernel
# with virtio-vsock/virtio-blk/overlayfs into vm_assets/.
set -euo pipefail
cd "$(dirname "$0")/.."
FC_VERSION=${FC_VERSION:-v1.18.0}
KERNEL_URL=${KERNEL_URL:-https://s3.amazonaws.com/spec.ccfc.min/firecracker-ci/v1.15/x86_64/vmlinux-6.1.155}
mkdir -p vm_assets/dl && cd vm_assets/dl
base=https://github.com/firecracker-microvm/firecracker/releases/download/$FC_VERSION
curl -fsSLO "$base/firecracker-$FC_VERSION-x86_64.tgz"
curl -fsSLO "$base/firecracker-$FC_VERSION-x86_64.tgz.sha256.txt"
sha256sum -c "firecracker-$FC_VERSION-x86_64.tgz.sha256.txt"
tar xzf "firecracker-$FC_VERSION-x86_64.tgz"
install -m 755 "release-$FC_VERSION-x86_64/firecracker-$FC_VERSION-x86_64" ../firecracker
curl -fsSL -o ../vmlinux "$KERNEL_URL"
echo "vm_assets ready: $(ls ..)"
