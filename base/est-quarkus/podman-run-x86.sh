#!/bin/bash
# Run emulated x86_64 container on Apple Silicon

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGE_NAME="pki-est-quarkus-dev"
IMAGE_TAG="x86"
CONTAINER_NAME="pki-est-quarkus-x86"

echo "╔════════════════════════════════════════════════════════╗"
echo "║  PKI EST Quarkus - x86_64 Emulated Container          ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Check if image exists
if ! podman image exists ${IMAGE_NAME}:${IMAGE_TAG}; then
    echo "ERROR: x86_64 image not found: ${IMAGE_NAME}:${IMAGE_TAG}"
    echo ""
    echo "Build it first with:"
    echo "  ./podman-build-x86.sh"
    echo ""
    echo "Or use ARM64 review container:"
    echo "  ./podman-build.sh && ./podman-run.sh"
    exit 1
fi

# Remove existing container if running
if podman ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
    echo "Removing existing container: ${CONTAINER_NAME}"
    podman rm -f ${CONTAINER_NAME} 2>/dev/null || true
fi

echo "Starting x86_64 emulated container..."
echo ""
echo "NOTE: Performance will be 2-3x slower than native due to QEMU emulation"
echo ""
echo "Container details:"
echo "  Platform: linux/amd64 (emulated)"
echo "  Mounts:   ${PKI_ROOT} → /workspace/pki"
echo "  Ports:    8080 (HTTP), 8443 (HTTPS), 5005 (debug)"
echo ""
echo "Once inside, verify architecture:"
echo "  uname -m    # Should show: x86_64"
echo "  lscpu       # Should show: x86_64 architecture"
echo ""

podman run -it --rm \
    --platform linux/amd64 \
    --name ${CONTAINER_NAME} \
    -v "${PKI_ROOT}:/workspace/pki:Z" \
    -p 8080:8080 \
    -p 8443:8443 \
    -p 5005:5005 \
    -w /workspace/pki/base/est-quarkus \
    ${IMAGE_NAME}:${IMAGE_TAG} \
    /bin/bash

echo ""
echo "Container stopped."
