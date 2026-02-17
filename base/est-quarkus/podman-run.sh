#!/bin/bash
# Run the EST Quarkus PoC in Podman container

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGE_NAME="pki-est-quarkus-dev"
CONTAINER_NAME="pki-est-quarkus"

# Detect architecture and choose appropriate image tag
ARCH=$(uname -m)
if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    IMAGE_TAG="latest-arm64"
else
    IMAGE_TAG="latest"
fi

echo "================================"
echo "PKI EST Quarkus PoC - Podman Run"
echo "================================"
echo ""
echo "Architecture: ${ARCH}"
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""

# Check if image exists
if ! podman image exists ${IMAGE_NAME}:${IMAGE_TAG}; then
    echo "ERROR: Container image not found: ${IMAGE_NAME}:${IMAGE_TAG}"
    echo "Build it first with: ./podman-build.sh"
    exit 1
fi

# Remove existing container if running
if podman ps -a --format "{{.Names}}" | grep -q "^${CONTAINER_NAME}$"; then
    echo "Removing existing container: ${CONTAINER_NAME}"
    podman rm -f ${CONTAINER_NAME} 2>/dev/null || true
fi

# Run the container
echo "Starting development container..."
echo ""
echo "Container will mount your local PKI source at /workspace/pki"
echo "Changes made inside will reflect in your local directory"
echo ""

podman run -it --rm \
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
