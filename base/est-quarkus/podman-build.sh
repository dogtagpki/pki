#!/bin/bash
# Build the Podman container for EST Quarkus PoC development

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGE_NAME="pki-est-quarkus-dev"
IMAGE_TAG="latest"

echo "================================"
echo "PKI EST Quarkus PoC - Podman Build"
echo "================================"
echo ""
echo "PKI Root: ${PKI_ROOT}"
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""

# Check if podman is installed
if ! command -v podman &> /dev/null; then
    echo "ERROR: podman is not installed"
    echo "Install with:"
    echo "  macOS:  brew install podman"
    echo "  Fedora: dnf install podman"
    exit 1
fi

# Detect architecture
ARCH=$(uname -m)
echo "Detected architecture: ${ARCH}"
echo ""

# Choose appropriate Containerfile
if [ "$ARCH" = "arm64" ] || [ "$ARCH" = "aarch64" ]; then
    echo "⚠️  ARM64 detected (Apple Silicon)"
    echo ""
    echo "NOTE: Full PKI stack cannot be built on ARM64 because:"
    echo "  • JSS (Java Security Services) is only available for x86_64"
    echo "  • LDAP SDK is only available for x86_64"
    echo ""
    echo "This build will create a REVIEW environment that allows you to:"
    echo "  ✓ Review all source code"
    echo "  ✓ Compare Tomcat vs Quarkus implementations"
    echo "  ✓ Study migration patterns"
    echo "  ✓ Read documentation"
    echo ""
    echo "For full build, you need:"
    echo "  1. x86_64 Linux machine, OR"
    echo "  2. Use platform emulation: podman build --platform linux/amd64 ..."
    echo ""
    read -p "Continue with ARM64 review environment? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Build cancelled"
        exit 0
    fi

    CONTAINERFILE="base/est-quarkus/Containerfile.arm64"
    IMAGE_TAG="latest-arm64"
else
    echo "✓ x86_64 detected - full build environment"
    CONTAINERFILE="base/est-quarkus/Containerfile"
fi

echo ""
echo "Building container image..."
echo "Containerfile: ${CONTAINERFILE}"
echo ""

cd "${PKI_ROOT}"

podman build \
    -f "${CONTAINERFILE}" \
    -t ${IMAGE_NAME}:${IMAGE_TAG} \
    .

echo ""
echo "================================"
echo "Build complete!"
echo "================================"
echo ""
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
echo "Next steps:"
echo "  1. Run development environment:"
echo "     ./podman-run.sh"
echo ""
echo "  2. Or run interactively:"
echo "     podman run -it --rm -v \$(pwd):/workspace/pki:Z ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
