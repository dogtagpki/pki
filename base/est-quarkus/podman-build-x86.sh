#!/bin/bash
# Build x86_64 image with QEMU emulation on Apple Silicon

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKI_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
IMAGE_NAME="pki-est-quarkus-dev"
IMAGE_TAG="x86"

echo "╔════════════════════════════════════════════════════════╗"
echo "║  PKI EST Quarkus - x86_64 Emulation Build             ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

# Check architecture
ARCH=$(uname -m)
if [ "$ARCH" != "arm64" ] && [ "$ARCH" != "aarch64" ]; then
    echo "WARNING: You're on ${ARCH}, not ARM64"
    echo "You don't need emulation - use ./podman-build.sh instead"
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
fi

# Check if podman is installed
if ! command -v podman &> /dev/null; then
    echo "ERROR: podman is not installed"
    echo "Install with: brew install podman"
    exit 1
fi

# Check if podman machine is running
if ! podman machine list 2>/dev/null | grep -q "Currently running"; then
    echo "ERROR: No Podman machine is running"
    echo ""
    echo "Initialize Podman machine with:"
    echo "  podman machine init --cpus 4 --memory 8192 --disk-size 60"
    echo "  podman machine start"
    exit 1
fi

# Get machine info
MACHINE_INFO=$(podman machine list --format "{{.Name}}: {{.CPUs}} CPUs, {{.Memory}} memory")
echo "Podman Machine: ${MACHINE_INFO}"
echo ""

# Warn about build time
echo "╔════════════════════════════════════════════════════════╗"
echo "║  IMPORTANT: Emulation Performance Notice              ║"
echo "╠════════════════════════════════════════════════════════╣"
echo "║  This build uses QEMU to emulate x86_64               ║"
echo "║                                                        ║"
echo "║  Expected Build Time: 30-45 minutes                   ║"
echo "║  (vs 5 minutes for native ARM64)                      ║"
echo "║                                                        ║"
echo "║  Runtime Performance: 2-3x slower than native         ║"
echo "║                                                        ║"
echo "║  Alternatives:                                         ║"
echo "║   • ARM64 review container (fast, limited)            ║"
echo "║   • Cloud x86_64 VM (fast, full featured)             ║"
echo "║   • UTM VM (medium speed, local)                      ║"
echo "║                                                        ║"
echo "║  See QEMU-EMULATION-GUIDE.md for details              ║"
echo "╚════════════════════════════════════════════════════════╝"
echo ""

read -p "Continue with emulated build? [y/N] " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Build cancelled"
    echo ""
    echo "Alternatives:"
    echo "  • ARM64 review:  ./podman-build.sh"
    echo "  • Cloud VM:      See ARM64-README.md"
    echo "  • UTM VM:        See QEMU-EMULATION-GUIDE.md"
    exit 0
fi

echo ""
echo "Starting emulated x86_64 build..."
echo "Started at: $(date)"
echo "PKI Root: ${PKI_ROOT}"
echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
echo ""
echo "Grab a coffee - this will take 30-45 minutes! ☕"
echo ""

cd "${PKI_ROOT}"

# Build with platform emulation
time podman build \
    --platform linux/amd64 \
    -f base/est-quarkus/Containerfile \
    -t ${IMAGE_NAME}:${IMAGE_TAG} \
    . 2>&1 | tee /tmp/pki-emulated-build.log

BUILD_STATUS=$?

echo ""
echo "Finished at: $(date)"
echo ""

if [ $BUILD_STATUS -eq 0 ]; then
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Build Successful!                                     ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""
    echo "Image: ${IMAGE_NAME}:${IMAGE_TAG}"
    echo "Platform: linux/amd64 (emulated)"
    echo ""
    echo "Next steps:"
    echo "  1. Run the container:"
    echo "     ./podman-run-x86.sh"
    echo ""
    echo "  2. Or run manually:"
    echo "     podman run --platform linux/amd64 -it --rm \\"
    echo "       -v \$(pwd):/workspace/pki:Z \\"
    echo "       -p 8080:8080 -p 8443:8443 \\"
    echo "       ${IMAGE_NAME}:${IMAGE_TAG}"
    echo ""
    echo "Build log saved to: /tmp/pki-emulated-build.log"
    echo ""
else
    echo "╔════════════════════════════════════════════════════════╗"
    echo "║  Build Failed                                          ║"
    echo "╚════════════════════════════════════════════════════════╝"
    echo ""
    echo "Check build log: /tmp/pki-emulated-build.log"
    echo ""
    echo "Common issues:"
    echo "  • Timeout: Increase timeout with --timeout flag"
    echo "  • Memory: Increase Podman machine memory"
    echo "  • Network: Check connectivity to COPR/Fedora repos"
    echo ""
    exit 1
fi
