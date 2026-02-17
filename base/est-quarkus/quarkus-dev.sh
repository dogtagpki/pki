#!/bin/bash
# Run Quarkus in development mode (to be used inside container)

set -e

echo "================================"
echo "Starting Quarkus Development Mode"
echo "================================"
echo ""
echo "This will:"
echo "  - Compile the EST Quarkus PoC"
echo "  - Start Quarkus with live reload"
echo "  - Expose endpoints on port 8080/8443"
echo ""
echo "Available endpoints:"
echo "  - Dev UI:  http://localhost:8080/q/dev"
echo "  - Health:  http://localhost:8080/q/health"
echo "  - Metrics: http://localhost:8080/q/metrics"
echo "  - EST API: https://localhost:8443/rest/cacerts"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Ensure we're in the right directory
cd /workspace/pki/base/est-quarkus

# Check if parent PKI is built
if [ ! -d "$HOME/.m2/repository/org/dogtagpki/pki/pki-common" ]; then
    echo "⚠️  Parent PKI modules not found in Maven repository"
    echo "Building parent PKI first..."
    echo ""
    cd /workspace/pki
    ./build.sh dist
    cd /workspace/pki/base/est-quarkus
    echo ""
fi

# Run Quarkus dev mode
mvn quarkus:dev \
    -Dquarkus.http.host=0.0.0.0 \
    -Ddebug=5005
