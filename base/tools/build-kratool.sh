#!/bin/bash
#
# Build script for standalone KRATool package
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_NAME="pki-kratool"

# Extract version from spec file (single source of truth)
PKG_VERSION=$(grep "^Version:" "${SCRIPT_DIR}/pki-kratool.spec" | awk '{print $2}')

if [ -z "$PKG_VERSION" ]; then
    echo "ERROR: Could not extract version from pki-kratool.spec"
    exit 1
fi

BUILD_DIR="${HOME}/build/${PKG_NAME}"

echo "=== Building Standalone KRATool Package ==="
echo "Package: ${PKG_NAME}-${PKG_VERSION}"
echo "Build directory: ${BUILD_DIR}"
echo

# Validate required files exist
echo "Validating required files..."
if [ ! -f "${SCRIPT_DIR}/src/main/java/com/netscape/cmstools/KRATool.java" ]; then
    echo "ERROR: KRATool.java not found at ${SCRIPT_DIR}/src/main/java/com/netscape/cmstools/"
    exit 1
fi

if [ ! -f "${SCRIPT_DIR}/kratool-pom.xml" ]; then
    echo "ERROR: kratool-pom.xml not found at ${SCRIPT_DIR}/"
    exit 1
fi

if [ ! -f "${SCRIPT_DIR}/pki-kratool.spec" ]; then
    echo "ERROR: pki-kratool.spec not found at ${SCRIPT_DIR}/"
    exit 1
fi

# Create build directory structure
echo "Creating build directories..."
rm -rf "${BUILD_DIR}"
mkdir -p "${BUILD_DIR}/"{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Create source tarball
echo "Creating source tarball..."
TARBALL_DIR="${BUILD_DIR}/SOURCES/${PKG_NAME}-${PKG_VERSION}"
mkdir -p "${TARBALL_DIR}/src/main/java/com/netscape/cmstools"

# Copy KRATool source file
cp "${SCRIPT_DIR}/src/main/java/com/netscape/cmstools/KRATool.java" \
   "${TARBALL_DIR}/src/main/java/com/netscape/cmstools/"

# Copy pom.xml
cp "${SCRIPT_DIR}/kratool-pom.xml" "${TARBALL_DIR}/pom.xml"

# Create tarball
cd "${BUILD_DIR}/SOURCES"
tar czf "${PKG_NAME}-${PKG_VERSION}.tar.gz" "${PKG_NAME}-${PKG_VERSION}"
rm -rf "${PKG_NAME}-${PKG_VERSION}"

# Copy spec file
echo "Copying spec file..."
cp "${SCRIPT_DIR}/pki-kratool.spec" "${BUILD_DIR}/SPECS/"

# Build RPM
echo "Building RPM..."
cd "${BUILD_DIR}"
rpmbuild --define "_topdir ${BUILD_DIR}" \
         -ba SPECS/pki-kratool.spec

echo
echo "=== Build Complete ==="
echo "RPMs in: ${BUILD_DIR}/RPMS/noarch/"
ls -lh "${BUILD_DIR}/RPMS/noarch/"
echo
echo "To install:"
echo "  sudo rpm -ivh ${BUILD_DIR}/RPMS/noarch/${PKG_NAME}-${PKG_VERSION}-*.rpm"
echo "  # Or to upgrade existing:"
echo "  sudo rpm -Uvh ${BUILD_DIR}/RPMS/noarch/${PKG_NAME}-${PKG_VERSION}-*.rpm"
echo
