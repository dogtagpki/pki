#!/bin/bash
#
# Build script for standalone KRATool package
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_NAME="pki-kratool"
PKG_VERSION="11.6.0"
BUILD_DIR="${HOME}/build/${PKG_NAME}"

echo "=== Building Standalone KRATool Package ==="
echo "Package: ${PKG_NAME}-${PKG_VERSION}"
echo "Build directory: ${BUILD_DIR}"
echo

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
echo "RPMs: ${BUILD_DIR}/RPMS/"
ls -lh "${BUILD_DIR}/RPMS/noarch/" 2>/dev/null || ls -lh "${BUILD_DIR}/RPMS/x86_64/" 2>/dev/null
echo
echo "To install:"
echo "  sudo rpm -ivh ${BUILD_DIR}/RPMS/noarch/${PKG_NAME}-${PKG_VERSION}-*.rpm"
echo "  # Or to upgrade existing:"
echo "  sudo rpm -Uvh ${BUILD_DIR}/RPMS/noarch/${PKG_NAME}-${PKG_VERSION}-*.rpm"
echo
