#!/bin/bash
#
# Build script for standalone KRATool package
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_NAME="pki-kratool"

# Extract version from spec file (single source of truth)
PKG_VERSION=$(awk '$1=="Version:"{print $2; exit}' "${SCRIPT_DIR}/pki-kratool.spec")

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
validate_file() {
    if [ ! -f "$1" ]; then
        echo "ERROR: $2 not found at $3"
        exit 1
    fi
}

echo "Validating required files..."
validate_file "${SCRIPT_DIR}/src/main/java/com/netscape/cmstools/KRATool.java" "KRATool.java" "${SCRIPT_DIR}/src/main/java/com/netscape/cmstools/"
validate_file "${SCRIPT_DIR}/kratool-pom.xml" "kratool-pom.xml" "${SCRIPT_DIR}/"
validate_file "${SCRIPT_DIR}/pki-kratool.spec" "pki-kratool.spec" "${SCRIPT_DIR}/"

# Create build directory structure
echo "Creating build directories..."
if [ -n "${BUILD_DIR}" ] && [ "${BUILD_DIR}" != "/" ]; then
   rm -rf "${BUILD_DIR}"
fi
mkdir -p "${BUILD_DIR}/"{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

# Create source tarball
echo "Creating source tarball..."
TARBALL_DIR="${BUILD_DIR}/SOURCES/${PKG_NAME}-${PKG_VERSION}"
mkdir -p "${TARBALL_DIR}/src/main/java/com/netscape/cmstools"

# Copy KRATool source file
cp "${SCRIPT_DIR}/src/main/java/com/netscape/cmstools/KRATool.java" \
   "${TARBALL_DIR}/src/main/java/com/netscape/cmstools/"

# Copy pom.xml and sync version from spec file (spec is single source of truth)
cp "${SCRIPT_DIR}/kratool-pom.xml" "${TARBALL_DIR}/pom.xml"
sed -i "/<artifactId>pki-kratool<\/artifactId>/,/<\/version>/ s|<version>.*</version>|<version>${PKG_VERSION}</version>|" "${TARBALL_DIR}/pom.xml"

# Copy license file
cp "${SCRIPT_DIR}/../../LICENSE" "${TARBALL_DIR}/"

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
