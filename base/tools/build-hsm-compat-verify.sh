#!/bin/bash
#
# Build script for standalone PKI HSM Compatibility Verification package
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PKG_NAME="pki-hsm-compat-verify"
PKG_VERSION="${PKG_VERSION:-$(awk '/^Version:/ {print $2; exit}' "${SCRIPT_DIR}/pki-hsm-compat-verify.spec")}"
BUILD_DIR="${BUILD_DIR:-${HOME}/build/${PKG_NAME}}"

echo "=== Building PKI HSM Compatibility Verification Package ==="
echo "Package: ${PKG_NAME}-${PKG_VERSION}"
echo "Build directory: ${BUILD_DIR}"
echo

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

# Copy source files
cp "${SCRIPT_DIR}/src/main/java/com/netscape/cmstools/hsmCompatVerifyServ.java" \
   "${TARBALL_DIR}/src/main/java/com/netscape/cmstools/"
cp "${SCRIPT_DIR}/src/main/java/com/netscape/cmstools/hsmCompatVerifyClnt.java" \
   "${TARBALL_DIR}/src/main/java/com/netscape/cmstools/"
cp "${SCRIPT_DIR}/src/main/java/com/netscape/cmstools/CryptoToolsUtil.java" \
   "${TARBALL_DIR}/src/main/java/com/netscape/cmstools/"

# Copy pom.xml
cp "${SCRIPT_DIR}/hsm-compat-verify-pom.xml" "${TARBALL_DIR}/pom.xml"

# Create tarball
cd "${BUILD_DIR}/SOURCES"
tar czf "${PKG_NAME}-${PKG_VERSION}.tar.gz" "${PKG_NAME}-${PKG_VERSION}"
rm -rf "${PKG_NAME}-${PKG_VERSION}"

# Copy spec file
echo "Copying spec file..."
cp "${SCRIPT_DIR}/pki-hsm-compat-verify.spec" "${BUILD_DIR}/SPECS/"

# Build RPM
echo "Building RPM..."
cd "${BUILD_DIR}"
rpmbuild --define "_topdir ${BUILD_DIR}" \
         -ba SPECS/pki-hsm-compat-verify.spec

echo
echo "=== Build Complete ==="
echo "RPMs: ${BUILD_DIR}/RPMS/"
ls -lh "${BUILD_DIR}/RPMS/noarch/"
echo
echo "To install:"
echo "  sudo rpm -ivh ${BUILD_DIR}/RPMS/noarch/${PKG_NAME}-${PKG_VERSION}-*.rpm"
echo
