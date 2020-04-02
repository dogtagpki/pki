#!/bin/bash -ex

. /etc/os-release

echo "$NAME $VERSION"

if test -z "${BUILDDIR}" || ! test -d "${BUILDDIR}"; then
    echo "BUILDDIR not set or ${BUILDDIR} is not a directory."
    exit 1
fi

if test -z "${BUILDUSER}" -o -z "${BUILDUSER_UID}" -o -z "${BUILDUSER_GID}"; then
    echo "BUILDUSER, BUILDUSER_UID, BUILDUSER_GID not set"
    exit 2
fi

## compose_pki_core_packages doesn't run as root, create a build user
echo "Creating build user ..."
groupadd --non-unique -g ${BUILDUSER_GID} ${BUILDUSER}
useradd --non-unique -u ${BUILDUSER_UID} -g ${BUILDUSER_GID} ${BUILDUSER}

## chown workdir and enter pki dir
chown ${BUILDUSER}:${BUILDUSER} ${BUILDDIR}

# workaround for
# [Errno 2] No such file or directory: '/var/cache/dnf/metadata_lock.pid'
rm -f /var/cache/dnf/metadata_lock.pid
dnf clean all
dnf makecache || :

echo "Installing basic development packages ..."
dnf install -y \
    dnf-plugins-core sudo wget 389-ds-base @buildsys-build @development-tools \
    --best --allowerasing

# This needs to be installed inorder to use setup-ds.pl (changed to `dscreate`)
# Only required >=28
if [[ `echo "$VERSION" | awk '{print $1}'` -ge 28 ]]
then
    echo "Installing 389-ds-base-legacy-tools"
    dnf install -y 389-ds-base-legacy-tools
fi

# Enable pki related COPR repo
# dnf copr enable -y ${COPR_REPO}

# update, container might be outdated
dnf update -y --best --allowerasing
