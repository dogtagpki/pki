#!/bin/bash
set -e

PACKAGE=$1
SCRIPT=$2

BUILDLOG=/tmp/$PACKAGE-build.log

function compose {
    pushd ${BUILDDIR}/pki
    sudo USE_TIMESTAMP=1 USE_GIT_COMMIT_ID=1 -u ${BUILDUSER} -- ./scripts/$SCRIPT rpms
    popd
}

function upload {
    if test -f $BUILDLOG; then
        curl -w "\n" --upload-file $BUILDLOG https://transfer.sh/$PACKAGE-build.txt | tee >> /tmp/workdir/pki/logs.txt
    fi
}

## prepare additional build dependencies
dnf builddep -y --spec ${BUILDDIR}/pki/specs/$PACKAGE.spec.in

if test "${TRAVIS}" != "true"; then
    compose

else
    trap "upload" EXIT
    echo "Building $PACKAGE with $SCRIPT."
    compose >> $BUILDLOG 2>&1
    echo "RC: $?"
fi
