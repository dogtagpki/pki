#!/bin/bash
set -e

PACKAGE=$1
SCRIPT=$2

BUILDLOG=/tmp/$SCRIPT.log

function compose {
    pushd ${BUILDDIR}/pki
    sudo -u ${BUILDUSER} -- ./scripts/$SCRIPT rpms
    popd
}

function upload {
    if test -f $BUILDLOG; then
        echo "Uploading build log to transfer"
        curl --upload-file $BUILDLOG https://transfer.sh/$SCRIPT.txt
        # Add new line for readability of logs
        printf "\n\n=====================================\n\n"
    fi
}

trap "upload" EXIT

echo "Installing build dependencies for $PACKAGE"
dnf builddep -y --spec ${BUILDDIR}/pki/specs/$PACKAGE.spec.in

echo "Building $PACKAGE with $SCRIPT"
echo $(date) > $BUILDLOG
echo "Travis job ${TRAVIS_JOB_NUMBER}" >> $BUILDLOG
compose $SCRIPT >> $BUILDLOG 2>&1
