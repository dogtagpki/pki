#!/bin/bash
set -e

PACKAGE=$1
SCRIPT=$2

BUILDLOG=/tmp/compose_$SCRIPT.log

function compose {
    pushd ${BUILDDIR}/pki
    sudo -u ${BUILDUSER} -- ./scripts/$SCRIPT rpms
    popd
}

function upload {
    if test -f $BUILDLOG; then
        echo "Uploading build log to transfer"
        curl --upload-file $BUILDLOG https://transfer.sh/pkitravis_$SCRIPT.txt >> /tmp/workdir/pki/logs.txt
        # Add new line for readability of logs
        printf "\n\n=====================================\n\n"
    fi
}

## prepare additional build dependencies
dnf builddep -y --spec ${BUILDDIR}/pki/specs/$PACKAGE.spec.in

if test "${TRAVIS}" != "true"; then
    compose

else
    trap "upload" EXIT
    echo "Runing $SCRIPT rpms."
    echo "Build log will be posted to transfer.sh"
    echo $(date) > $BUILDLOG
    echo "Travis job ${TRAVIS_JOB_NUMBER}" >> $BUILDLOG
    compose >> $BUILDLOG 2>&1
fi
