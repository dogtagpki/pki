#!/bin/bash
set -e

BUILDLOG=/tmp/pki-build.log

function compose {
    sudo -u ${BUILDUSER} -- ${BUILDDIR}/pki/build.sh --work-dir=${BUILDDIR}/packages --with-timestamp --with-commit-id "$@"
}

function upload {
    if test -f $BUILDLOG; then
        curl -k -w "\n" --upload-file $BUILDLOG https://transfer.sh/pki-build.txt >> ${BUILDDIR}/pki/logs.txt
        cat ${BUILDDIR}/pki/logs.txt
    fi
}

echo "Installing PKI build dependencies"

dnf builddep -y --allowerasing --spec ${BUILDDIR}/pki/pki.spec

echo "Building PKI packages"

if test "${TRAVIS}" != "true"; then
    compose

else
    # Always invoke upload() while exiting the script
    trap "upload" EXIT

    # If IPA task is run, we just need to build base, server, ca and kra packages
    [[ $TASK == 'IPA' ]] && args="$@ --with-pkgs=base,server,ca,kra" || args="$@"
    compose $args >> $BUILDLOG 2>&1
fi
