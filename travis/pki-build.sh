#!/bin/bash -ex

BUILDLOG=/tmp/pki-build.txt

build() {

    echo "Installing PKI build dependencies"
    dnf builddep -y --allowerasing --spec ${BUILDDIR}/pki/pki.spec

    echo "Building PKI packages"
    sudo -u ${BUILDUSER} -- ${BUILDDIR}/pki/build.sh \
        --work-dir=${BUILDDIR}/packages \
        --with-timestamp \
        --with-commit-id "$@" \
         2>&1 | tee $BUILDLOG
    echo "Build complete"
}

exit_handler() {

    if [ $? -eq 0 ]
    then
        # build succeeded, do not upload build log
        return
    fi

    echo "Build failed"

    if test -f $BUILDLOG; then

        # display the last 1000 lines for troubleshooting
        tail -n 1000 $BUILDLOG

        echo "Uploading build log"
        curl -k -w "\n" --upload-file $BUILDLOG https://transfer.sh/pki-build.txt \
            >> ${BUILDDIR}/pki/logs.txt || true
        cat ${BUILDDIR}/pki/logs.txt
    fi
}

if test "${TRAVIS}" != "true"; then
    build

else
    # Always invoke exit_handler() while exiting the script
    trap "exit_handler" EXIT

    # If IPA task is run, we just need to build base, server, ca and kra packages
    [[ $TASK == 'IPA' ]] && args="$@ --with-pkgs=base,server,ca,kra" || args="$@"
    build $args
fi
