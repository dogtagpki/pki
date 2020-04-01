#!/bin/bash -ex

set -o pipefail

exit_handler() {

    if [ $? -eq 0 ]
    then
        return
    fi

    # display logs for quick troubleshooting

    for DEBUG_LOG in `ls /var/log/pki/pkitest/tps/debug.*`
    do
        tail -n 1000 $DEBUG_LOG
    done

    SYSTEMD_LOG=/tmp/pkitest-systemd.log
    journalctl -u pki-tomcatd@pkitest.service --no-pager > $SYSTEMD_LOG
    tail -n 1000 $SYSTEMD_LOG

    # upload logs for further investigation

    for DEBUG_LOG in `ls /var/log/pki/pkitest/tps/debug.*`
    do
        filename=`basename $DEBUG_LOG`
        curl -k -w "\n" --upload-file $DEBUG_LOG https://transfer.sh/$filename
    done

    filename=`basename $SYSTEMD_LOG`
    curl -k -w "\n" --upload-file $SYSTEMD_LOG https://transfer.sh/$filename
}

trap "exit_handler" EXIT
pkispawn -v -f ${BUILDDIR}/pki/travis/pki.cfg -s TPS
