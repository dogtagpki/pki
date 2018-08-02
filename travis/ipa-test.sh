#!/bin/bash
#
# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2017 Red Hat, Inc.
# All rights reserved.
#

PYTHON="/usr/bin/python${TRAVIS_PYTHON_VERSION}"
IPA_TEST_LOG="${TRAVIS_BUILD_DIR}/ipa-test.txt"

test_set="test_caacl_plugin.py test_caacl_profile_enforcement.py test_cert_plugin.py test_certprofile_plugin.py test_vault_plugin.py"
cert_test_file_loc=""


function truncate_log_to_test_failures() {
    # chop off everything in the IPA_TEST_LOG preceding pytest error output
    # if there are pytest errors in the log
    error_fail_regexp='\(=== ERRORS ===\)\|\(=== FAILURES ===\)'

    if grep -e "$error_fail_regexp" $IPA_TEST_LOG > /dev/null
    then
        sed -i "/$error_fail_regexp/,\$!d" $IPA_TEST_LOG
    fi
}

for test_files in ${test_set}; do
    cert_test_file_loc="${cert_test_file_loc} test_xmlrpc/${test_files}"
done

echo ${cert_test_file_loc}

echo "Running IPA test in ${PWD}"

ipa-docker-test-runner -l ${IPA_TEST_LOG} \
    -c travis/ipa-test.yaml \
    --container-environment "PYTHON=$PYTHON" \
    --container-image ${IMAGE_REPO:-dogtagpki/pki-ci}:${IMAGE} \
    --git-repo ${TRAVIS_BUILD_DIR} \
    run-tests ${cert_test_file_loc}

exit_status="$?"

if [[ "$exit_status" -ne 0 ]]
then
    truncate_log_to_test_failures
fi

ls -la ${TRAVIS_BUILD_DIR}

echo "Uploading logs"

touch $LOGS

curl -k -w "\n" --upload-file ${TRAVIS_BUILD_DIR}/ipaclient-install.txt https://transfer.sh >> $LOGS
curl -k -w "\n" --upload-file ${TRAVIS_BUILD_DIR}/ipaclient-uninstall.txt https://transfer.sh >> $LOGS
curl -k -w "\n" --upload-file ${TRAVIS_BUILD_DIR}/ipaserver-install.txt https://transfer.sh >> $LOGS
curl -k -w "\n" --upload-file ${TRAVIS_BUILD_DIR}/ipaserver-uninstall.txt https://transfer.sh >> $LOGS
curl -k -w "\n" --upload-file ${TRAVIS_BUILD_DIR}/krb5kdc.txt https://transfer.sh >> $LOGS
curl -k -w "\n" --upload-file ${TRAVIS_BUILD_DIR}/systemd_journal.txt https://transfer.sh >> $LOGS
curl -k -w "\n" --upload-file ${TRAVIS_BUILD_DIR}/var_log.tar https://transfer.sh >> $LOGS
curl -k -w "\n" --upload-file ${IPA_TEST_LOG} https://transfer.sh >> $LOGS

cat $LOGS

exit $exit_status
