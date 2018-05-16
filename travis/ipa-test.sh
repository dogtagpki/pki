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
IPA_TEST_LOG="ipa-test.log"

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
    --developer-mode \
    --container-environment "PYTHON=$PYTHON" \
    --container-image ${BASE_IMAGE} \
    --git-repo ${TRAVIS_BUILD_DIR} \
    run-tests ${cert_test_file_loc}


exit_status="$?"

if [[ "$exit_status" -ne 0 ]]
then
    truncate_log_to_test_failures
fi

curl -w "\n" --upload-file ${IPA_TEST_LOG} https://transfer.sh/ipa-test.txt >> logs.txt

exit $exit_status
