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
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#

PYTHON="/usr/bin/python${TRAVIS_PYTHON_VERSION}"
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
TEST_RUNNER_IMAGE="mkd27/dogtag-freeipa-integration"
TEST_RUNNER_CONFIG=".test_runner_config.yaml"

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD

=======
CI_RESULTS_LOG="ci_results_${TRAVIS_BRANCH}.log"
>>>>>>> 4ef1f9c... transferring logs to transfer.sh

=======
TEST_RUNNER_IMAGE="dogtagpki/dogtag-freeipa-ci-containers:f25"
TEST_RUNNER_CONFIG=".test_runner_config.yaml"
>>>>>>> ee53f14... Uses official repo for Docker image
TASK_TO_RUN=run-tests

test_set="test_caacl_plugin.py test_caacl_profile_enforcement.py test_cert_plugin.py test_certprofile_plugin.py test_vault_plugin.py"
developer_mode_opt="--developer-mode"
cert_test_file_loc=""

=======

# IPA related variables
=======
>>>>>>> 2649e0d... Corrected the repo path to copy dogtag rpms to the mounted dir
TEST_RUNNER_IMAGE="martbab/freeipa-fedora-test-runner:master-latest"
=======
TEST_RUNNER_IMAGE="mkd27/dogtag-freeipa-integration"
>>>>>>> 4faa50d... Everything works fine except the vault_test. Requires code cleaning
TEST_RUNNER_CONFIG=".test_runner_config.yaml"

CI_RESULTS_LOG="ci_results_${TRAVIS_BRANCH}.log"
=======
>>>>>>> 3c27187... transferring logs to transfer.sh
=======

>>>>>>> 919fb90... Cleaned the code

TASK_TO_RUN=run-tests

test_set="test_caacl_plugin.py test_caacl_profile_enforcement.py test_cert_plugin.py test_certprofile_plugin.py test_vault_plugin.py"
developer_mode_opt="--developer-mode"
>>>>>>> 6e130a2... Configured to run IPA cert tests

cert_test_file_loc=""
#REMOVE THIS!!!!
#TRAVIS_BUILD_DIR="/home/dmoluguw/work/pki"


function truncate_log_to_test_failures() {
    # chop off everything in the CI_RESULTS_LOG preceding pytest error output
    # if there are pytest errors in the log
    error_fail_regexp='\(=== ERRORS ===\)\|\(=== FAILURES ===\)'

    if grep -e "$error_fail_regexp" $CI_RESULTS_LOG > /dev/null
    then
        sed -i "/$error_fail_regexp/,\$!d" $CI_RESULTS_LOG
    fi
}

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD


docker pull $TEST_RUNNER_IMAGE
<<<<<<< HEAD
echo ${TRAVIS_BUILD_DIR}
<<<<<<< HEAD

<<<<<<< HEAD
for test_files in ${test_set}; do
    cert_test_file_loc="${cert_test_file_loc} test_xmlrpc/${test_files}"
done

echo ${cert_test_file_loc}

ipa-docker-test-runner -l ${CI_RESULTS_LOG} \
    -c ${TEST_RUNNER_CONFIG} \
    $developer_mode_opt \
    --container-environment "PYTHON=$PYTHON" \
    --container-image ${TEST_RUNNER_IMAGE} \
    --git-repo ${TRAVIS_BUILD_DIR} \
    ${TASK_TO_RUN} ${cert_test_file_loc}

=======
=======


>>>>>>> 2649e0d... Corrected the repo path to copy dogtag rpms to the mounted dir
=======
>>>>>>> ee53f14... Uses official repo for Docker image
docker pull $TEST_RUNNER_IMAGE

<<<<<<< HEAD
ipa-docker-test-runner -l $CI_RESULTS_LOG \
=======
ipa-docker-test-runner 
>>>>>>> c75c4af... Added logs to spew on the log
    -c $TEST_RUNNER_CONFIG \
    $developer_mode_opt \
    --container-environment "PYTHON=$PYTHON" \
    --container-image $TEST_RUNNER_IMAGE \
    --git-repo $TRAVIS_BUILD_DIR \
    $TASK_TO_RUN $test_set
>>>>>>> 6e130a2... Configured to run IPA cert tests
=======
echo ${TEST_RUNNER_CONFIG}
echo ${developer_mode_opt}
echo ${TEST_RUNNER_IMAGE}
ls ${DOGTAG_PKI_RPMS}
echo ${DOGTAG_PKI_RPMS}
=======
>>>>>>> a18a797... Added correct configuration to setup ipa-server and ipa-kra using separate commands
=======
for test_files in ${test_set}; do
    cert_test_file_loc="${cert_test_file_loc} test_xmlrpc/${test_files}"
done

echo ${cert_test_file_loc}
>>>>>>> 4faa50d... Everything works fine except the vault_test. Requires code cleaning

ipa-docker-test-runner -l ${CI_RESULTS_LOG} \
    -c ${TEST_RUNNER_CONFIG} \
    $developer_mode_opt \
    --container-environment "PYTHON=$PYTHON" \
    --container-image ${TEST_RUNNER_IMAGE} \
    --git-repo ${TRAVIS_BUILD_DIR} \
    ${TASK_TO_RUN} ${cert_test_file_loc}

<<<<<<< HEAD
<<<<<<< HEAD
>>>>>>> 8c430ea... fixed the command to run

=======
echo "Uploading CI Logs to transfer.sh ..."
curl --upload-file ./${CI_RESULTS_LOG} https://transfer.sh/freeipa-integration.txt 
>>>>>>> 4ef1f9c... transferring logs to transfer.sh
=======
>>>>>>> 7ac2572... Fixed transfer.sh url

exit_status="$?"

if [[ "$exit_status" -ne 0 ]]
then
    truncate_log_to_test_failures
fi

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD


exit $exit_status

=======
=======
echo "Uploading CI Logs to transfer.sh ..."
curl --upload-file ./${CI_RESULTS_LOG} https://transfer.sh/freeipa-integration.txt 
=======

>>>>>>> 919fb90... Cleaned the code

>>>>>>> 7ac2572... Fixed transfer.sh url
=======
>>>>>>> ee53f14... Uses official repo for Docker image
exit $exit_status
<<<<<<< HEAD
>>>>>>> 6e130a2... Configured to run IPA cert tests
=======

>>>>>>> 2649e0d... Corrected the repo path to copy dogtag rpms to the mounted dir
