#!/bin/bash
#
# Copyright (C) 2017 FreeIPA Contributors see COPYING for license
#
# NOTE: this script is intended to run in Travis CI only

PYTHON="/usr/bin/python${TRAVIS_PYTHON_VERSION}"
TEST_RUNNER_IMAGE="mkd27/dogtag-freeipa-integration"
TEST_RUNNER_CONFIG=".test_runner_config.yaml"



TASK_TO_RUN=run-tests

test_set="test_caacl_plugin.py test_caacl_profile_enforcement.py test_cert_plugin.py test_certprofile_plugin.py test_vault_plugin.py"
developer_mode_opt="--developer-mode"

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



docker pull $TEST_RUNNER_IMAGE

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


exit_status="$?"

if [[ "$exit_status" -ne 0 ]]
then
    truncate_log_to_test_failures
fi



exit $exit_status

