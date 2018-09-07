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
set -e



function truncate_log_to_test_failures() {
    # chop off everything in the CI_RESULTS_LOG preceding pytest error output
    # if there are pytest errors in the log
    error_fail_regexp='\(=== ERRORS ===\)\|\(=== FAILURES ===\)'

    if grep -e "$error_fail_regexp" $CI_RESULTS_LOG > /dev/null
    then
        sed -i "/$error_fail_regexp/,\$!d" $CI_RESULTS_LOG
    fi
}


if [[ "$TASK_TO_RUN" == "ipa-test" ]]
then
    # 1. Base image is already available. No need to pull again

    # 2. Setup IPA environment
    docker exec -i ${CONTAINER} ${SCRIPTDIR}/ipa_test_setup.sh

    # 3. Install recently built dogtag RPMS
    docker exec -i ${CONTAINER} ${SCRIPTDIR}/20-install-rpms || exit $?

    # 4. Run IPA tests
    docker exec -i ${CONTAINER} ${SCRIPTDIR}/ipa_run_test.sh || exit $?

elif [[ "$TASK_TO_RUN" == "pki-test" ]]
then
   # First install pki-core packges as it's the dependency for other packages
   docker exec -i ${CONTAINER} ${SCRIPTDIR}/20-install-rpms || exit $?

   # Install deps, generate RPMS for all other packages and install them (in order)
   docker exec -i ${CONTAINER} ${SCRIPTDIR}/01-install-dependencies dogtag-pki-theme   # meta
   docker exec -i ${CONTAINER} ${SCRIPTDIR}/01-install-dependencies pki-console
   docker exec -i ${CONTAINER} ${SCRIPTDIR}/01-install-dependencies dogtag-pki

   docker exec -i ${CONTAINER} ${SCRIPTDIR}/10-compose-rpms compose_dogtag_pki_theme_packages
   docker exec -i ${CONTAINER} ${SCRIPTDIR}/20-install-rpms || exit $?

   docker exec -i ${CONTAINER} ${SCRIPTDIR}/10-compose-rpms compose_pki_console_packages
   docker exec -i ${CONTAINER} ${SCRIPTDIR}/20-install-rpms || exit $?

   docker exec -i ${CONTAINER} ${SCRIPTDIR}/10-compose-rpms compose_dogtag_pki_meta_packages
   docker exec -i ${CONTAINER} ${SCRIPTDIR}/20-install-rpms || exit $?

   docker exec -i ${CONTAINER} ${SCRIPTDIR}/30-setup-389ds
   # Test whether pki subsystem works correctly
   docker exec -i ${CONTAINER} ${SCRIPTDIR}/40-spawn-ca
   docker exec -i ${CONTAINER} ${SCRIPTDIR}/50-spawn-kra
   docker exec -i ${CONTAINER} ${SCRIPTDIR}/99-destroy

   # Python 3 tests are removed as it only needs to be tested against F28+
fi



exit_status="$?"

if [[ "$exit_status" -ne 0 && "$TASK_TO_RUN" == "ipa-test" ]]
then
    truncate_log_to_test_failures
fi

exit $exit_status
