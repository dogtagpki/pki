#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/PKI_TEST_USER_ID
#   Description: Dogtag-10/CS-9 testing
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Libraries Included:
#	rhcs-shared.sh pki-user-cli-lib.sh rhcs-install-shared.sh
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2013 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/rhcs-install-shared.sh
. /opt/rhqa_pki/pki-user-cli-lib.sh
. /opt/rhqa_pki/env.sh

# Include tests
. ./acceptance/quickinstall/rhcs-install.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-add-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-show-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-find-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-del-ca.sh
. ./dev_java_tests/run_junit_tests.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-membership-add-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-membership-find-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-membership-del-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cleanup-ca.sh

PACKAGE="pki-tools"

# Make sure TESTORDER is initialized or multihost may have issues
TESTORDER=1
dir1="/opt/rhqa_pki/CodeCoveragePKIhtml"
cmd1="python -m SimpleHTTPServer"
dir2="/opt/rhqa_pki/"
cmd2="ant report"

rlJournalStart
    rlPhaseStartSetup "list files in /opt/rhqa_pki and begin code coverage"
	rlRun "ls /opt/rhqa_pki" 0 "Listing files in /opt/rhqa_pki"
	rlRun "export MASTER=`hostname`"
        rlRun "env|sort"
    rlPhaseEnd

    rlPhaseStartSetup "RHCS tests"
	#Execute pki user config tests
        if [ "$QUICKINSTALL" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                  run_rhcs_install_subsystems
		  run_pki-user-cli-user-ca_tests
        fi
        if [ "$USER_ADD_CA" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                # Execute pki user-add-ca tests
                  run_pki-user-cli-user-add-ca_tests
        fi
        if [ "$USER_SHOW_CA" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                # Execute pki user-show-ca tests
                  run_pki-user-cli-user-show-ca_tests
        fi
        if [ "$USER_FIND_CA" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                # Execute pki user-find-ca tests
		  run_pki-user-cli-user-find-ca_tests
        fi
        if [ "$USER_DEL_CA" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                # Execute pki user-del-ca tests
		  run_pki-user-cli-user-del-ca_tests
        fi
	if [ "$USER_MEM_ADD_CA" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                # Execute pki user-mem-add-ca tests
                  run_pki-user-cli-user-membership-add-ca_tests
        fi
	if [ "$USER_MEM_FIND_CA" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                # Execute pki user-mem-find-ca tests
                  run_pki-user-cli-user-membership-find-ca_tests
        fi
        if [ "$USER_MEM_DEL_CA" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                # Execute pki user-mem-del-ca tests
                  run_pki-user-cli-user-membership-del-ca_tests
        fi
        #Clean up role users (admin agent etc) created in CA
        if [ "$USER_CLEANUP_CA" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                # Execute pki user-cleanup-ca tests
                  run_pki-user-cli-user-cleanup-ca_tests
        fi
        rlPhaseEnd

        if [ "$DEV_JAVA_TESTS" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
        rlPhaseStartSetup "Dev Tests"
             run_dev_junit_tests
        rlPhaseEnd
        fi

    if [ $CODE_COVERAGE = "TRUE" ] ; then
        rlPhaseStartSetup "JACOCO Code coverage report"
                rlRun "cp /tmp/jacoco.exec /opt/rhqa_pki/."
                rlLog "ant task to create a report"
                rlRun "cd $dir2 && $cmd2"
                rlRun "ls /opt/rhqa_pki" 0 "Listing files in /opt/rhqa_pki"
                rlLog "Jacoco coverage report can be viewed at http://`hostname`:8000/"
                rlRun "screen -d -m sh -c 'cd $dir1 ; $cmd1'"
		rhts-submit-log -l $dir1
        rlPhaseEnd
    fi
    rlJournalPrintText
    report=/tmp/rhts.report.$RANDOM.txt
    makereport $report
    rhts-submit-log -l $report
rlJournalEnd
