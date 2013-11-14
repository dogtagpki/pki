#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/PKI_TEST_USER_ID
#   Description: CS testing
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Libraries Included:
#	rhcs-shared.sh
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Laxmi Sunkara <lsunkara@redhat.com>
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

PACKAGE="pki-tools"

# Make sure TESTORDER is initialized or multihost may have issues
TESTORDER=1
rlJournalStart
    rlPhaseStartSetup "list files in /opt/rhqa_pki"
	rlRun "ls /opt/rhqa_pki" 0 "Listing files in /opt/rhqa_pki"
	rlRun "export MASTER=`hostname`"
        rlRun "env|sort"
    rlPhaseEnd

    rlPhaseStartSetup "RHCS tests"
	#Execute pki user config tests
        if [ "$QUICKINSTALL" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                  run_rhcs_install_subsystems
        fi
        if [ "$USER_ADD_CA" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                # Execute pki user-add-ca tests
		  run_pki-user-cli-user-ca_tests
                  run_pki-user-cli-user-add-ca_tests
        fi
        if [ "$USER_SHOW_CA" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                # Execute pki user-show-ca tests
                  run_pki-user-cli-user-ca_tests
                  run_pki-user-cli-user-show-ca_tests
        fi
        if [ "$USER_FIND_CA" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                # Execute pki user-find-ca tests
                  run_pki-user-cli-user-ca_tests
		  run_pki-user-cli-user-find-ca_tests
        fi
        if [ "$USER_DEL_CA" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
                # Execute pki user-del-ca tests
	          run_pki-user-cli-user-ca_tests
		  run_pki-user-cli-user-del-ca_tests

        fi
    rlPhaseEnd

    if [ "$DEV_JAVA_TESTS" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
        rlPhaseStartSetup "Dev Tests"
             run_dev_junit_tests
        rlPhaseEnd
    fi

    rlJournalPrintText
    report=/tmp/rhts.report.$RANDOM.txt
    makereport $report
    rhts-submit-log -l $report
rlJournalEnd
