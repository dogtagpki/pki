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
. /opt/rhqa_pki/saving_codecoverage_results.sh

# Include tests

#. ./acceptance/quickinstall/rhcs-set-time.sh
. ./acceptance/quickinstall/rhcs-set-time.sh
. ./acceptance/quickinstall/rhcs-install.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-add-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-show-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-mod-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-find-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-del-ca.sh
. ./dev_java_tests/run_junit_tests.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-membership-add-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-membership-find-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-membership-del-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-find-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-add-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-show-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-delete-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cleanup-ca.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-show.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-request-show.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-bigInt.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-revoke.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-release-hold.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-hold.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-submit-ca.sh

PACKAGE="pki-tools"

# Make sure TESTORDER is initialized or multihost may have issues
TESTORDER=1
dir1="/opt/rhqa_pki/CodeCoveragePKIhtml"
cmd1="python -m SimpleHTTPServer"
dir2="/opt/rhqa_pki/"
cmd2="ant report"

rlJournalStart
    rlPhaseStartSetup "list files in /opt/rhqa_pki"
	rlRun "ls /opt/rhqa_pki" 0 "Listing files in /opt/rhqa_pki"
	rlRun "export MASTER=`hostname`"
        rlRun "env|sort"
    rlPhaseEnd

    rlPhaseStartSetup "RHCS tests"
	#Execute pki user config tests
	TEST_ALL_UPPERCASE=$(echo $TEST_ALL | tr [a-z] [A-Z])
	QUICKINSTALL_UPPERCASE=$(echo $QUICKINSTALL | tr [a-z] [A-Z])
        if [ "$QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
		  run_rhcs_set_time 
                  run_rhcs_install_subsystems
		  run_pki-user-cli-user-ca_tests
        fi
	PKI_USER_CA_UPPERCASE=$(echo $PKI_USER_CA | tr [a-z] [A-Z])
        if [ "$PKI_USER_CA_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-ca tests
                  run_pki-user-cli-user-add-ca_tests
                  run_pki-user-cli-user-show-ca_tests
                  run_pki-user-cli-user-mod-ca_tests
                  run_pki-user-cli-user-find-ca_tests
                  run_pki-user-cli-user-del-ca_tests
                  run_pki-user-cli-user-membership-add-ca_tests
                  run_pki-user-cli-user-membership-find-ca_tests
                  run_pki-user-cli-user-membership-del-ca_tests
                  run_pki-user-cli-user-cert-add-ca_tests
                  run_pki-user-cli-user-cert-find-ca_tests
                  run_pki-user-cli-user-cert-show-ca_tests
        fi
	USER_ADD_CA_UPPERCASE=$(echo $USER_ADD_CA | tr [a-z] [A-Z])
        if [ "$USER_ADD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-ca tests
                  run_pki-user-cli-user-add-ca_tests
        fi
	USER_SHOW_CA_UPPERCASE=$(echo $USER_SHOW_CA | tr [a-z] [A-Z])
        if [ "$USER_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-show-ca tests
                  run_pki-user-cli-user-show-ca_tests
        fi
	USER_MOD_CA_UPPERCASE=$(echo $USER_MOD_CA | tr [a-z] [A-Z])
	if [ "$USER_MOD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-mod-ca tests
                  run_pki-user-cli-user-mod-ca_tests
	fi
	USER_FIND_CA_UPPERCASE=$(echo $USER_FIND_CA | tr [a-z] [A-Z])
        if [ "$USER_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-find-ca tests
		  run_pki-user-cli-user-find-ca_tests
        fi
	USER_DEL_CA_UPPERCASE=$(echo $USER_DEL_CA | tr [a-z] [A-Z])
        if [ "$USER_DEL_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-del-ca tests
		  run_pki-user-cli-user-del-ca_tests
        fi
	USER_MEMBERSHIP_ADD_CA_UPPERCASE=$(echo $USER_MEMBERSHIP_ADD_CA | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_ADD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-add-ca tests
                  run_pki-user-cli-user-membership-add-ca_tests
        fi
        USER_MEMBERSHIP_FIND_CA_UPPERCASE=$(echo $USER_MEMBERSHIP_FIND_CA | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-find-ca tests
                  run_pki-user-cli-user-membership-find-ca_tests
        fi
        USER_MEMBERSHIP_DEL_CA_UPPERCASE=$(echo $USER_MEMBERSHIP_DEL_CA | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_DEL_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-del-ca tests
                  run_pki-user-cli-user-membership-del-ca_tests
        fi
	USER_CERT_ADD_CA_UPPERCASE=$(echo $USER_CERT_ADD_CA | tr [a-z] [A-Z])
        if [ "$USER_CERT_ADD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-add-ca tests
                  run_pki-user-cli-user-cert-add-ca_tests
        fi
        USER_CERT_FIND_CA_UPPERCASE=$(echo $USER_CERT_FIND_CA | tr [a-z] [A-Z])
        if [ "$USER_CERT_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-find-ca tests
                  run_pki-user-cli-user-cert-find-ca_tests
        fi
        USER_CERT_SHOW_CA_UPPERCASE=$(echo $USER_CERT_SHOW_CA | tr [a-z] [A-Z])
        if [ "$USER_CERT_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-show-ca tests
                  run_pki-user-cli-user-cert-show-ca_tests
        fi
	USER_CERT_DEL_CA_UPPERCASE=$(echo $USER_CERT_DEL_CA | tr [a-z] [A-Z])
        if [ "$USER_CERT_DEL_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-del-ca tests
                  run_pki-user-cli-user-cert-delete-ca_tests
        fi
        CERT_CONFIG_CA_UPPERCASE=$(echo $CERT_CONFIG_CA | tr [a-z] [A-Z])
        if [ "$CERT_CONFIG_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert tests
                  run_pki-cert-ca_tests
        fi
        CERT_SHOW_CA_UPPERCASE=$(echo $CERT_SHOW_CA | tr [a-z] [A-Z])
        if [ "$CERT_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-show tests
                  run_pki-cert-show-ca_tests
        fi
        CERT_REQUEST_SHOW_CA_UPPERCASE=$(echo $CERT_REQUEST_SHOW_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-show tests
                  run_pki-cert-request-show-ca_tests
        fi
        CERT_REVOKE_CA_UPPERCASE=$(echo $CERT_REVOKE_CA | tr [a-z] [A-Z])
        if [ "$CERT_REVOKE_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-revoke tests
                  run_pki-cert-revoke-ca_tests
        fi
        CERT_RELEASE_HOLD_CA_UPPERCASE=$(echo $CERT_RELEASE_HOLD_CA | tr [a-z] [A-Z])
        if [ "$CERT_RELEASE_HOLD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-release-hold tests
                  run_pki-cert-release-hold-ca_tests
        fi
        CERT_HOLD_CA_UPPERCASE=$(echo $CERT_HOLD_CA | tr [a-z] [A-Z])
        if [ "$CERT_HOLD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-hold tests
                  run_pki-cert-hold-ca_tests
        fi
	CERT_REQUEST_SUBMIT_CA_UPPERCASE=$(echo $CERT_REQUEST_SUBMIT_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_SUBMIT_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-hold tests
                  run_pki-cert-request-submit_tests
        fi
	CERT_TEST_UPPERCASE=$(echo $CERT_TEST | tr [a-z] [A-Z])
	if [ "$CERT_TEST_UPPERCASE" = "TRUE" ] ; then
		#Execute pki cert tests
		 run_pki-cert-ca_tests
		 run_pki-cert-revoke-ca_tests
		 run_pki-cert-show-ca_tests
		 run_pki-cert-request-show-ca_tests
		 run_pki-cert-release-hold-ca_tests
		 run_pki-cert-hold-ca_tests
	fi
	BIG_INT_UPPERCASE=$(echo $BIG_INT | tr [a-z] [A-Z])
	if [ "$BIG_INT_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		#Execute pki bigInt tests
		run_pki_big_int
		run_pki_cert
		run_pki_cert_show
		run_pki_cert_request_show
	fi
	USER_CLEANUP_CA_UPPERCASE=$(echo $USER_CLEANUP_CA | tr [a-z] [A-Z])
        #Clean up role users (admin agent etc) created in CA
        if [ "$USER_CLEANUP_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cleanup-ca tests
                  run_pki-user-cli-user-cleanup-ca_tests
	fi
        rlPhaseEnd

	DEV_JAVA_TESTS_UPPERCASE=$(echo $DEV_JAVA_TESTS | tr [a-z] [A-Z])
        if [ "$DEV_JAVA_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
        rlPhaseStartSetup "Dev Tests"
             run_dev_junit_tests
        rlPhaseEnd
        fi

	CODE_COVERAGE_UPPERCASE=$(echo $CODE_COVERAGE | tr [a-z] [A-Z])
	if [ $CODE_COVERAGE_UPPERCASE = "TRUE" ] ; then
	        rlPhaseStartSetup "JACOCO Code coverage report"
        	        rlRun "cp /tmp/jacoco.exec /opt/rhqa_pki/."
                	rlLog "ant task to create a report"
	                rlRun "cd $dir2 && $cmd2"
                	rlLog "Jacoco coverage report stored locally on $HOSTNAME can be viewed at http://$HOSTNAME:8000/"
	                rlRun "screen -d -m sh -c 'cd $dir1 ; $cmd1'"
			#Archive the codecoverage results 
			if [ "$ARCHIVELOCATIONSERVER" != "" ] ; then
				rlLog "Archiving results to $ARCHIVELOCATIONSERVER"
				rlRun "backupCodeCoverageResults $dir1"
			fi
        	rlPhaseEnd
	fi
    rlJournalPrintText
    report=/tmp/rhts.report.$RANDOM.txt
    makereport $report
    rhts-submit-log -l $report
rlJournalEnd

