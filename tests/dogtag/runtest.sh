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
. ./topologies.sh
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
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-ca.sh
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
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-profile-find-ca.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-profile-show-ca.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-review-ca.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-find-ca.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-find-ca.sh
. ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-add-ca.sh
. ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-show-ca.sh
. ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-find-ca.sh
. ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-mod-ca.sh
. ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-del-ca.sh
. ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-member-add-ca.sh
. ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-member-find-ca.sh
. ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-member-del-ca.sh
. ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-member-show-ca.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-add.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-show.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-find.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-del.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-membership-add.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-membership-find.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-membership-del.sh

PACKAGE="pki-tools"

# Make sure TESTORDER is initialized or multihost may have issues
TESTORDER=1
dir1="/opt/rhqa_pki/CodeCoveragePKIhtml"
cmd1="python -m SimpleHTTPServer"
dir2="/opt/rhqa_pki/"
cmd2="ant report"

if   [ $(echo "$MASTER" | grep $(hostname -s)|wc -l) -gt 0 ]; then
        MYROLE=MASTER
elif [ $(echo "$CLONE1"  | grep $(hostname -s)|wc -l) -gt 0 ]; then
        MYROLE=CLONE1
elif [ $(echo "$CLONE2" | grep $(hostname -s)|wc -l) -gt 0 ]; then
        MYROLE=CLONE2
elif [ $(echo "$SUBCA1" | grep $(hostname -s)|wc -l) -gt 0 ]; then
        MYROLE=SUBCA1
elif [ $(echo "$SUBCA2" | grep $(hostname -s)| wc -l) -gt 0 ]; then
        MYROLE=SUBCA2
else
        MYROLE=UNKNOWN
fi

rlJournalStart
    rlPhaseStartSetup "list files in /opt/rhqa_pki"
	rlRun "ls /opt/rhqa_pki" 0 "Listing files in /opt/rhqa_pki"
        rlRun "env|sort"
    rlPhaseEnd

    rlPhaseStartSetup "RHCS tests"
	#Execute pki user config tests
	TEST_ALL_UPPERCASE=$(echo $TEST_ALL | tr [a-z] [A-Z])
	QUICKINSTALL_UPPERCASE=$(echo $QUICKINSTALL | tr [a-z] [A-Z])
	TOPO1_UPPERCASE=$(echo $TOPO1 | tr [a-z] [A-Z])
	TOPO2_UPPERCASE=$(echo $TOPO2 | tr [a-z] [A-Z])
	TOPO3_UPPERCASE=$(echo $TOPO3 | tr [a-z] [A-Z])
	TOPO4_UPPERCASE=$(echo $TOPO4 | tr [a-z] [A-Z])
	TOPO5_UPPERCASE=$(echo $TOPO5 | tr [a-z] [A-Z])
	TOPO6_UPPERCASE=$(echo $TOPO6 | tr [a-z] [A-Z])
	TOPO7_UPPERCASE=$(echo $TOPO7 | tr [a-z] [A-Z])
	TOPO8_UPPERCASE=$(echo $TOPO8 | tr [a-z] [A-Z])
	
        if [ "$QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
		  run_rhcs_set_time 
                  run_rhcs_install_set_vars
                  run_rhcs_install_quickinstall
		  #Set-up role users
		  run_pki-user-cli-user-ca_tests
        elif [ "$TOPO1_UPPERCASE" = "TRUE" ]; then
                run_rhcs_install_set_vars
                run_rhcs_install_default
        elif [ "$TOPO2_UPPERCASE" = "TRUE" ]; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_1
        elif [ "$TOPO3_UPPERCASE" = "TRUE" ]; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_2
        elif [ "$TOPO4_UPPERCASE" = "TRUE" ]; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_3
        elif [ "$TOPO5_UPPERCASE" = "TRUE" ]; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_4
        elif [ "$TOPO6_UPPERCASE" = "TRUE" ]; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_5
        elif [ "$TOPO7_UPPERCASE" = "TRUE" ]; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_6
        elif [ "$TOPO8_UPPERCASE" = "TRUE" ]; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_7
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
		  run_pki-user-cli-user-cert-delete-ca_tests
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
		  run_pki-user-cert
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
	PKI_CA_USER_UPPERCASE=$(echo $PKI_CA_USER | tr [a-z] [A-Z])
        if [ "$PKI_CA_USER_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user tests
                  run_pki-ca-user-cli-ca-user-add_tests
                  run_pki-ca-user-cli-ca-user-show_tests
                  run_pki-ca-user-cli-ca-user-find_tests
                  run_pki-ca-user-cli-ca-user-del_tests
                  run_pki-ca-user-cli-ca-user-membership-add_tests
                  run_pki-ca-user-cli-ca-user-membership-find_tests
                  run_pki-ca-user-cli-ca-user-membership-del_tests
        fi
        CA_USER_ADD_UPPERCASE=$(echo $CA_USER_ADD | tr [a-z] [A-Z])
        if [ "$CA_USER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-add tests
                  run_pki-ca-user-cli-ca-user-add_tests
        fi
        CA_USER_SHOW_UPPERCASE=$(echo $CA_USER_SHOW | tr [a-z] [A-Z])
        if [ "$CA_USER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-show tests
                  run_pki-ca-user-cli-ca-user-show_tests
        fi
        CA_USER_FIND_UPPERCASE=$(echo $CA_USER_FIND | tr [a-z] [A-Z])
        if [ "$CA_USER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-find-ca tests
                  run_pki-ca-user-cli-ca-user-find_tests
        fi
        CA_USER_DEL_UPPERCASE=$(echo $CA_USER_DEL | tr [a-z] [A-Z])
        if [ "$CA_USER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-del tests
                  run_pki-ca-user-cli-ca-user-del_tests
        fi
        CA_USER_MEMBERSHIP_ADD_UPPERCASE=$(echo $CA_USER_MEMBERSHIP_ADD | tr [a-z] [A-Z])
        if [ "$CA_USER_MEMBERSHIP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-membership-add tests
                  run_pki-ca-user-cli-ca-user-membership-add_tests
        fi
	CA_USER_MEMBERSHIP_FIND_UPPERCASE=$(echo $CA_USER_MEMBERSHIP_FIND | tr [a-z] [A-Z])
        if [ "$CA_USER_MEMBERSHIP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-membership-find tests
                  run_pki-ca-user-cli-ca-user-membership-find_tests
        fi
        CA_USER_MEMBERSHIP_DEL_UPPERCASE=$(echo $CA_USER_MEMBERSHIP_DEL | tr [a-z] [A-Z])
        if [ "$CA_USER_MEMBERSHIP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-membership-del tests
                  run_pki-ca-user-cli-ca-user-membership-del_tests
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
		 run_pki-cert-request-submit_tests
		 run_pki-cert-request-profile-find-ca_tests
		 run_pki-cert-request-profile-show-ca_tests
		 run_pki-cert-request-review-ca_tests
		 run_pki-cert-request-find-ca_tests
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
        CERT_REQUEST_PROFILE_FIND_CA_UPPERCASE=$(echo $CERT_REQUEST_PROFILE_FIND_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_PROFILE_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-profile-find tests
                  run_pki-cert-request-profile-find-ca_tests
        fi
        CERT_REQUEST_PROFILE_SHOW_CA_UPPERCASE=$(echo $CERT_REQUEST_PROFILE_SHOW_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_PROFILE_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-profile-show tests
                  run_pki-cert-request-profile-show-ca_tests
        fi
        CERT_REQUEST_REVIEW_CA_UPPERCASE=$(echo $CERT_REQUEST_REVIEW_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_REVIEW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-review tests
                  run_pki-cert-request-review-ca_tests
        fi
        CERT_REQUEST_FIND_CA_UPPERCASE=$(echo $CERT_REQUEST_FIND_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-find tests
                  run_pki-cert-request-find-ca_tests
        fi
        CERT_FIND_CA_UPPERCASE=$(echo $CERT_FIND_CA | tr [a-z] [A-Z])
        if [ "$CERT_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-find tests
                  run_pki-cert-find-ca_tests
        fi
	GROUP_ADD_UPPERCASE=$(echo $GROUP_ADD | tr [a-z] [A-Z])
        if [ "$GROUP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-add-ca tests
		  run_pki-group-cli-group-add-ca_tests
        fi
	GROUP_SHOW_UPPERCASE=$(echo $GROUP_SHOW | tr [a-z] [A-Z])
        if [ "$GROUP_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-show-ca tests
                  run_pki-group-cli-group-show-ca_tests
        fi
	GROUP_FIND_UPPERCASE=$(echo $GROUP_FIND | tr [a-z] [A-Z])
        if [ "$GROUP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-find-ca tests
                  run_pki-group-cli-group-find-ca_tests
        fi
	GROUP_MOD_UPPERCASE=$(echo $GROUP_MOD | tr [a-z] [A-Z])
        if [ "$GROUP_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-mod-ca tests
                  run_pki-group-cli-group-mod-ca_tests
        fi
	GROUP_DEL_UPPERCASE=$(echo $GROUP_DEL | tr [a-z] [A-Z])
        if [ "$GROUP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-del-ca tests
                  run_pki-group-cli-group-del-ca_tests
        fi
	GROUP_MEMBER_ADD_UPPERCASE=$(echo $GROUP_MEMBER_ADD | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-add-ca tests
                  run_pki-group-cli-group-member-add-ca_tests
        fi
	GROUP_MEMBER_FIND_UPPERCASE=$(echo $GROUP_MEMBER_FIND | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-find-ca tests
                  run_pki-group-cli-group-member-find-ca_tests
        fi
	GROUP_MEMBER_DEL_UPPERCASE=$(echo $GROUP_MEMBER_DEL | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-del-ca tests
                  run_pki-group-cli-group-member-del-ca_tests
        fi
	GROUP_MEMBER_SHOW_UPPERCASE=$(echo $GROUP_MEMBER_SHOW | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-show-ca tests
                  run_pki-group-cli-group-member-show-ca_tests
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
