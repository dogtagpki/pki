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
. ./acceptance/quickinstall/rhcs-set-time.sh
. ./acceptance/quickinstall/rhcs-install.sh
. ./acceptance/cli-tests/pki-tests-setup/create-role-users.sh
. ./acceptance/cli-tests/pki-tests-setup/cleanup-role-users.sh
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
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-cert-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-show-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-show-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-revoke-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-release-hold-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-cert-hold-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-submit-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-profile-find-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-show-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-review-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-find-ca.sh 
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-find-ca.sh
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
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-mod.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert-add.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert-find.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert-show.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert-delete.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-add.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-mod.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-find.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-show.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-del.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-add.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-show.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-find.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-del.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-generate-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-find-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-template-find-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-template-show-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-request-find-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-show-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-request-show-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-mod-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-archive-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-recover-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-retrieve-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-request-review-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-generate-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-find-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-template-show-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-template-find-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-request-find-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-show-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-request-show-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-mod-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-archive-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-recover-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-retrieve-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-request-review-kra.sh
. ./acceptance/bugzilla/tomcatjss-bugs.sh
. ./acceptance/bugzilla/pki-core-bugs/giant-debug-log.sh
. ./acceptance/bugzilla/pki-core-bugs/CSbackup-bug.sh

# Make sure TESTORDER is initialized or multihost may have issues
TESTORDER=1
dir1="/opt/rhqa_pki/CodeCoveragePKIhtml"
cmd1="python -m SimpleHTTPServer"
dir2="/opt/rhqa_pki/"
cmd2="ant report"

if   [ $(echo "$MASTER" | grep $(hostname -s)|wc -l) -gt 0 ] ; then
        MYROLE=MASTER
elif [ $(echo "$CLONE1"  | grep $(hostname -s)|wc -l) -gt 0 ] ; then
        MYROLE=CLONE1
elif [ $(echo "$CLONE2" | grep $(hostname -s)|wc -l) -gt 0 ] ; then
        MYROLE=CLONE2
elif [ $(echo "$SUBCA1" | grep $(hostname -s)|wc -l) -gt 0 ] ; then
        MYROLE=SUBCA1
elif [ $(echo "$SUBCA2" | grep $(hostname -s)| wc -l) -gt 0 ] ; then
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

	get_topo_stack $MYROLE /tmp/topo_file
	CA_INST=$(cat /tmp/topo_file | grep MY_CA | cut -d= -f2)
	KRA_INST=$(cat /tmp/topo_file | grep MY_KRA | cut -d= -f2)
	OCSP_INST=$(cat /tmp/topo_file | grep MY_OCSP | cut -d= -f2)
        TKS_INST=$(cat /tmp/topo_file | grep MY_TKS | cut -d= -f2)

        if [ "$QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
		run_rhcs_set_time 
		run_rhcs_install_set_vars
		run_rhcs_install_quickinstall
		#Set-up role users
		get_topo_stack $MYROLE /tmp/topo_file
	        CA_INST=$(cat /tmp/topo_file | grep MY_CA | cut -d= -f2)
		rlLog "Subsystem ID CA=$CA_INST"
		run_pki-user-cli-role-user-create-tests $CA_INST ca $MYROLE
	        KRA_INST=$(cat /tmp/topo_file | grep MY_KRA | cut -d= -f2)
		rlLog "Subsystem ID KRA=$KRA_INST"
		run_pki-user-cli-role-user-create-tests $KRA_INST kra $MYROLE
		OCSP_INST=$(cat /tmp/topo_file | grep MY_OCSP | cut -d= -f2)
                rlLog "Subsystem ID OCSP=$OCSP_INST"
                run_pki-user-cli-role-user-create-tests $OCSP_INST ocsp $MYROLE
                TKS_INST=$(cat /tmp/topo_file | grep MY_TKS | cut -d= -f2)
                rlLog "Subsystem ID TKS=$TKS_INST"
                run_pki-user-cli-role-user-create-tests $TKS_INST tks $MYROLE
        elif [ "$TOPO1_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_1
        elif [ "$TOPO2_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_2
        elif [ "$TOPO3_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_3
        elif [ "$TOPO4_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_4
        elif [ "$TOPO5_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_5
        elif [ "$TOPO6_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_6
        elif [ "$TOPO7_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_7
        elif [ "$TOPO8_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_8
        fi
	
	######## PKI USER CA TESTS ############
	PKI_USER_CA_UPPERCASE=$(echo $PKI_USER_CA | tr [a-z] [A-Z])
        if [ "$PKI_USER_CA_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-add-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-show-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-mod-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-find-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-del-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-membership-add-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-membership-find-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-membership-del-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-cert-add-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-cert-find-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-cert-show-ca_tests $subsystemId $subsystemType $MYROLE
		  run_pki-user-cli-user-cert-delete-ca_tests $subsystemId $subsystemType $MYROLE
        fi
	USER_ADD_CA_UPPERCASE=$(echo $USER_ADD_CA | tr [a-z] [A-Z])
        if [ "$USER_ADD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-add-ca_tests $subsystemId $subsystemType $MYROLE
        fi
	USER_SHOW_CA_UPPERCASE=$(echo $USER_SHOW_CA | tr [a-z] [A-Z])
        if [ "$USER_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-show-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-show-ca_tests $subsystemId $subsystemType $MYROLE
        fi
	USER_MOD_CA_UPPERCASE=$(echo $USER_MOD_CA | tr [a-z] [A-Z])
	if [ "$USER_MOD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-mod-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-mod-ca_tests $subsystemId $subsystemType $MYROLE
	fi
	USER_FIND_CA_UPPERCASE=$(echo $USER_FIND_CA | tr [a-z] [A-Z])
        if [ "$USER_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-find-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
		  run_pki-user-cli-user-find-ca_tests $subsystemId $subsystemType $MYROLE
        fi
	USER_DEL_CA_UPPERCASE=$(echo $USER_DEL_CA | tr [a-z] [A-Z])
        if [ "$USER_DEL_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-del-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
		  run_pki-user-cli-user-del-ca_tests $subsystemId $subsystemType $MYROLE
        fi
	USER_MEMBERSHIP_ADD_CA_UPPERCASE=$(echo $USER_MEMBERSHIP_ADD_CA | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_ADD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-add-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-membership-add-ca_tests $subsystemId $subsystemType $MYROLE
        fi
        USER_MEMBERSHIP_FIND_CA_UPPERCASE=$(echo $USER_MEMBERSHIP_FIND_CA | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-find-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-membership-find-ca_tests $subsystemId $subsystemType $MYROLE
        fi
        USER_MEMBERSHIP_DEL_CA_UPPERCASE=$(echo $USER_MEMBERSHIP_DEL_CA | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_DEL_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-del-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-membership-del-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
	USER_CERT_ADD_CA_UPPERCASE=$(echo $USER_CERT_ADD_CA | tr [a-z] [A-Z])
        if [ "$USER_CERT_ADD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-add-ca tests 
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-cert-add-ca_tests  $subsystemId $subsystemType $MYROLE
		  run_pki-user-cert  $subsystemId $subsystemType $MYROLE
        fi
        USER_CERT_FIND_CA_UPPERCASE=$(echo $USER_CERT_FIND_CA | tr [a-z] [A-Z])
        if [ "$USER_CERT_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-find-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-cert-find-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
        USER_CERT_SHOW_CA_UPPERCASE=$(echo $USER_CERT_SHOW_CA | tr [a-z] [A-Z])
        if [ "$USER_CERT_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-show-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-cert-show-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
	USER_CERT_DEL_CA_UPPERCASE=$(echo $USER_CERT_DEL_CA | tr [a-z] [A-Z])
        if [ "$USER_CERT_DEL_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-del-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-cert-delete-ca_tests  $subsystemId $subsystemType $MYROLE
        fi

	######## PKI CA_USER TESTS ############
	PKI_CA_USER_UPPERCASE=$(echo $PKI_CA_USER | tr [a-z] [A-Z])
        if [ "$PKI_CA_USER_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-add_tests $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-show_tests $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-find_tests $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-del_tests $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-membership-add_tests $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-membership-find_tests $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-membership-del_tests $subsystemId $subsystemType $MYROLE
		  run_pki-ca-user-cli-ca-user-mod_tests  $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-user-cert-add_tests  $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-cert-find_tests  $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-cert-show_tests  $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-cert-delete_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_ADD_UPPERCASE=$(echo $CA_USER_ADD | tr [a-z] [A-Z])
        if [ "$CA_USER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-add tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-add_tests $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_SHOW_UPPERCASE=$(echo $CA_USER_SHOW | tr [a-z] [A-Z])
        if [ "$CA_USER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-show tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-show_tests $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_FIND_UPPERCASE=$(echo $CA_USER_FIND | tr [a-z] [A-Z])
        if [ "$CA_USER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-find-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-find_tests $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_DEL_UPPERCASE=$(echo $CA_USER_DEL | tr [a-z] [A-Z])
        if [ "$CA_USER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-del tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-del_tests $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_MEMBERSHIP_ADD_UPPERCASE=$(echo $CA_USER_MEMBERSHIP_ADD | tr [a-z] [A-Z])
        if [ "$CA_USER_MEMBERSHIP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-membership-add tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-membership-add_tests $subsystemId $subsystemType $MYROLE
        fi
	CA_USER_MEMBERSHIP_FIND_UPPERCASE=$(echo $CA_USER_MEMBERSHIP_FIND | tr [a-z] [A-Z])
        if [ "$CA_USER_MEMBERSHIP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-membership-find tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-membership-find_tests $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_MEMBERSHIP_DEL_UPPERCASE=$(echo $CA_USER_MEMBERSHIP_DEL | tr [a-z] [A-Z])
        if [ "$CA_USER_MEMBERSHIP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-membership-del tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-membership-del_tests $subsystemId $subsystemType $MYROLE
        fi
	CA_USER_MOD_UPPERCASE=$(echo $CA_USER_MOD | tr [a-z] [A-Z])
        if [ "$CA_USER_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-mod tests
                  subsystemId=$CA_INST
                subsystemType=ca
                  run_pki-ca-user-cli-ca-user-mod_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_CERT_ADD_UPPERCASE=$(echo $CA_USER_CERT_ADD | tr [a-z] [A-Z])
        if [ "$CA_USER_CERT_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-cert-add tests
                  subsystemId=$CA_INST
                subsystemType=ca
                  run_pki-ca-user-cli-user-cert-add_tests  $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cert  $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_CERT_FIND_UPPERCASE=$(echo $CA_USER_CERT_FIND | tr [a-z] [A-Z])
        if [ "$CA_USER_CERT_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-cert-find tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-user-cli-ca-user-cert-find_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_CERT_SHOW_UPPERCASE=$(echo $CA_USER_CERT_SHOW | tr [a-z] [A-Z])
        if [ "$CA_USER_CERT_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-cert-show tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-user-cli-ca-user-cert-show_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_CERT_DEL_UPPERCASE=$(echo $CA_USER_CERT_DEL | tr [a-z] [A-Z])
        if [ "$CA_USER_CERT_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-cert-del tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-user-cli-ca-user-cert-delete_tests  $subsystemId $subsystemType $MYROLE
        fi
	######## PKI CERT TESTS ############
	CERT_TEST_UPPERCASE=$(echo $CERT_TEST | tr [a-z] [A-Z])
        if [ "$CERT_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki cert tests
		 subsystemType=ca
                 run_pki-cert-ca_tests 
                 run_pki-cert-revoke-ca_tests $subsystemType $MYROLE
                 run_pki-cert-show-ca_tests $subsystemType $MYROLE
                 run_pki-cert-request-show-ca_tests $subsystemType $MYROLE
                 run_pki-cert-release-hold-ca_tests $subsystemType $MYROLE
                 run_pki-cert-hold-ca_tests $subsystemType $MYROLE
		 run_pki-cert-request-submit_tests $subsystemType $MYROLE
		 run_pki-cert-request-profile-find-ca_tests $subsystemType $MYROLE
		 run_pki-cert-request-profile-show-ca_tests $subsystemType $MYROLE
		 run_pki-cert-request-review-ca_tests $subsystemType $MYROLE
		 run_pki-cert-request-find-ca_tests $subsystemType $MYROLE
        fi
        CERT_CONFIG_CA_UPPERCASE=$(echo $CERT_CONFIG_CA | tr [a-z] [A-Z])
        if [ "$CERT_CONFIG_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert tests
                  run_pki-cert-ca_tests
        fi
        CERT_SHOW_CA_UPPERCASE=$(echo $CERT_SHOW_CA | tr [a-z] [A-Z])
        if [ "$CERT_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-show tests
		  subsystemType=ca
                  run_pki-cert-show-ca_tests $subsystemType $MYROLE
        fi
        CERT_REQUEST_SHOW_CA_UPPERCASE=$(echo $CERT_REQUEST_SHOW_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-show tests
		  subsystemType=ca 
                  run_pki-cert-request-show-ca_tests $subsystemType $MYROLE
        fi
        CERT_REVOKE_CA_UPPERCASE=$(echo $CERT_REVOKE_CA | tr [a-z] [A-Z])
        if [ "$CERT_REVOKE_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-revoke tests
		  subsystemType=ca
		  run_pki-cert-revoke-ca_tests $subsystemType $MYROLE
        fi
        CERT_RELEASE_HOLD_CA_UPPERCASE=$(echo $CERT_RELEASE_HOLD_CA | tr [a-z] [A-Z])
        if [ "$CERT_RELEASE_HOLD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-release-hold tests
		  subsystemType=ca
                  run_pki-cert-release-hold-ca_tests $subsystemType $MYROLE
        fi
        CERT_HOLD_CA_UPPERCASE=$(echo $CERT_HOLD_CA | tr [a-z] [A-Z])
        if [ "$CERT_HOLD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-hold tests
		  subsystemType=ca
                  run_pki-cert-hold-ca_tests $subsystemType $MYROLE
        fi
	CERT_REQUEST_SUBMIT_CA_UPPERCASE=$(echo $CERT_REQUEST_SUBMIT_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_SUBMIT_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-hold tests
		  subsystemType=ca
                  run_pki-cert-request-submit_tests $subsystemType $MYROLE
        fi
        CERT_REQUEST_PROFILE_FIND_CA_UPPERCASE=$(echo $CERT_REQUEST_PROFILE_FIND_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_PROFILE_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-profile-find tests
		  subsystemType=ca
                  run_pki-cert-request-profile-find-ca_tests $subsystemType $MYROLE
        fi
        CERT_REQUEST_PROFILE_SHOW_CA_UPPERCASE=$(echo $CERT_REQUEST_PROFILE_SHOW_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_PROFILE_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-profile-show tests
		  subsystemType=ca
                  run_pki-cert-request-profile-show-ca_tests $subsystemType $MYROLE
        fi
        CERT_REQUEST_REVIEW_CA_UPPERCASE=$(echo $CERT_REQUEST_REVIEW_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_REVIEW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-review tests
		  subsystemType=ca
                  run_pki-cert-request-review-ca_tests $subsystemType $MYROLE
        fi
        CERT_REQUEST_FIND_CA_UPPERCASE=$(echo $CERT_REQUEST_FIND_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-find tests
		  subsystemType=ca
                  run_pki-cert-request-find-ca_tests $subsystemType $MYROLE
        fi
        CERT_FIND_CA_UPPERCASE=$(echo $CERT_FIND_CA | tr [a-z] [A-Z])
        if [ "$CERT_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-find tests
		  subsystemType=ca
                  run_pki-cert-find-ca_tests $subsystemType $MYROLE
        fi
        ######## PKI CA CERT TESTS ############
        PKI_CA_CERT_TEST_UPPERCASE=$(echo $PKI_CA_CERT_TEST | tr [a-z] [A-Z])
        if [ "$PKI_CA_CERT_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki cert tests
                 subsystemType=ca
                 run_pki-ca-cert-ca_tests
                 run_pki-ca-cert-revoke-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-show-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-request-show-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-release-hold-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-hold-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-request-submit_tests $subsystemType $MYROLE
                 run_pki-ca-cert-request-profile-find-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-request-profile-show-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-request-review-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-request-find-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-find-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_CONFIG_UPPERCASE=$(echo $CA_CERT_CONFIG | tr [a-z] [A-Z])
        if [ "$CA_CERT_CONFIG_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert tests
                  run_pki-ca-cert-ca_tests
        fi
        CA_CERT_SHOW_UPPERCASE=$(echo $CA_CERT_SHOW | tr [a-z] [A-Z])
        if [ "$CA_CERT_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-show tests
                  subsystemType=ca
                  run_pki-ca-cert-show-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_REQUEST_SHOW_UPPERCASE=$(echo $CA_CERT_REQUEST_SHOW | tr [a-z] [A-Z])
        if [ "$CA_CERT_REQUEST_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-request-show tests
                  subsystemType=ca
                  run_pki-ca-cert-request-show-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_REVOKE_UPPERCASE=$(echo $CA_CERT_REVOKE | tr [a-z] [A-Z])
        if [ "$CA_CERT_REVOKE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-revoke tests
                  subsystemType=ca
                  run_pki-ca-cert-revoke-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_RELEASE_HOLD_UPPERCASE=$(echo $CA_CERT_RELEASE_HOLD | tr [a-z] [A-Z])
        if [ "$CA_CERT_RELEASE_HOLD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-release-hold tests
                  subsystemType=ca
                  run_pki-ca-cert-release-hold-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_HOLD_UPPERCASE=$(echo $CA_CERT_HOLD | tr [a-z] [A-Z])
        if [ "$CA_CERT_HOLD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-hold tests
                  subsystemType=ca
                  run_pki-ca-cert-hold-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_REQUEST_SUBMIT_UPPERCASE=$(echo $CA_CERT_REQUEST_SUBMIT | tr [a-z] [A-Z])
        if [ "$CA_CERT_REQUEST_SUBMIT_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-request-submit tests
                  subsystemType=ca
                  run_pki-ca-cert-request-submit_tests $subsystemType $MYROLE
        fi
        CA_CERT_REQUEST_PROFILE_FIND_UPPERCASE=$(echo $CA_CERT_REQUEST_PROFILE_FIND | tr [a-z] [A-Z])
        if [ "$CA_CERT_REQUEST_PROFILE_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-request-profile-find tests
                  subsystemType=ca
                  run_pki-ca-cert-request-profile-find-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_REQUEST_PROFILE_SHOW_UPPERCASE=$(echo $CA_CERT_REQUEST_PROFILE_SHOW | tr [a-z] [A-Z])
        if [ "$CA_CERT_REQUEST_PROFILE_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-request-profile-show tests
                  subsystemType=ca
                  run_pki-ca-cert-request-profile-show-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_REQUEST_REVIEW_UPPERCASE=$(echo $CA_CERT_REQUEST_REVIEW | tr [a-z] [A-Z])
        if [ "$CA_CERT_REQUEST_REVIEW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-request-review tests
                  subsystemType=ca
                  run_pki-ca-cert-request-review-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_REQUEST_FIND_UPPERCASE=$(echo $CA_CERT_REQUEST_FIND | tr [a-z] [A-Z])
        if [ "$CA_CERT_REQUEST_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-request-find tests
                  subsystemType=ca
                  run_pki-ca-cert-request-find-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_FIND_UPPERCASE=$(echo $CA_CERT_FIND | tr [a-z] [A-Z])
        if [ "$CA_CERT_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-find tests
                  subsystemType=ca
                  run_pki-ca-cert-find-ca_tests $subsystemType $MYROLE
        fi
	######## PKI GROUP CA TESTS ############
	PKI_GROUP_CA_TEST_UPPERCASE=$(echo $PKI_GROUP_CA_TEST | tr [a-z] [A-Z])
        if [ "$PKI_GROUP_CA_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki group tests for ca
		run_pki-group-cli-group-add-ca_tests
                run_pki-group-cli-group-show-ca_tests
                run_pki-group-cli-group-find-ca_tests
                run_pki-group-cli-group-mod-ca_tests
                run_pki-group-cli-group-del-ca_tests
                run_pki-group-cli-group-member-add-ca_tests
                run_pki-group-cli-group-member-find-ca_tests
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
	if [ "$BIG_INT_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		#Execute pki bigInt tests
		run_pki_big_int
		run_pki_cert
		run_pki_cert_show
		run_pki_cert_request_show
	fi

	######## PKI CA GROUP TESTS ############
        PKI_CA_GROUP_TEST_UPPERCASE=$(echo $PKI_CA_GROUP_TEST | tr [a-z] [A-Z])
        if [ "$PKI_CA_GROUP_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki ca-group tests
		subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-add_tests  $subsystemId $subsystemType $MYROLE
		run_pki-ca-group-cli-ca-group-mod_tests  $subsystemId $subsystemType $MYROLE
		run_pki-ca-group-cli-ca-group-find_tests  $subsystemId $subsystemType $MYROLE
		run_pki-ca-group-cli-ca-group-show_tests  $subsystemId $subsystemType $MYROLE
		run_pki-ca-group-cli-ca-group-del_tests  $subsystemId $subsystemType $MYROLE
		run_pki-ca-group-cli-ca-group-member-add_tests  $subsystemId $subsystemType $MYROLE
		run_pki-ca-group-cli-ca-group-member-show_tests  $subsystemId $subsystemType $MYROLE
		run_pki-ca-group-cli-ca-group-member-find_tests  $subsystemId $subsystemType $MYROLE
		run_pki-ca-group-cli-ca-group-member-del_tests  $subsystemId $subsystemType $MYROLE
        fi

	CA_GROUP_ADD_UPPERCASE=$(echo $CA_GROUP_ADD | tr [a-z] [A-Z])
        if [ "$CA_GROUP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-add tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-add_tests  $subsystemId $subsystemType $MYROLE
        fi
	CA_GROUP_MOD_UPPERCASE=$(echo $CA_GROUP_MOD | tr [a-z] [A-Z])
        if [ "$CA_GROUP_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-mod tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-mod_tests  $subsystemId $subsystemType $MYROLE
        fi
	CA_GROUP_FIND_UPPERCASE=$(echo $CA_GROUP_FIND | tr [a-z] [A-Z])
        if [ "$CA_GROUP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-find tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-find_tests  $subsystemId $subsystemType $MYROLE
        fi
	CA_GROUP_SHOW_UPPERCASE=$(echo $CA_GROUP_SHOW | tr [a-z] [A-Z])
        if [ "$CA_GROUP_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-show tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-show_tests  $subsystemId $subsystemType $MYROLE
        fi
	CA_GROUP_DEL_UPPERCASE=$(echo $CA_GROUP_DEL | tr [a-z] [A-Z])
        if [ "$CA_GROUP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-del tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-del_tests  $subsystemId $subsystemType $MYROLE
        fi
	CA_GROUP_MEMBER_ADD_UPPERCASE=$(echo $CA_GROUP_MEMBER_ADD | tr [a-z] [A-Z])
        if [ "$CA_GROUP_MEMBER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-member-add tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-member-add_tests  $subsystemId $subsystemType $MYROLE
        fi
	CA_GROUP_MEMBER_SHOW_UPPERCASE=$(echo $CA_GROUP_MEMBER_SHOW | tr [a-z] [A-Z])
        if [ "$CA_GROUP_MEMBER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-member-show tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-member-show_tests  $subsystemId $subsystemType $MYROLE
        fi
	CA_GROUP_MEMBER_FIND_UPPERCASE=$(echo $CA_GROUP_MEMBER_FIND | tr [a-z] [A-Z])
        if [ "$CA_GROUP_MEMBER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-member-find tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-member-find_tests  $subsystemId $subsystemType $MYROLE
        fi
	CA_GROUP_MEMBER_DEL_UPPERCASE=$(echo $CA_GROUP_MEMBER_DEL | tr [a-z] [A-Z])
        if [ "$CA_GROUP_MEMBER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-member-del tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-member-del_tests  $subsystemId $subsystemType $MYROLE
        fi
	######## PKI BUG VERIFICATIONS ############
	BUG_VERIFICATION_UPPERCASE=$(echo $BUG_VERIFICATION | tr [a-z] [A-Z])
        if [ "$BUG_VERIFICATION_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                #Execute pki bigInt tests
                run_CS-backup-bug-verification
                run_pki-core-bug-verification
                run_tomcatjss-bug-verification
        fi

	######## PKI KEY KRA TESTS ############
	PKI_KEY_KRA_TESTS_UPPERCASE=$(echo $PKI_KEY_KRA_TESTS | tr [a-z] [A-Z])
        if [ "$PKI_KEY_KRA_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		subsystemType=kra
		run_pki-key-kra_tests
		run_pki-key-generate-kra_tests $subsystemType $MYROLE
		run_pki-key-find-kra_tests $subsystemType $MYROLE
		run_pki-key-template-find-kra_tests
		run_pki-key-template-show-kra_tests
		run_pki-key-request-find-kra_tests $subsystemType $MYROLE
		run_pki-key-show-kra_tests $subsystemType $MYROLE
		run_pki-key-request-show-kra_tests $subsystemType $MYROLE
		run_pki-key-mod-kra_tests $subsystemType $MYROLE
		run_pki-key-recover-kra_tests $subsystemType $MYROLE
		run_pki-key-archive-kra_tests $subsystemType $MYROLE
		run_pki-key-retrieve-kra_tests $subsystemType $MYROLE
		run_pki-key-request-review-kra_tests $subsystemType $MYROLE

	fi
	KEY_CONFIG_KRA_UPPERCASE=$(echo $KEY_CONFIG_KRA | tr [a-z] [A-Z]) 
	if [ "$KEY_CONFIG_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key config tests
		 run_pki-key-kra_tests
	fi
	KEY_GENERATE_KRA_UPPERCASE=$(echo $KEY_GENERATE_KRA | tr [a-z] [A-Z])
	if [ "$KEY_GENERATE_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key generate tests
		  subsystemType=kra
		  run_pki-key-generate-kra_tests $subsystemType $MYROLE
	fi
	KEY_FIND_KRA_UPPERCASE=$(echo $KEY_FIND_KRA | tr [a-z] [A-Z])
	if [ "$KEY_FIND_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key find tests
		  subsystemType=kra
		  run_pki-key-find-kra_tests $subsystemType $MYROLE
	fi
	KEY_TEMPLATE_FIND_KRA_UPPERCASE=$(echo $KEY_TEMPLATE_FIND_KRA | tr [a-z] [A-Z])
	if [ "$KEY_TEMPLATE_FIND_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key template-find tests
		 run_pki-key-template-find-kra_tests
	fi
	KEY_TEMPLATE_SHOW_KRA_UPPERCASE=$(echo $KEY_TEMPLATE_SHOW_KRA | tr [a-z] [A-Z])
	if [ "$KEY_TEMPLATE_SHOW_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key template-show tests
		 run_pki-key-template-show-kra_tests
	fi
	KEY_REQUEST_FIND_KRA_UPPERCASE=$(echo $KEY_REQUEST_FIND_KRA | tr [a-z] [A-Z])
	if [ "$KEY_REQUEST_FIND_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key request-find tests 
		  subsystemType=kra
		  run_pki-key-request-find-kra_tests $subsystemType $MYROLE
	fi
	KEY_SHOW_KRA_UPPERCASE=$(echo $KEY_SHOW_KRA | tr [a-z] [A-Z])
	if [ "$KEY_SHOW_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-show tests 
		  subsystemType=kra
		  run_pki-key-show-kra_tests $subsystemType $MYROLE
	fi
	KEY_REQUEST_SHOW_KRA_UPPERCASE=$(echo $KEY_REQUEST_SHOW_KRA | tr [a-z] [A-Z])
	if [ "$KEY_REQUEST_SHOW_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-request-show tests 
		  subsystemType=kra
		  run_pki-key-request-show-kra_tests $subsystemType $MYROLE
	fi
	KEY_MOD_KRA_UPPERCASE=$(echo $KEY_MOD_KRA | tr [a-z] [A-Z])
	if [ "$KEY_MOD_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-mod tests
		  subsystemType=kra
		  run_pki-key-mod-kra_tests $subsystemType $MYROLE
	fi
	KEY_RECOVER_KRA_UPPERCASE=$(echo $KEY_RECOVER_KRA | tr [a-z] [A-Z])
	if [ "$KEY_RECOVER_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-recover tests
		subsystemType=kra
		run_pki-key-recover-kra_tests $subsystemType $MYROLE
	fi
	KEY_ARCHIVE_KRA_UPPERCASE=$(echo $KEY_ARCHIVE_KRA | tr [a-z] [A-Z])
	if [ "$KEY_ARCHIVE_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-archive tests
		subsystemType=kra
		run_pki-key-archive-kra_tests $subsystemType $MYROLE
	fi
	KEY_RETRIEVE_KRA_UPPERCASE=$(echo $KEY_RETRIEVE_KRA | tr [a-z] [A-Z])	
	if [ "$KEY_RETRIEVE_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-retrieve tests
		subsystemType=kra
		run_pki-key-retrieve-kra_tests $subsystemType $MYROLE
	fi
	KEY_REQUEST_REVIEW_KRA_UPPERCASE=$(echo $KEY_REQUEST_REVIEW_KRA | tr [a-z] [A-Z])
	if [ "$KEY_REQUEST_REVIEW_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-request-review tests
		subsystemType=kra
		run_pki-key-request-review-kra_tests $subsystemType $MYROLE
	fi
	
	######## PKI KRA KEY TESTS ############
	PKI_KRA_KEY_TESTS_UPPERCASE=$(echo $PKI_KRA_KEY_TESTS | tr [a-z] [A-Z])
        if [ "$PKI_KRA_KEY_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		subsystemType=kra
		run_pki-kra-key-kra_tests
		run_pki-kra-key-generate-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-find-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-template-find-kra_tests
		run_pki-kra-key-template-show-kra_tests
		run_pki-kra-key-request-find-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-show-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-request-show-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-mod-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-recover-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-archive-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-retrieve-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-request-review-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_CONFIG_UPPERCASE=$(echo $KRA_KEY_CONFIG | tr [a-z] [A-Z]) 
	if [ "$KRA_KEY_CONFIG_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key config tests
		run_pki-kra-key-kra_tests 
	fi
	KRA_KEY_GENERATE_UPPERCASE=$(echo $KRA_KEY_GENERATE | tr [a-z] [A-Z])
	if [ "$KRA_KEY_GENERATE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key generate tests
		  subsystemType=kra
		  run_pki-kra-key-generate-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_FIND_UPPERCASE=$(echo $KRA_KEY_FIND | tr [a-z] [A-Z])
	if [ "$KRA_KEY_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key find tests
		  subsystemType=kra
		  run_pki-kra-key-find-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_TEMPLATE_FIND_UPPERCASE=$(echo $KRA_KEY_TEMPLATE_FIND | tr [a-z] [A-Z])
	if [ "$KRA_KEY_TEMPLATE_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key template-find tests
		  run_pki-kra-key-template-find-kra_tests
	fi
	KRA_KEY_TEMPLATE_SHOW_UPPERCASE=$(echo $KRA_KEY_TEMPLATE_SHOW | tr [a-z] [A-Z])
	if [ "$KRA_KEY_TEMPLATE_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key template-show tests
		 run_pki-kra-key-template-show-kra_tests
	fi
	KRA_KEY_REQUEST_FIND_UPPERCASE=$(echo $KRA_KEY_REQUEST_FIND | tr [a-z] [A-Z])
	if [ "$KRA_KEY_REQUEST_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key request-find tests 
		  subsystemType=kra
		  run_pki-kra-key-request-find-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_SHOW_UPPERCASE=$(echo $KRA_KEY_SHOW | tr [a-z] [A-Z])
	if [ "$KRA_KEY_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-show tests 
		  subsystemType=kra
		  run_pki-kra-key-show-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_REQUEST_SHOW_UPPERCASE=$(echo $KRA_KEY_REQUEST_SHOW | tr [a-z] [A-Z])
	if [ "$KRA_KEY_REQUEST_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-request-show tests 
		  subsystemType=kra
		  run_pki-kra-key-request-show-kra_tests $subsystemType $MYROLE
  	fi
	KRA_KEY_MOD_UPPERCASE=$(echo $KRA_KEY_MOD | tr [a-z] [A-Z])
	if [ "$KRA_KEY_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-mod tests
		  subsystemType=kra
		  run_pki-kra-key-mod-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_RECOVER_UPPERCASE=$(echo $KRA_KEY_RECOVER | tr [a-z] [A-Z])
	if [ "$KEY_RECOVER_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-recover tests
		subsystemType=kra
		run_pki-kra-key-recover-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_ARCHIVE_UPPERCASE=$(echo $KRA_KEY_ARCHIVE | tr [a-z] [A-Z])
	if [ "$KRA_KEY_ARCHIVE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-archive tests
		subsystemType=kra
		run_pki-kra-key-archive-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_RETRIEVE_UPPERCASE=$(echo $KRA_KEY_RETRIEVE | tr [a-z] [A-Z])	
	if [ "$KRA_KEY_RETRIEVE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-retrieve tests
		subsystemType=kra
		run_pki-kra-key-retrieve-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_REQUEST_REVIEW_UPPERCASE=$(echo $KRA_KEY_REQUEST_REVIEW | tr [a-z] [A-Z])
	if [ "$KRA_KEY_REQUEST_REVIEW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-request-review tests
		subsystemType=kra
		run_pki-kra-key-request-review-kra_tests $subsystemType $MYROLE	
	fi
	######## PKI USER TESTS ############
	USER_CLEANUP_CA_UPPERCASE=$(echo $USER_CLEANUP_CA | tr [a-z] [A-Z])
        #Clean up role users (admin agent etc) created in CA
        if [ "$USER_CLEANUP_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cleanup-ca tests
		CA_INST=$(cat /tmp/topo_file | grep MY_CA | cut -d= -f2)
                rlLog "Subsystem ID CA=$CA_INST"
                run_pki-user-cli-user-cleanup_tests $CA_INST ca $MY_ROLE
	fi
        rlPhaseEnd

	######## DEV UNIT TESTS ############
	DEV_JAVA_TESTS_UPPERCASE=$(echo $DEV_JAVA_TESTS | tr [a-z] [A-Z])
        if [ "$DEV_JAVA_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
        rlPhaseStartSetup "Dev Tests"
             run_dev_junit_tests
        rlPhaseEnd
        fi

	######## CODE COVERAGE TESTS ############
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
