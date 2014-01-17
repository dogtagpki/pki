#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following ipa cli commands needs to be tested:
#  pki-user-cli-user-add    Add users to pki subsystems.
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
. /opt/rhqa_pki/pki-cert-cli-lib.sh
. /opt/rhqa_pki/env.sh


########################################################################
# Test Suite Globals
########################################################################
user1=ca_agent2
user1fullname="Test ca_agent"
user2=abcdefghijklmnopqrstuvwxyx12345678
user3=abc#
user4=abc$
user5=abc@
user6=abc?
user7=0

run_pki-user-cli-user-del-ca_tests(){
    rlPhaseStartTest "pki_user_cli_user_del-001: Add users to test user-del functionality"
	del_user=($CA_adminV_user $CA_adminR_user $CA_adminE_user $CA_adminUTCA_user $CA_agentV_user $CA_agentR_user $CA_agentE_user $CA_agentUTCA_user $CA_auditV_user $CA_operatorV_user)
	#positive test cases
	#Add users to CA using CA_adminV cert
	i=1
        while [ $i -lt 25 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-add --fullName=test_user u$i"
                let i=$i+1
        done

	#===Deleting users created using CA_adminV cert===#
	i=1
	while [ $i -lt 25 ] ; do
	       rlLog "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  u$i"
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  u$i > $TmpDir/pki-user-del-ca-user1-00$i.out" \
                           0 \
                           "Deleted user  u$i"
		rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-ca-user1-00$i.out"
                let i=$i+1
        done
	#Add users to CA using CA_adminV cert
        i=1
        while [ $i -lt 8 ] ; do
	       eval usr=\$user$i
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-add --fullName=test_user $usr"
                let i=$i+1
        done

        #===Deleting users(symbols) created using CA_adminV cert===#
	j=1
        while [ $j -lt 8 ] ; do
	       eval usr=\$user$j
	       rlLog "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del $usr "
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del $usr > $TmpDir/pki-user-del-ca-user2-00$j.out" \
			   0 \
			   "Deleted user  $usr"
		rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user2-00$j.out"
                let j=$j+1
        done
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_del-002: Case sensitive userid, Negative test case"
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-add --fullName=test_user user_abc"
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  USER_ABC > $TmpDir/pki-user-del-ca-user-002_1.out" \
                           0 \
                           "Deleted user USER_ABC userid is not case sensitive"
        rlAssertGrep "Deleted user \"USER_ABC\"" "$TmpDir/pki-user-del-ca-user-002_1.out"
    rlPhaseEnd
    rlPhaseStartTest "pki_user_cli_user_del-003: user id missing, Negative test case"
        rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-add --fullName=test_user test_user"
        rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  > $TmpDir/pki-user-del-ca-user-003_1.out 2>&1" \
                           1 \
                           "Cannot delete a user without userid"
        rlAssertGrep "usage: user-del <User ID>" "$TmpDir/pki-user-del-ca-user-003_1.out"
	rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del test_user > $TmpDir/pki-user-del-ca-user-003_2.out" \
                           0 \
                           "Deleted user test_user"
        rlAssertGrep "Deleted user \"test_user\"" "$TmpDir/pki-user-del-ca-user-003_2.out"
    rlPhaseEnd

}
