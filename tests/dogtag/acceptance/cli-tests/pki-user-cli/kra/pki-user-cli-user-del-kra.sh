#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-add CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following ipa cli commands needs to be tested:
#  pki-user-cli-user-add    Add users to pki subsystems.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Asha Akkiangady <aakkiang@redhat.com>
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

run_pki-user-cli-user-del-kra_tests(){
    rlPhaseStartSetup "pki_user_cli_user_add-kra-startup:Getting the temp directory and nss certificate db "
	 rlLog "nss_db directory = $TmpDir/nssdb"
	 rlLog "temp directory = /tmp/requestdb"
    rlPhaseEnd

    rlPhaseStartCleanup "pki_user_cli_user_add-cleanup: Delete temp dir"
	del_user=($KRA_adminV_user $KRA_adminR_user $KRA_adminE_user $KRA_adminUTKRA_user $KRA_agentV_user $KRA_agentR_user $KRA_agentE_user $KRA_agentUTKRA_user $KRA_auditV_user $KRA_operatorV_user)

	#===Deleting users created using KRA_adminV cert===#
	i=1
	while [ $i -lt 25 ] ; do
               rlRun "pki -d /tmp/requestdb \
                          -n KRA_adminV \
                          -c $nss_db_password \
                           user-del  u$i > $TmpDir/pki-user-del-kra-user-00$i.out" \
                           0 \
                           "Deleted user  u$i"
		rlAssertGrep "Deleted user \"u$i\"" "$TmpDir/pki-user-del-kra-user-00$i.out"
                let i=$i+1
        done
        #===Deleting users(symbols) created using KRA_adminV cert===#
	j=1
        while [ $j -lt 8 ] ; do
	       eval usr=\$user$j
               rlRun "pki -d /tmp/requestdb \
                          -n KRA_adminV \
                          -c $nss_db_password \
                           user-del  $usr > $TmpDir/pki-user-del-kra-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-kra-user-symbol-00$j.out"
                let j=$j+1
        done
	i=0
        while [ $i -lt ${#del_user[@]} ] ; do
               userid_del=${del_user[$i]}
               rlRun "pki -d $TmpDir/nssdb \
                          -n \"$admin_cert_nickname\" \
                          -c $nss_db_password \
                           user-del  $userid_del > $TmpDir/pki-user-del-kra-00$i.out"  \
                           0 \
                           "Deleted user  $userid_del"
                rlAssertGrep "Deleted user \"$userid_del\"" "$TmpDir/pki-user-del-kra-00$i.out"
                let i=$i+1
        done


#	rlRun "rm -r $TmpDir" 0 "Removing temp directory"
#	rlRun "popd"
 #       rlRun "rm -rf /tmp/requestdb"
  #      rlRun "rm -rf /tmp/dummydb"


    rlPhaseEnd
}
