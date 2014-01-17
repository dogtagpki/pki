#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   cleanupscript of /CoreOS/dogtag/acceptance/cli-tests/pki-user-cli
#   Description: Deleting the role users and temp directories
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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

######################################################################################
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-cleanup-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

run_pki-user-cli-user-cleanup-ca_tests(){

    rlPhaseStartTest "pki_user_cli_user_cleanup-001: Deleting the temp directory and users"
        del_user=($CA_adminV_user $CA_adminR_user $CA_adminE_user $CA_adminUTCA_user $CA_agentV_user $CA_agentR_user $CA_agentE_user $CA_agentUTCA_user $CA_auditV_user $CA_operatorV_user)

        i=0
        while [ $i -lt ${#del_user[@]} ] ; do
               userid_del=${del_user[$i]}
               rlRun "pki -d $CERTDB_DIR \
                          -n \"$admin_cert_nickname\" \
                          -c $CERTDB_DIR_PASSWORD  \
                           user-del  $userid_del > $TmpDir/pki-user-del-ca-00$i.out"  \
                           0 \
                           "Deleted user  $userid_del"
                rlAssertGrep "Deleted user \"$userid_del\"" "$TmpDir/pki-user-del-ca-00$i.out"
                let i=$i+1
        done


       # rlRun "rm -rf $TmpDir" 0 "Removing temp directory"
        rlRun "popd"
       # rlRun "rm -rf $CERTDB_DIR"
        rlRun "rm -rf /tmp/untrusted_cert_db"
    rlPhaseEnd
}
