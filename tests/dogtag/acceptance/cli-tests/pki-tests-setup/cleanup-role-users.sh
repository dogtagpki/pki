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
########################################################################

run_pki-user-cli-user-cleanup_tests(){
subsystemId=$1
SUBSYSTEM_TYPE=$2
MYROLE=$3
SUBSYSTEM_HOST=$(eval echo \$${MYROLE})
if [ "$TOPO9" = "TRUE" ] ; then
        ADMIN_CERT_LOCATION=$(eval echo \$${subsystemId}_ADMIN_CERT_LOCATION)
        admin_cert_nickname=$(eval echo \$${subsystemId}_ADMIN_CERT_NICKNAME)
        CLIENT_PKCS12_PASSWORD=$(eval echo \$${subsystemId}_CLIENT_PKCS12_PASSWORD)
elif [ "$MYROLE" = "MASTER" ] ; then
        if [[ $subsystemId == SUBCA* ]]; then
                ADMIN_CERT_LOCATION=$(eval echo \$${subsystemId}_ADMIN_CERT_LOCATION)
                admin_cert_nickname=$(eval echo \$${subsystemId}_ADMIN_CERT_NICKNAME)
                CLIENT_PKCS12_PASSWORD=$(eval echo \$${subsystemId}_CLIENT_PKCS12_PASSWORD)
        else
                ADMIN_CERT_LOCATION=$ROOTCA_ADMIN_CERT_LOCATION
                admin_cert_nickname=$ROOTCA_ADMIN_CERT_NICKNAME
                CLIENT_PKCS12_PASSWORD=$ROOTCA_CLIENT_PKCS12_PASSWORD
        fi
else
        ADMIN_CERT_LOCATION=$(eval echo \$${MYROLE}_ADMIN_CERT_LOCATION)
        admin_cert_nickname=$(eval echo \$${MYROLE}_ADMIN_CERT_NICKNAME)
        CLIENT_PKCS12_PASSWORD=$(eval echo \$${MYROLE}_CLIENT_PKCS12_PASSWORD)
fi


    rlPhaseStartTest "pki_user_cli_user_cleanup-001: Deleting the temp directory and users"
        del_user=(${subsystemId}_adminV ${subsystemId}_adminR ${subsystemId}_adminE ${subsystemId}_adminUTCA ${subsystemId}_agentV ${subsystemId}_agentR ${subsystemId}_agentE ${subsystemId}_agentUTCA ${subsystemId}_auditV ${subsystemId}_operatorV)
	rlLog "after del_user - listing users under it"
        i=0
	rlLog "${del_user[$i]}"
        while [ $i -lt ${#del_user[@]} ] ; do
               userid_del=${del_user[$i]}
	       rlLog "in while $i"
               rlRun "pki -d $CERTDB_DIR \
                          -n \"$admin_cert_nickname\" \
                          -c $CERTDB_DIR_PASSWORD  \
			  -h $SUBSYSTEM_HOST \
                          -t $SUBSYSTEM_TYPE \
                          -p $(eval echo \$${subsystemId}_UNSECURE_PORT) \
                           user-del  $userid_del > $TmpDir/pki-user-del-00$i.out"  \
                           0 \
                           "Deleted user  $userid_del"
                rlAssertGrep "Deleted user \"$userid_del\"" "$TmpDir/pki-user-del-00$i.out"
		echo "$userid_del" | grep UTCA
		if [$? -eq 0 ] ; then
			rlLog "$userid_del UTCA user"
		else
			rlRun "certutil -D -d $CERTDB_DIR -n $userid_del"
		fi
                let i=$i+1
        done
	#rlRun "certutil -D -d $UNTRUSTED_CERT_DB_LOCATION -n role_user_UTCA"
       	#rlRun "rm -rf $TmpDir" 0 "Removing temp directory"
       	#rlRun "rm -rf $CERTDB_DIR"
       	#rlRun "rm -rf $UNTRUSTED_CERT_DB_LOCATION"
    rlPhaseEnd
}

