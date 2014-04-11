#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli
#   Description: PKI user-cert-find CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following ipa cli commands needs to be tested:
#  pki-user-cli-user-cert-find    Finding the certs assigned to users in the pki ca subsystem.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Roshni Pattath <rpattath@redhat.com>
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
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-add-ca.sh
#pki-user-cli-user-ca.sh should be first executed prior to pki-user-cli-user-cert-find-ca.sh
######################################################################################

########################################################################
# Test Suite Globals
########################################################################

########################################################################

run_pki-user-cli-user-cert-find-ca_tests(){

user1=testuser1
user2=testuser2
user1fullname="Test user1"
user2fullname="Test user2"
user3=testuser3
user3fullname="Test user3"
cert_info="$TmpDir/cert_info"


##### pki_user_cli_user_cert_find_ca-configtest ####
     rlPhaseStartTest "pki_user_cli_user_cert-find-configtest-001: pki user-cert-find configuration test"
        rlRun "pki user-cert-find > $TmpDir/pki_user_cert_find_cfg.out" \
                1 \
                "User cert find configuration"
        rlAssertGrep "usage: user-cert-find <User ID> \[OPTIONS...\]" "$TmpDir/pki_user_cert_find_cfg.out"
        rlAssertGrep "--size <size>     Page size" "$TmpDir/pki_user_cert_find_cfg.out"
        rlAssertGrep "--start <start>   Page start" "$TmpDir/pki_user_cert_find_cfg.out"
    rlPhaseEnd

     ##### Tests to find certs assigned to CA users ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-002: Find the certs of a user in CA --userid only - single page of certs"
        i=0
#        l=0
        k=2
        rlRun "pki -d $CERTDB_DIR \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                            user-add --fullName=\"$user1fullname\" $user1"
        while [ $i -lt 4 ] ; do
                rlRun "generate_cert_cert_find $cert_info $k $user1$(($i+1)) \"$user1fullname$(($i+1))\" $i" 0  "Generating temp cert"
                local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
                serialhexuser1[$i]=$cert_serialNumber
                serialdecuser1[$i]=$decimal_valid_serialNumber_pkcs10
                rlLog "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_find_CA_validcert_002$i.pem"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_find_CA_validcert_002$i.pem  > $TmpDir/useraddcert__002_$i.out" \
                            0 \
                            "Cert is added to the user $user1"
                let i=$i+1
                #let l=$l+1
        done
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user1"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user1 > $TmpDir/pki_user_cert_find_ca_002.out" \
                    0 \
                    "Finding certs assigned to $user1"
        #let i=$i-1
        numcertsuser1=$i
        rlAssertGrep "$i entries matched" "$TmpDir/pki_user_cert_find_ca_002.out"
        rlAssertGrep "Number of entries returned $i" "$TmpDir/pki_user_cert_find_ca_002.out"
        i=0
        #l=0
        while [ $i -lt 4 ] ; do
        	rlAssertGrep "Cert ID: 2;${serialdecuser1[$i]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user1$(($i+1)),E=$user1$(($i+1))i@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_002.out"
        	rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_002.out"
        	rlAssertGrep "Serial Number: ${serialhexuser1[$i]}" "$TmpDir/pki_user_cert_find_ca_002.out"
        	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_002.out"
        	rlAssertGrep "Subject: UID=$user1$(($i+1)),E=$user1$(($i+1))@example.org,CN=$user1fullname$(($i+1)),OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_002.out"
                let i=$i+1
                #let l=$l+1
	done
	rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-003: Find the certs of a user in CA --userid only - multiple pages of certs"
        i=1
        l=0
	k=3
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   user-add --fullName=\"$user2fullname\" $user2"
        while [ $i -lt 25 ] ; do
		rlRun "generate_cert_cert_find $cert_info $k $user2$i \"$user2fullname$i\" $i" 0  "Generating temp cert"
                local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
                local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
                local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
                local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
                serialhexuser2[$l]=$cert_serialNumber
                serialdecuser2[$l]=$decimal_valid_serialNumber_pkcs10
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user2 --input $TmpDir/pki_user_cert_find_CA_validcert_003$i.pem  > $TmpDir/useraddcert__003_$i.out" \
                            0 \
                            "Cert is added to the user $user2"
                let i=$i+1
                let l=$l+1
        done
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user2"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
		   user-cert-find $user2 > $TmpDir/pki_user_cert_find_ca_003.out" \
                    0 \
                    "Finding certs assigned to $user2"
  	let i=$i-1
	numcertsuser2=$i
        rlAssertGrep "$i entries matched" "$TmpDir/pki_user_cert_find_ca_003.out"
        i=1
        l=0
        while [ $i -lt 21 ] ; do
        rlAssertGrep "Cert ID: 2;${serialdecuser2[$l]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlAssertGrep "Serial Number: ${serialhexuser2[$l]}" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlAssertGrep "Subject: UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_003.out"
                let i=$i+1
                let l=$l+1
        done
	rlAssertGrep "Number of entries returned 20" "$TmpDir/pki_user_cert_find_ca_003.out"
        rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-004: Find the certs of a user in CA --userid only - user does not exist"

	rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find tuser"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find tuser > $TmpDir/pki_user_cert_find_ca_004.out 2>&1" \
                    1 \
                    "Finding certs assigned to tuser"
	rlAssertGrep "UserNotFoundException: User tuser not found" "$TmpDir/pki_user_cert_find_ca_004.out"

rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-005: Find the certs of a user in CA --userid only - no certs added to the user"

	rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-add $user3 --fullName=\"$user3fullname\""
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user3"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user3 > $TmpDir/pki_user_cert_find_ca_005.out" \
                    0 \
                    "Finding certs assigned to $user3"
        rlAssertGrep "0 entries matched" "$TmpDir/pki_user_cert_find_ca_005.out"

rlPhaseEnd

##### Tests to find certs assigned to CA users using --size parameter ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-006: Find the certs of a user in CA --size - a number less than the actual number of certs"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user1 --size=2"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user1 --size=2 > $TmpDir/pki_user_cert_find_ca_006.out" \
                    0 \
                    "Finding certs assigned to $user1 - --size=2"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_006.out"
	rlAssertGrep "Number of entries returned 2" "$TmpDir/pki_user_cert_find_ca_006.out"
	i=1
	l=0
	while [ $i -lt 3 ] ; do
        	rlAssertGrep "Cert ID: 2;${serialdecuser1[$l]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user1$i,E=$user1$i@example.org,CN=$user1fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_006.out"
        	rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_006.out"
        	rlAssertGrep "Serial Number: ${serialhexuser1[$l]}" "$TmpDir/pki_user_cert_find_ca_006.out"
        	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_006.out"
        	rlAssertGrep "Subject: UID=$user1$i,E=$user1$i@example.org,CN=$user1fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_006.out"
                let i=$i+1
                let l=$l+1
        done
rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-007: Find the certs of a user in CA --size=0"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user1 --size=0"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user1 --size=0 > $TmpDir/pki_user_cert_find_ca_007.out" \
                    0 \
                    "Finding certs assigned to $user1 - --size=0"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_007.out"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki_user_cert_find_ca_007.out"
rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-008: Find the certs of a user in CA --size=-1"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user1 --size=-1"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user1 --size=-1 > $TmpDir/pki_user_cert_find_ca_008.out" \
                    1 \
                    "Finding certs assigned to $user1 - --size=-1"
        rlAssertGrep "The value for size shold be greater than or equal to 0" "$TmpDir/pki_user_cert_find_ca_008.out"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/861"
rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-009: Find the certs of a user in CA --size - a number greater than number of certs assigned to the user"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user1 --size=50"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user1 --size=50 > $TmpDir/pki_user_cert_find_ca_009.out" \
                    0 \
                    "Finding certs assigned to $user1 - --size=50"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Number of entries returned $numcertsuser1" "$TmpDir/pki_user_cert_find_ca_009.out"
	i=1
        l=0
        while [ $i -lt 5 ] ; do
        rlAssertGrep "Cert ID: 2;${serialdecuser1[$l]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user1$i,E=$user1$i@example.org,CN=$user1fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Serial Number: ${serialhexuser1[$l]}" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Subject: UID=$user1$i,E=$user1$i@example.org,CN=$user1fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_009.out"
                let i=$i+1
                let l=$l+1
        done
rlPhaseEnd

##### Tests to find certs assigned to CA users using --start parameter ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-010: Find the certs of a user in CA --start - a number less than the actual number of certs"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user1 --start=2"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user1 --start=2 > $TmpDir/pki_user_cert_find_ca_010.out" \
                    0 \
                    "Finding certs assigned to $user1 - --start=2"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_010.out"
	let newnumcerts=$numcertsuser1-2
        rlAssertGrep "Number of entries returned $newnumcerts" "$TmpDir/pki_user_cert_find_ca_010.out"
        i=3
        l=2
        while [ $i -lt 5 ] ; do
                rlAssertGrep "Cert ID: 2;${serialdecuser1[$l]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user1$i,E=$user1$i@example.org,CN=$user1fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_010.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_010.out"
                rlAssertGrep "Serial Number: ${serialhexuser1[$l]}" "$TmpDir/pki_user_cert_find_ca_010.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_010.out"
                rlAssertGrep "Subject: UID=$user1$i,E=$user1$i@example.org,CN=$user1fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_010.out"
                let i=$i+1
                let l=$l+1
        done
rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-011: Find the certs of a user in CA --start=0"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user1 --start=0"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user1 --start=0 > $TmpDir/pki_user_cert_find_ca_011.out" \
                    0 \
                    "Finding certs assigned to $user1 - --start=0"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_011.out"
        rlAssertGrep "Number of entries returned $numcertsuser1" "$TmpDir/pki_user_cert_find_ca_011.out"
	i=1
        l=0
        while [ $i -lt 5 ] ; do
        rlAssertGrep "Cert ID: 2;${serialdecuser1[$l]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user1$i,E=$user1$i@example.org,CN=$user1fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Serial Number: ${serialhexuser1[$l]}" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_009.out"
        rlAssertGrep "Subject: UID=$user1$i,E=$user1$i@example.org,CN=$user1fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_009.out"
                let i=$i+1
                let l=$l+1
        done
rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-012: Find the certs of a user in CA --start=0 - multiple pages"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user2 --start=0"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user2 --start=0 > $TmpDir/pki_user_cert_find_ca_012.out" \
                    0 \
                    "Finding certs assigned to $user2 - --start=0"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Number of entries returned 20" "$TmpDir/pki_user_cert_find_ca_012.out"
	i=1
        l=0
        while [ $i -lt 21 ] ; do
        rlAssertGrep "Cert ID: 2;${serialdecuser2[$l]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Serial Number: ${serialhexuser2[$l]}" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_012.out"
        rlAssertGrep "Subject: UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_012.out"
                let i=$i+1
                let l=$l+1
        done
rlPhaseEnd


rlPhaseStartTest "pki_user_cli_user_cert-find-CA-013: Find the certs of a user in CA --start=-1"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user1 --start=-1"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user1 --start=-1 > $TmpDir/pki_user_cert_find_ca_013.out" \
                    1 \
                    "Finding certs assigned to $user1 - --start=-1"
        rlAssertGrep "The value for start shold be greater than or equal to 0" "$TmpDir/pki_user_cert_find_ca_013.out"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/929"
rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-014: Find the certs of a user in CA --start - a number greater than number of certs assigned to the user"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user1 --start=50"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user1 --start=50 > $TmpDir/pki_user_cert_find_ca_014.out" \
                    0 \
                    "Finding certs assigned to $user1 - --start=50"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_014.out"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki_user_cert_find_ca_014.out"
rlPhaseEnd

##### Tests to find certs assigned to CA users using --size and --start parameters ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-015: Find the certs of a user in CA --start=0 --size=0"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user1 --start=0 --size=0"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user1 --start=0 --size=0 > $TmpDir/pki_user_cert_find_ca_015.out" \
                    0 \
                    "Finding certs assigned to $user1 - --start=0 --size=0"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_015.out"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki_user_cert_find_ca_015.out"
rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-016: Find the certs of a user in CA --start=1 --size=1"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user1 --start=1 --size=1"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user1 --start=1 --size=1 > $TmpDir/pki_user_cert_find_ca_016.out" \
                    0 \
                    "Finding certs assigned to $user1 - --start=1 --size=1"
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_016.out"
        rlAssertGrep "Number of entries returned 1" "$TmpDir/pki_user_cert_find_ca_016.out"
	i=2
	rlAssertGrep "Cert ID: 2;${serialdecuser1[1]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user1$i,E=$user1$i@example.org,CN=$user1fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_016.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_016.out"
        rlAssertGrep "Serial Number: ${serialhexuser1[1]}" "$TmpDir/pki_user_cert_find_ca_016.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_016.out"
        rlAssertGrep "Subject: UID=$user1$i,E=$user1$i@example.org,CN=$user1fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_016.out"
rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-017: Find the certs of a user in CA --start=-1 --size=-1"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user1 --start=-1 --size=-1"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user1 --start=-1 --size=-1 > $TmpDir/pki_user_cert_find_ca_017.out" \
                    1 \
                    "Finding certs assigned to $user1 - --start=-1 --size=-1"
        rlAssertGrep "The value for start and size shold be greater than or equal to 0" "$TmpDir/pki_user_cert_find_ca_017.out"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/929"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/861"
rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-018: Find the certs of a user in CA --start --size equal to page size - default page size=20 entries"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user2 --start=20 --size=20"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user2 --start=20 --size=20 > $TmpDir/pki_user_cert_find_ca_018.out" \
                    0 \
                    "Finding certs assigned to $user2 - --start=20 --size=20"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_user_cert_find_ca_018.out"
	let newnumcert=$numcertsuser2-20
        rlAssertGrep "Number of entries returned $newnumcert" "$TmpDir/pki_user_cert_find_ca_018.out"
	i=21
        l=20
        while [ $i -lt 25 ] ; do
        rlAssertGrep "Cert ID: 2;${serialdecuser2[$l]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_018.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_018.out"
        rlAssertGrep "Serial Number: ${serialhexuser2[$l]}" "$TmpDir/pki_user_cert_find_ca_018.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_018.out"
        rlAssertGrep "Subject: UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_018.out"
                let i=$i+1
                let l=$l+1
        done 
rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-019: Find the certs of a user in CA --start=0 --size greater than default page size - default page size=20 entries"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user2 --start=0 --size=22"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user2 --start=0 --size=22 > $TmpDir/pki_user_cert_find_ca_019.out" \
                    0 \
                    "Finding certs assigned to $user2 - --start=0 --size=22"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Number of entries returned 22" "$TmpDir/pki_user_cert_find_ca_019.out"
        i=1
        l=0
        while [ $i -lt 23 ] ; do
        rlAssertGrep "Cert ID: 2;${serialdecuser2[$l]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Serial Number: ${serialhexuser2[$l]}" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_019.out"
        rlAssertGrep "Subject: UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_019.out"
                let i=$i+1
                let l=$l+1
        done
rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-020: Find the certs of a user in CA --start - values greater than default page size --size=1"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user2 --start=22 --size=1"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user2 --start=22 --size=1 > $TmpDir/pki_user_cert_find_ca_020.out" \
                    0 \
                    "Finding certs assigned to $user2 - --start=22 --size=1"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_user_cert_find_ca_020.out"
        rlAssertGrep "Number of entries returned 1" "$TmpDir/pki_user_cert_find_ca_020.out"
        i=23
        l=22
        rlAssertGrep "Cert ID: 2;${serialdecuser2[$l]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_020.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_020.out"
        rlAssertGrep "Serial Number: ${serialhexuser2[$l]}" "$TmpDir/pki_user_cert_find_ca_020.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_020.out"
        rlAssertGrep "Subject: UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_020.out"
rlPhaseEnd


rlPhaseStartTest "pki_user_cli_user_cert-find-CA-021: Find the certs of a user in CA --start - values greater than default page size --size - value greater than the available number of certs from the start value"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user2 --start=22 --size=5"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user2 --start=22 --size=5 > $TmpDir/pki_user_cert_find_ca_021.out" \
                    0 \
                    "Finding certs assigned to $user2 - --start=22 --size=5"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_user_cert_find_ca_021.out"
        rlAssertGrep "Number of entries returned 2" "$TmpDir/pki_user_cert_find_ca_021.out"
        i=23
        l=22
	while [ $i -lt 25 ] ; do
        	rlAssertGrep "Cert ID: 2;${serialdecuser2[$l]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_021.out"
        	rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_021.out"
        	rlAssertGrep "Serial Number: ${serialhexuser2[$l]}" "$TmpDir/pki_user_cert_find_ca_021.out"
        	rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_021.out"
        	rlAssertGrep "Subject: UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_021.out"
		let i=$i+1
		let l=$l+1
	done
rlPhaseEnd

##### Tests to find certs assigned to CA users - i18n characters ####

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-022: Find certs assigned to user \"CN=Örjan Äke,UID=Örjan Äke\" i18n Characters"
	k=22
	rlRun "generate_cert_cert_find $cert_info $k \"Örjan Äke\" \"Örjan Äke\"" 0  "Generating temp cert"
        local cert_serialNumber=$(cat $cert_info| grep cert_serialNumber | cut -d- -f2)
        local STRIP_HEX_PKCS10=$(echo $cert_serialNumber | cut -dx -f2)
        local CONV_UPP_VAL_PKCS10=${STRIP_HEX_PKCS10^^}
        local decimal_valid_serialNumber_pkcs10=$(echo "ibase=16;$CONV_UPP_VAL_PKCS10"|bc)
        rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_adminV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                            user-cert-add $user1 --input $TmpDir/pki_user_cert_find_CA_validcert_0022.pem  > $TmpDir/useraddcer0t__003.out" \
                            0 \
                            "Cert is added to the user $user1"
        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_adminV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user1"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user1 > $TmpDir/pki_user_cert_find_ca_022.out" \
                    0 \
                    "Finding certs assigned to $user1"
        let numcertsuser1=$numcertsuser1+1
        i=5
        rlAssertGrep "$numcertsuser1 entries matched" "$TmpDir/pki_user_cert_find_ca_022.out"
        rlAssertGrep "Number of entries returned $numcertsuser1" "$TmpDir/pki_user_cert_find_ca_022.out"

        rlAssertGrep "Cert ID: 2;$decimal_valid_serialNumber_pkcs10;CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_022.out"
        rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_022.out"
        rlAssertGrep "Serial Number: $cert_serialNumber" "$TmpDir/pki_user_cert_find_ca_022.out"
        rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_022.out"
        rlAssertGrep "Subject: UID=Örjan Äke,E=test@example.org,CN=Örjan Äke,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_022.out"

        rlPhaseEnd

	rlPhaseStartTest "pki_user_cli_user_cert-find-CA-023: Find the certs of a user as CA_agentV"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_agentV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user2"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_agentV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user2 > $TmpDir/pki_user_cert_find_ca_023.out" \
                    0 \
                    "Finding certs assigned to $user2 as CA_agentV"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_user_cert_find_ca_023.out"
        rlAssertGrep "Number of entries returned 20" "$TmpDir/pki_user_cert_find_ca_023.out"
        i=1
        l=0
        while [ $i -lt 25 ] ; do
                rlAssertGrep "Cert ID: 2;${serialdecuser2[$l]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_023.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_023.out"
                rlAssertGrep "Serial Number: ${serialhexuser2[$l]}" "$TmpDir/pki_user_cert_find_ca_023.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_023.out"
                rlAssertGrep "Subject: UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_023.out"
                let i=$i+1
                let l=$l+1
        done
rlPhaseEnd

rlPhaseStartTest "pki_user_cli_user_cert-find-CA-024: Find the certs of a user as CA_auditorV"

        rlLog "Executing: pki -d $CERTDB_DIR/ \
                              -n CA_auditorV \
                              -c $CERTDB_DIR_PASSWORD \
                              -t ca \
                               user-cert-find $user2"
        rlRun "pki -d $CERTDB_DIR/ \
                   -n CA_auditorV \
                   -c $CERTDB_DIR_PASSWORD \
                   -t ca \
                   user-cert-find $user2 > $TmpDir/pki_user_cert_find_ca_024.out" \
                    0 \
                    "Finding certs assigned to $user2 as CA_auditorV"
        rlAssertGrep "$numcertsuser2 entries matched" "$TmpDir/pki_user_cert_find_ca_024.out"
        rlAssertGrep "Number of entries returned 20" "$TmpDir/pki_user_cert_find_ca_024.out"
        i=1
        l=0
        while [ $i -lt 25 ] ; do
                rlAssertGrep "Cert ID: 2;${serialdecuser2[$l]};CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain;UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_024.out"
                rlAssertGrep "Version: 2" "$TmpDir/pki_user_cert_find_ca_024.out"
                rlAssertGrep "Serial Number: ${serialhexuser2[$l]}" "$TmpDir/pki_user_cert_find_ca_024.out"
                rlAssertGrep "Issuer: CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain" "$TmpDir/pki_user_cert_find_ca_024.out"
                rlAssertGrep "Subject: UID=$user2$i,E=$user2$i@example.org,CN=$user2fullname$i,OU=Engineering,O=Example,C=US" "$TmpDir/pki_user_cert_find_ca_024.out"
                let i=$i+1
                let l=$l+1
        done
rlPhaseEnd


#===Deleting users===#
rlPhaseStartTest "pki_user_cli_user_cleanup: Deleting role users"

	j=1
        while [ $j -lt 4 ] ; do
               eval usr=\$user$j
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           user-del  $usr > $TmpDir/pki-user-del-ca-user-symbol-00$j.out" \
                           0 \
                           "Deleted user $usr"
                rlAssertGrep "Deleted user \"$usr\"" "$TmpDir/pki-user-del-ca-user-symbol-00$j.out"
                let j=$j+1
        done 
    rlPhaseEnd

}

generate_cert_cert_find()
{

                local reqstatus
                local requestid
                local requestdn
                local CERT_INFO="$1"
                local file_no="$2"
                local user_id="$3"
                local userfullname="$4"
                local ext=".out"
                local cert_ext=".pem"
                local num="$5"
                if [ "$user_id" = "Örjan Äke" ] ; then
                        rlRun "create_cert_request $CERTDB_DIR redhat123 pkcs10 rsa 2048 \"Örjan Äke\" \"Örjan Äke\" "test@example.org" "Engineering" "Example" "US" "--" "reqstatus" "requestid" "requestdn""
                else
                        rlRun "create_cert_request $CERTDB_DIR redhat123 pkcs10 rsa 2048 \"$userfullname\" "$user_id" "$user_id@example.org" "Engineering" "Example" "US" "--" "reqstatus" "requestid" "requestdn""
                fi

                rlRun "pki cert-request-show $requestid > $TmpDir/pki_user_cert_find_CA_certrequestshow_00$file_no$num$ext" 0 "Executing pki cert-request-show $requestid"
                rlAssertGrep "Request ID: $requestid" "$TmpDir/pki_user_cert_find_CA_certrequestshow_00$file_no$num$ext"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_find_CA_certrequestshow_00$file_no$num$ext"
                rlAssertGrep "Status: pending" "$TmpDir/pki_user_cert_find_CA_certrequestshow_00$file_no$num$ext"
                rlAssertGrep "Operation Result: success" "$TmpDir/pki_user_cert_find_CA_certrequestshow_00$file_no$num$ext"

                #Agent Approve the certificate after reviewing the cert for the user
                rlLog "Executing: pki -d $CERTDB_DIR/ \
                                      -n CA_agentV \
                                      -c $CERTDB_DIR_PASSWORD \
                                      -t ca \
                                      cert-request-review --action=approve $requestid"
                rlRun "pki -d $CERTDB_DIR/ \
                           -n CA_agentV \
                           -c $CERTDB_DIR_PASSWORD \
                           -t ca \
                           cert-request-review --action=approve $requestid > $TmpDir/pki_user_cert_find_CA_certapprove_00$file_no$num$ext" \
                           0 \
                           "CA agent approve the cert"
                rlAssertGrep "Approved certificate request $requestid" "$TmpDir/pki_user_cert_find_CA_certapprove_00$file_no$num$ext"
                rlRun "pki cert-request-show $requestid > $TmpDir/pki_user_cert_find_CA_certapprovedshow_00$file_no$num$ext" 0 "Executing pki cert-request-show $requestid"
                rlAssertGrep "Request ID: $requestid" "$TmpDir/pki_user_cert_find_CA_certapprovedshow_00$file_no$num$ext"
                rlAssertGrep "Type: enrollment" "$TmpDir/pki_user_cert_find_CA_certapprovedshow_00$file_no$num$ext"
                rlAssertGrep "Status: complete" "$TmpDir/pki_user_cert_find_CA_certapprovedshow_00$file_no$num$ext"
                rlAssertGrep "Certificate ID:" "$TmpDir/pki_user_cert_find_CA_certapprovedshow_00$file_no$num$ext"
                local certificate_serial_number=`cat $TmpDir/pki_user_cert_find_CA_certapprovedshow_00$file_no$num$ext | grep "Certificate ID:" | awk '{print $3}'`
                rlLog "Cerificate Serial Number=$certificate_serial_number"
                #Verify the certificate is valid
                rlRun "pki cert-show  $certificate_serial_number --encoded > $TmpDir/pki_user_cert_find_CA_certificate_show_00$file_no$num$ext" 0 "Executing pki cert-show $certificate_serial_number"

                rlRun "sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' $TmpDir/pki_user_cert_find_CA_certificate_show_00$file_no$num$ext > $TmpDir/pki_user_cert_find_CA_validcert_00$file_no$num$cert_ext"
                 rlRun "certutil -d $CERTDB_DIR -A -n \"$user_id\" -i $TmpDir/pki_user_cert_find_CA_validcert_00$file_no$num$cert_ext  -t "u,u,u""
                echo cert_serialNumber-$certificate_serial_number > $CERT_INFO
                echo cert_requestdn-$requestdn >> $CERT_INFO
                return 0;
}

