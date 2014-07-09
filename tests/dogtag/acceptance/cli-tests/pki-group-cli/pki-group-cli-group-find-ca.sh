#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/cli-tests/pki-group-cli
#   Description: PKI group-find CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cli commands needs to be tested:
#  pki-group-cli-group-find  To  list  groups in CA.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Roshni Pattath <rpattath@redhat.com>
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

run_pki-group-cli-group-find-ca_tests(){

    rlPhaseStartSetup "pki_group_cli_group_find-ca-startup: Create temporary directory and add groups"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
	i=1
        while [ $i -lt 25 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-add --description=test_group g$i"
                let i=$i+1
        done
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-configtest-001: pki group-find --help configuration test"
        rlRun "pki group-find --help > $TmpDir/group_find.out 2>&1" 0 "pki group-find --help"
        rlAssertGrep "usage: group-find \[FILTER\] \[OPTIONS...\]" "$TmpDir/group_find.out"
        rlAssertGrep "\--size <size>     Page size" "$TmpDir/group_find.out"
        rlAssertGrep "\--start <start>   Page start" "$TmpDir/group_find.out"
        rlAssertGrep "\--help            Show help options" "$TmpDir/group_find.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-configtest-002: pki group-find configuration test"
	command="pki group-find"
	errmsg="Error: Certificate database not initialized."
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki group-find"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-003: Find 5 groups, --size=5"
	rlRun "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find --size=5  > $TmpDir/pki-group-find-ca-001.out 2>&1" \
                         0 \
                        "Found 5 groups"
	rlAssertGrep "Number of entries returned 5" "$TmpDir/pki-group-find-ca-001.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-004: Find no group, --size=0"
        rlRun "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find --size=0  > $TmpDir/pki-group-find-ca-002.out 2>&1" \
                    0 \
                    "Found no groups"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-group-find-ca-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-005: Find all groups, large value as input"
        large_num=1000000
	rlRun "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find --size=$large_num  > $TmpDir/pki-group-find-ca-003.out 2>&1" \
                         0 \ 
                    "Find all groups, large value as input"
	result=`cat $TmpDir/pki-group-find-ca-003.out | grep "Number of entries returned"`
        number=`echo $result | cut -d " " -f 5`
        if [ $number -gt 25 ] ; then
                rlPass "Number of entries returned is more than 25 as expected"
        else

                rlFail "Number of entries returned is not expected, Got: $number, Expected: > 25"
        fi
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-006: Find all groups, --size with maximum possible value as input"
        maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 9 | head -n 1`
	rlLog "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find --size=$maximum_check"
        rlRun "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                   group-find --size=$maximum_check  > $TmpDir/pki-group-find-ca-003_2.out 2>&1" \
                   0 \
                   "Find all groups, maximum possible value as input"
	result=`cat $TmpDir/pki-group-find-ca-003_2.out | grep "Number of entries returned"`
	number=`echo $result | cut -d " " -f 5`	
	if [ $number -gt 25 ] ; then
        	rlPass "Number of entries returned is more than 25 as expected"
	else
	
        	rlFail "Number of entries returned is not expected, Got: $number, Expected: > 25"
	fi
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-007: Find all groups, --size more than maximum possible value"
        maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 11 | head -n 1`
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-find --size=$maximum_check"
	errmsg="NumberFormatException: For input string: $maximum_check"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - More than maximum possible value as input should fail"	
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-008: Find groups, check for negative input --size=-1"
	command="pki -d $CERTDB_DIR -n \"CA_adminV\" -c $CERTDB_DIR_PASSWORD group-find --size=-1"
	errmsg="size should not have value less than 0"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - size with negative value should fail"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/861"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-009: Find groups for size input as noninteger, --size=abc"
        size_noninteger="abc"
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-find --size=$size_noninteger"
	errmsg="NumberFormatException: For input string: $size_noninteger"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - size with characters should fail"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-010: Find groups, check for no input --size="
	command="pki -d $CERTDB_DIR -n \"CA_adminV\" -c $CERTDB_DIR_PASSWORD group-find --size="
	errmsg="NumberFormatException: For input string: \"""\""
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - size with empty value should fail"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-011: Find groups, --start=10"
	#Find the 10th group
        rlRun "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                   group-find  > $TmpDir/pki-group-find-ca-007_1.out 2>&1" \
                   0 \
                   "Get all groups in CA"
	group_entry_10=`cat $TmpDir/pki-group-find-ca-007_1.out | grep "Group ID" | head -11 | tail -1`
	rlLog "10th entry=$group_entry_10"

	rlLog "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find --start=10"
        rlRun "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                   group-find --start=10  > $TmpDir/pki-group-find-ca-007.out 2>&1" \
                   0 \
                   "Displays groups from the 10th group and the next to the maximum 20 groups, if available "
	#First group in the response should be the 10th group $group_entry_10
	group_entry_1=`cat $TmpDir/pki-group-find-ca-007.out | grep "Group ID" | head -1`
	rlLog "1st entry=$group_entry_1"
	if [ "$group_entry_1" = "$group_entry_10" ]; then
		rlPass "Displays groups from the 10th group"
	else
		rlFail "Display did not start from the 10th group"
	fi
        rlAssertGrep "Number of entries returned 20" "$TmpDir/pki-group-find-ca-007.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-012: Find groups, --start=10000, large possible input"
        rlRun "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                   group-find --start=10000  > $TmpDir/pki-group-find-ca-008.out 2>&1" \
                    0 \
                   "Find users, --start=10000, large possible input"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-group-find-ca-008.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-013: Find groups, --start with maximum possible input"
	maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 9 | head -n 1`
	rlLog "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                   group-find --start=$maximum_check"
        rlRun "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                   group-find --start=$maximum_check  > $TmpDir/pki-group-find-ca-008_2.out 2>&1" \
                    0 \
                   "Find groups, --start with maximum possible input"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-group-find-ca-008_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-014: Find groups, --start with more than maximum possible input"
        maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 11 | head -n 1`
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-find --start=$maximum_check"
	errmsg="NumberFormatException: For input string: \"$maximum_check\""
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Find users, --start with more than maximum possible input should fail"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-015: Find groups, --start=0"
        rlRun "pki -d $CERTDB_DIR \
                    -n \"CA_adminV\" \
                    -c $CERTDB_DIR_PASSWORD \
                    group-find --start=0  > $TmpDir/pki-group-find-ca-009.out 2>&1" \
                     0 \
                     "Displays from the zeroth user, maximum possible are 20 users in a page"
        rlAssertGrep "Number of entries returned 20" "$TmpDir/pki-group-find-ca-009.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-016: Find groups, --start=-1"
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-find --start=-1"
        errmsg="start should not have value less than 0"
        errorcode=255
        rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - start with negative value should fail"
        rlLog "FAIL: https://fedorahosted.org/pki/ticket/929"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-017: Find groups for size input as noninteger, --start=abc"
        size_noninteger="abc"
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-find --start=$size_noninteger"
	errmsg="NumberFormatException: For input string: \"$size_noninteger\""
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - start with non integer value should fail"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-018: Find groups, check for no input --start= "
	command="pki -d $CERTDB_DIR -n \"CA_adminV\" -c $CERTDB_DIR_PASSWORD group-find --start="
	errmsg="NumberFormatException: For input string: \"""\""
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - start with empty value should fail"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-019: Find groups, --size=12 --start=12"
        #Find 12 groups starting from 12th group
        rlRun "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                   group-find  > $TmpDir/pki-group-find-ca-00_13_1.out 2>&1" \
                     0 \
                   "Get all groups in CA"
        group_entry_12=`cat $TmpDir/pki-group-find-ca-00_13_1.out | grep "Group ID" | head -13 | tail -1`

        rlRun "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                   group-find --start=12 --size=12  > $TmpDir/pki-group-find-ca-0013.out 2>&1" \
                   0 \
                   "Displays groups from the 12th group and the next to the maximum 12 groups"
        #First group in the response should be the 12th group $group_entry_12
        group_entry_1=`cat  $TmpDir/pki-group-find-ca-0013.out | grep "Group ID" | head -1`
        if [ "$group_entry_1" = "$group_entry_12" ]; then
                rlPass "Displays groups from the 12th group"
        else
                rlFail "Display did not start from the 12th group"
        fi
        rlAssertGrep "Number of entries returned 12" "$TmpDir/pki-group-find-ca-0013.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-020: Find groups, --size=0 --start=12"
        #Find 12 groups starting from 12th group
        rlRun "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find  > $TmpDir/pki-group-find-ca-00_14_1.out 2>&1" \
                  0 \
                        "Get all groups in CA"
        group_entry_12=`cat $TmpDir/pki-group-find-ca-00_14_1.out | grep "Group ID" | head -13 | tail -1`

        rlRun "pki -d $CERTDB_DIR \
                   -n \"CA_adminV\" \
                   -c $CERTDB_DIR_PASSWORD \
                   group-find --start=12 --size=0  > $TmpDir/pki-group-find-ca-0014.out 2>&1" \
                    0 \
                   "Displays groups from the 12th group and 0 groups"
        rlAssertGrep "Number of entries returned 0" "$TmpDir/pki-group-find-ca-0014.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-021: Should not be able to find group using a revoked cert CA_adminR"
	command="pki -d $CERTDB_DIR -n CA_adminR -c $CERTDB_DIR_PASSWORD user-find --start=1 --size=5"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to find users using a revoked admin cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-022: Should not be able to find groups using an agent with revoked cert CA_agentR"
	command="pki -d $CERTDB_DIR -n CA_agentR -c $CERTDB_DIR_PASSWORD group-find --start=1 --size=5"
	errmsg="PKIException: Unauthorized"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to find users using a revoked agent cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-023: Should not be able to find groups using a valid agent CA_agentV user"
	command="pki -d $CERTDB_DIR -n CA_agentV -c $CERTDB_DIR_PASSWORD group-find --start=1 --size=5"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to find groups using a valid agent cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-024: Should not be able to find groups using admin user with expired cert CA_adminE"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
	rlRun "date"
	command="pki -d $CERTDB_DIR -n CA_adminE -c $CERTDB_DIR_PASSWORD group-find --start=1 --size=5"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to find groups using a expired admin cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-025: Should not be able to find groups using CA_agentE cert"
        rlRun "date --set='next day'" 0 "Set System date a day ahead"
	rlRun "date --set='next day'" 0 "Set System date a day ahead"
	rlRun "date"
	command="pki -d $CERTDB_DIR -n CA_agentE -c $CERTDB_DIR_PASSWORD group-find --start=1 --size=5"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to find groups using a expired agent cert"
        rlRun "date --set='2 days ago'" 0 "Set System back to the present day"
	rlLog "FAIL: https://fedorahosted.org/pki/ticket/962"
    rlPhaseEnd

     rlPhaseStartTest "pki_group_cli_group_find-ca-026: Should not be able to find groups using a CA_auditV"
	command="pki -d $CERTDB_DIR -n CA_auditV -c $CERTDB_DIR_PASSWORD group-find --start=1 --size=5"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to find groups using a valid auditor cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-027: Should not be able to find groups using a CA_operatorV"
	command="pki -d $CERTDB_DIR -n CA_operatorV -c $CERTDB_DIR_PASSWORD group-find --start=1 --size=5"
	errmsg="ForbiddenException: Authorization failed on resource: certServer.ca.groups, operation: execute"
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to find groups using a valid operator cert"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-028: Should not be able to find groups using a cert created from a untrusted CA CA_adminUTCA"
	command="pki -d /tmp/untrusted_cert_db -n CA_adminUTCA -c Password group-find --start=1 --size=5"
	errmsg="PKIException: Unauthorized"
	errocode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - Should not be able to find groups using CA_adminUTCA"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-029: Should not be able to find groups using a user cert"
	#Create a user cert
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local ret_reqstatus
        local ret_requestid
        local valid_serialNumber
        local temp_out="$TmpDir/usercert-show.out"
        rlRun "create_cert_request $TEMP_NSS_DB Password pkcs10 rsa 2048 \"pki User1\" \"pkiUser1\" \
                \"pkiuser1@example.org\" \"Engineering\" \"Example.Inc\" "US" "--" "ret_reqstatus" "ret_requestid"" 0 "Generating  pkcs10 Certificate Request"
        rlLog "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"CA_agentV\" ca-cert-request-review $ret_requestid \
                --action approve 1"
        rlRun "pki -d $CERTDB_DIR -c $CERTDB_DIR_PASSWORD -n \"CA_agentV\" ca-cert-request-review $ret_requestid \
                --action approve 1> $TmpDir/pki-approve-out" 0 "Approve Certificate requeset"
        rlAssertGrep "Approved certificate request $ret_requestid" "$TmpDir/pki-approve-out"
        rlLog "pki cert-request-show $ret_requestid | grep \"Certificate ID\" | sed 's/ //g' | cut -d: -f2)"
        rlRun "pki cert-request-show $ret_requestid > $TmpDir/usercert-show1.out"
        valid_serialNumber=`cat $TmpDir/usercert-show1.out | grep 'Certificate ID' | sed 's/ //g' | cut -d: -f2`
        rlLog "valid_serialNumber=$valid_serialNumber"
        #Import user certs to $TEMP_NSS_DB
        rlRun "pki cert-show $valid_serialNumber --encoded > $temp_out" 0 "command pki cert-show $valid_serialNumber --encoded"
        rlRun "certutil -d $TEMP_NSS_DB -A -n pkiUser1 -i $temp_out  -t "u,u,u""
	local expfile="$TmpDir/expfile_pkiuser1.out"
        rlLog "Executing: pki -d $TEMP_NSS_DB \
                   -n pkiUser1 \
                   -c Password \
                    group-find --start=1 --size=5"
        echo "spawn -noecho pki -d $TEMP_NSS_DB -n pkiUser1 -c Password user-find --start=1 --size=5" > $expfile
	echo "expect \"WARNING: UNTRUSTED ISSUER encountered on 'CN=$HOSTNAME,O=$CA_DOMAIN Security Domain' indicates a non-trusted CA cert 'CN=CA Signing Certificate,O=$CA_DOMAIN Security Domain'
Import CA certificate (Y/n)? \"" >> $expfile
        echo "send -- \"Y\r\"" >> $expfile
        echo "expect \"CA server URI \[http://$HOSTNAME:$CA_UNSECURE_PORT/ca\]: \"" >> $expfile
        echo "send -- \"\r\"" >> $expfile
        echo "expect eof" >> $expfile
	echo "catch wait result" >> $expfile
        echo "exit [lindex \$result 3]" >> $expfile
        rlRun "/usr/bin/expect -f $expfile >  $TmpDir/pki-group-find-ca-pkiUser1-002.out 2>&1" 255 "Should not be able to find groups using a user cert"
        rlAssertGrep "PKIException: Unauthorized" "$TmpDir/pki-group-find-ca-pkiUser1-002.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-030: find groups when group id has i18n characters"
	maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1`
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description='Örjan Äke' 'ÖrjanÄke' > $TmpDir/pki-group-find-ca-001_31.out 2>&1" \
                    0 \
                    "Adding gid ÖrjanÄke with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find --size=$maximum_check "
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find --size=$maximum_check > $TmpDir/pki-group-show-ca-001_31_2.out" \
                    0 \
                    "Find group with max size"
        rlAssertGrep "Group ID: ÖrjanÄke" "$TmpDir/pki-group-show-ca-001_31_2.out"
        rlAssertGrep "Description: Örjan Äke" "$TmpDir/pki-group-show-ca-001_31_2.out"
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_find-ca-031: find group when group id has i18n characters"
	maximum_check=`cat /dev/urandom | tr -dc '0-9' | fold -w 5 | head -n 1`
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-add --description='Éric Têko' 'ÉricTêko' > $TmpDir/pki-group-show-ca-001_32.out 2>&1" \
                    0 \
                    "Adding group id ÉricTêko with i18n characters"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find --size=$maximum_check"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find --size=$maximum_check > $TmpDir/pki-group-show-ca-001_32_2.out" \
                    0 \
                    "Find group with max size"
        rlAssertGrep "Group ID: ÉricTêko" "$TmpDir/pki-group-show-ca-001_32_2.out"
        rlAssertGrep "Description: Éric Têko" "$TmpDir/pki-group-show-ca-001_32_2.out"
    rlPhaseEnd
	
	#pki group-find with filters

	rlPhaseStartTest "pki_group_cli_group_find-ca-032: find group - filter 'Administrator'"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find Administrator"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find Administrator > $TmpDir/pki-group-show-ca-033.out" \
                    0 \
                    "Find group with Keyword Administrator"
	rlAssertGrep "Group ID: Administrators" "$TmpDir/pki-group-show-ca-033.out"
	rlAssertGrep "Group ID: Security Domain Administrators" "$TmpDir/pki-group-show-ca-033.out"
	rlAssertGrep "Group ID: Enterprise CA Administrators" "$TmpDir/pki-group-show-ca-033.out"
	rlAssertGrep "Group ID: Enterprise KRA Administrators" "$TmpDir/pki-group-show-ca-033.out"
	rlAssertGrep "Group ID: Enterprise RA Administrators" "$TmpDir/pki-group-show-ca-033.out"
	rlAssertGrep "Group ID: Enterprise OCSP Administrators" "$TmpDir/pki-group-show-ca-033.out"
	rlAssertGrep "Group ID: Enterprise TKS Administrators" "$TmpDir/pki-group-show-ca-033.out"
	rlAssertGrep "Group ID: Enterprise TPS Administrators" "$TmpDir/pki-group-show-ca-033.out"
    rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_find-ca-033: find group - filter 'KRA'"
        rlLog "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find KRA"
        rlRun "pki -d $CERTDB_DIR \
                   -n CA_adminV \
                   -c $CERTDB_DIR_PASSWORD \
                    group-find KRA > $TmpDir/pki-group-show-ca-034.out" \
                    0 \
                    "Find group with Keyword KRA"
        rlAssertGrep "Group ID: Enterprise KRA Administrators" "$TmpDir/pki-group-show-ca-034.out"
    rlPhaseEnd

	rlPhaseStartTest "pki_group_cli_group_find-ca-034: find group should fail when filter keyword has less than 3 characters"
	command="pki -d $CERTDB_DIR -n CA_adminV -c $CERTDB_DIR_PASSWORD group-find CA"
	errmsg="BadRequestException: Filter is too short."
	errorcode=255
	rlRun "verifyErrorMsg \"$command\" \"$errmsg\" \"$errorcode\"" 0 "Verify expected error message - pki group-find should fail if the filter has less than 3 characters"	
    rlPhaseEnd

    rlPhaseStartTest "pki_group_cli_group_cleanup-001: Deleting groups"
        #===Deleting groups created using CA_adminV cert===#
        i=1
        while [ $i -lt 25 ] ; do
               rlRun "pki -d $CERTDB_DIR \
                          -n CA_adminV \
                          -c $CERTDB_DIR_PASSWORD \
                           group-del  g$i > $TmpDir/pki-group-del-ca-group-00$i.out" \
                           0 \
                           "Deleted group  g$i"
                rlAssertGrep "Deleted group \"g$i\"" "$TmpDir/pki-group-del-ca-group-00$i.out"
                let i=$i+1
        done

	#===Deleting i18n groups created using CA_adminV cert===#
        rlRun "pki -d $CERTDB_DIR \
                -n CA_adminV \
                -c $CERTDB_DIR_PASSWORD \
                group-del 'ÖrjanÄke' > $TmpDir/pki-group-del-ca-group-i18n_1.out" \
                0 \
                "Deleted group ÖrjanÄke"
        rlAssertGrep "Deleted group \"ÖrjanÄke\"" "$TmpDir/pki-group-del-ca-group-i18n_1.out"

        rlRun "pki -d $CERTDB_DIR \
                -n CA_adminV \
                -c $CERTDB_DIR_PASSWORD \
                group-del 'ÉricTêko' > $TmpDir/pki-group-del-ca-group-i18n_2.out" \
                0 \
                "Deleted group ÉricTêko"
        rlAssertGrep "Deleted group \"ÉricTêko\"" "$TmpDir/pki-group-del-ca-group-i18n_2.out"

	#Delete temporary directory
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
    rlPhaseEnd
}
