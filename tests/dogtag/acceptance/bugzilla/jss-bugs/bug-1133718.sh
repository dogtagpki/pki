#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/bugzilla/jss-bugs
#   Description: 1058366 bug verification
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
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/pki-cert-cli-lib.sh
. /opt/rhqa_pki/env.sh

########################################################################
#bug_setup.sh should be first executed prior to bug verification
########################################################################

########################################################################
# Test Suite Globals
########################################################################
run_bug-1133718-verification(){
 
     rlPhaseStartTest "Bug 1133718 - Key strength validation is not performed for RC4 algorithm"
	BUGCA_DOMAIN=`hostname -d`
	rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1133718"
	rlLog "pki -d $BUGCA_CERTDB_DIR -c $BUGCA_CERTDB_DIR_PASSWORD -n \"PKI Administrator for $BUGCA_DOMAIN\" -h $MASTER -p $BUGCA_HTTP_PORT key-generate test --key-algorithm RC4 --key-size -1"
	rlRun "pki -d $BUGCA_CERTDB_DIR -c $BUGCA_CERTDB_DIR_PASSWORD -n \"PKI Administrator for $BUGCA_DOMAIN\" -h $MASTER -p $BUGCA_HTTP_PORT key-generate test --key-algorithm RC4 --key-size -1 > /tmp/kra-key-generate001.out 2>&1" 255 "KRA key generate using key size -1"
	rlRun "sleep 10"
	rlAssertGrep "BadRequestException: Invalid key size for this algorithm" "/tmp/kra-key-generate001.out"
	rlRun "pki -d $BUGCA_CERTDB_DIR -c $BUGCA_CERTDB_DIR_PASSWORD -n \"PKI Administrator for $BUGCA_DOMAIN\" -h $MASTER -p $BUGCA_HTTP_PORT key-generate test --key-algorithm RC4 --key-size 39 > /tmp/kra-key-generate002.out 2>&1" 255 "KRA key generate using key size 39"
	rlRun "sleep 10"
        rlAssertGrep "BadRequestException: Invalid key size for this algorithm" "/tmp/kra-key-generate002.out"
	rlRun "pki -d $BUGCA_CERTDB_DIR -c $BUGCA_CERTDB_DIR_PASSWORD -n \"PKI Administrator for $BUGCA_DOMAIN\" -h $MASTER -p $BUGCA_HTTP_PORT key-generate test --key-algorithm RC4 --key-size 2049 > /tmp/kra-key-generate003.out 2>&1" 255 "KRA key generate using key size 2049"
	rlRun "sleep 10"
        rlAssertGrep "BadRequestException: Invalid key size for this algorithm" "/tmp/kra-key-generate003.out"
	rlRun "pki -d $BUGCA_CERTDB_DIR -c $BUGCA_CERTDB_DIR_PASSWORD -n \"PKI Administrator for $BUGCA_DOMAIN\" -h $MASTER -p $BUGCA_HTTP_PORT key-generate test --key-algorithm RC4 --key-size 40 > /tmp/kra-key-generate004.out 2>&1" 0 "KRA key generate using key size 40"
	rlRun "sleep 10"
        rlAssertGrep "Key generation request info" "/tmp/kra-key-generate004.out"
	rlAssertGrep "Type: symkeyGenRequest" "/tmp/kra-key-generate004.out"
	rlAssertGrep "Status: complete" "/tmp/kra-key-generate004.out"
	rlRun "pki -d $BUGCA_CERTDB_DIR -c $BUGCA_CERTDB_DIR_PASSWORD -n \"PKI Administrator for $BUGCA_DOMAIN\" -h $MASTER -p $BUGCA_HTTP_PORT key-generate test1 --key-algorithm RC4 --key-size 100 > /tmp/kra-key-generate005.out 2>&1" 0 "KRA key generate using key size 100"
        rlRun "sleep 10"
        rlAssertGrep "Key generation request info" "/tmp/kra-key-generate005.out"
        rlAssertGrep "Type: symkeyGenRequest" "/tmp/kra-key-generate005.out"
        rlAssertGrep "Status: complete" "/tmp/kra-key-generate005.out"
	rlRun "pki -d $BUGCA_CERTDB_DIR -c $BUGCA_CERTDB_DIR_PASSWORD -n \"PKI Administrator for $BUGCA_DOMAIN\" -h $MASTER -p $BUGCA_HTTP_PORT key-generate test2 --key-algorithm RC4 --key-size 2048 > /tmp/kra-key-generate006.out 2>&1" 0 "KRA key generate using key size 2048"
        rlRun "sleep 10"
        rlAssertGrep "Key generation request info" "/tmp/kra-key-generate006.out"
        rlAssertGrep "Type: symkeyGenRequest" "/tmp/kra-key-generate006.out"
        rlAssertGrep "Status: complete" "/tmp/kra-key-generate006.out"
     rlPhaseEnd

}
