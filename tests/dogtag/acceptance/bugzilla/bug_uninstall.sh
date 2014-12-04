#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/bugzilla/
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
#pki-user-cli-user-ca.sh should be first executed prior to bug verification
########################################################################

########################################################################
# Test Suite Globals
########################################################################
run_bug-uninstall(){
 
     rlPhaseStartTest "Bug verification - uninstall instances"
	rlRun "pkidestroy -s TKS -i pki-ca-bug"
	rlRun "sleep 10"
	rlRun "pkidestroy -s OCSP -i pki-ca-bug"
        rlRun "sleep 10"
	rlRun "pkidestroy -s KRA -i pki-ca-bug"
        rlRun "sleep 10"
	rlRun "pkidestroy -s CA -i pki-ca-bug"
        rlRun "sleep 10"
	rlRun "remove-ds.pl -f -i slapd-pki-ca-bug"
	rlRun "sleep 10"
	rlRun "remove-ds.pl -f -i slapd-pki-kra-bug"
        rlRun "sleep 10"
	rlRun "remove-ds.pl -f -i slapd-pki-ocsp-bug"
        rlRun "sleep 10"
	rlRun "remove-ds.pl -f -i slapd-pki-tks-bug"
        rlRun "sleep 10"
	rlRun "rm -rf $BUGCA_CERTDB_DIR"
     rlPhaseEnd

}
