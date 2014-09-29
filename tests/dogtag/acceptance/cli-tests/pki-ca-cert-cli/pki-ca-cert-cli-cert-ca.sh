#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ca-cert-cli
#   Description: PKI CA CERT CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki cert cli commands needs to be tested:
#  pki-ca-cert
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Niranjan Mallapadi <mniranja@redhat.com>
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

# pki cert ran without any options should show all the command line options of pki cert
run_pki-ca-cert-ca_tests()
{
	rlPhaseStartSetup "Create Temporary Directory"
	rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
	rlRun "pushd $TmpDir"
	rlPhaseEnd

	rlPhaseStartTest "pki_cert config test: pki cert --help configuration test"
	local temp_out="$TmpDir/pki_cert"
	rlLog "Executing pki ca-cert --help"
	rlRun "pki cert --help 1> $temp_out" 0 "pki cert --help"
	rlAssertGrep "Commands:"  "$temp_out"
	rlAssertGrep "ca-cert-find               Find certificates" "$temp_out"
	rlAssertGrep "ca-cert-show               Show certificate" "$temp_out"
	rlAssertGrep "ca-cert-hold               Place certificate on-hold" "$temp_out"
	rlAssertGrep "ca-cert-release-hold       Place certificate off-hold" "$temp_out"
	rlAssertGrep "ca-cert-request-find       Find certificate requests" "$temp_out"
	rlAssertGrep "ca-cert-request-show       Show certificate request" "$temp_out"
	rlAssertGrep "ca-cert-request-submit     Submit certificate request" "$temp_out"
	rlAssertGrep "ca-cert-request-review     Review certificate request" "$temp_out"
	rlAssertGrep "ca-cert-request-profile-find List Enrollment templates" "$temp_out"
	rlAssertGrep "ca-cert-request-profile-show Get Enrollment template" "$temp_out"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_cert001: pki ca-cert with junk characters should return invalid module"
	local temp_out1="$TmpDir/pki_cert001"
	local rand=`cat /dev/urandom | tr -dc 'a-zA-Z0-9*?$@#!%^&*()' | fold -w 40 | head -n 1`
	rlLog "Executing pki ca-cert \"$junk\" characters"
	rlRun "pki ca-cert \"$rand\" 2> $temp_out1" 1,255 "Command pki cert with junk characters"
	rlAssertGrep "Error: Invalid module" "$temp_out1"
	rlPhaseEnd
	
	rlPhaseStartCleanup "pki ca-cert cleanup: Delete temp dir"
	rlRun "popd"
	rlPhaseEnd
}
