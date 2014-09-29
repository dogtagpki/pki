#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-key-cli
#   Description: PKI KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki key cli commands needs to be tested:
#  pki-key --help
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

# pki key ran without any options should show all the command line options of pki cert
run_pki-key-kra_tests()
{
	rlPhaseStartSetup "Create Temporary Directory"
	rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
	rlRun "pushd $TmpDir"
	rlPhaseEnd

	rlPhaseStartTest "pki_key --help Test: Show all the options of pki ke"
	local temp_out="$TmpDir/pki_key"
	rlLog "Executing pki key --help"
	rlRun "pki key --help 1> $temp_out" 0 "pki key --help"
	rlAssertGrep "Commands:"	"$temp_out"
	rlAssertGrep "key-find                Find keys" "$temp_out"
	rlAssertGrep "key-request-find        Find key requests" "$temp_out"
	rlAssertGrep "key-show                Get key" "$temp_out"
	rlAssertGrep "key-request-show        Get key request" "$temp_out"
	rlAssertGrep "key-mod                 Modify the status of a key" "$temp_out"
	rlAssertGrep "key-template-find       List request template IDs" "$temp_out"
	rlAssertGrep "key-template-show       Get request template" "$temp_out"
	rlAssertGrep "key-archive             Archive a secret in the DRM." "$temp_out"
	rlAssertGrep "key-retrieve            Retrieve key" "$temp_out"
	rlAssertGrep "key-generate            Generate key" "$temp_out"
	rlAssertGrep "key-recover             Create a key recovery request" "$temp_out"
	rlAssertGrep "key-request-review      Review key request" "$temp_out"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_key001: pki key with junk characters should return invalid module"
	local temp_out1="$TmpDir/pki_key001"
	local rand=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9*?$@#!%^&*()' | fold -w 40 | head -n 1)
	rlLog "Executing pki cert \"$junk\" characters"
	rlRun "pki key \"$rand\" 2> $temp_out1" 1,255 "Command pki cert with junk characters"
	rlAssertGrep "Error: Invalid module" "$temp_out1"
	rlPhaseEnd
	
	rlPhaseStartCleanup "pki key cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlPhaseEnd
}
