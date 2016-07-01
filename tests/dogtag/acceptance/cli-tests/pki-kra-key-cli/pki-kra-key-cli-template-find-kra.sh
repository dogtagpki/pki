#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-kra-key-cli
#   Description: PKI KRA-KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki kra-key cli commands needs to be tested:
#  pki kra-kra-key-template-find
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
. /opt/rhqa_pki/env.sh

run_pki-kra-key-template-find-kra_tests()
{
	rlPhaseStartSetup "Create Temporary Directory"
	rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
	rlRun "pushd $TmpDir"
	rlPhaseEnd

	rlPhaseStartTest "pki kra-key-template-find --help Test: Show all the options of pki kra-key-template-find"
	local temp_out="$TmpDir/pki_kra-key-template-find"
	rlLog "Executing pki kra-key-template-find --help"
	rlRun "pki kra-key-template-find --help 1> $temp_out" 0 "pki key --help"
	rlAssertGrep "usage: kra-key-template-find \[OPTIONS...\]" "$temp_out"
	rlAssertGrep "    --help   Show help options" "$temp_out"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_kra_key_template_find-001: Run pki kra-key-template-find to display all the key archival templates"
	local temp_out1="$TmpDir/pki_key_template_find_001"
	rlLog "Executing pki kra-key-template-find"
	rlRun "pki kra-key-template-find 1> $temp_out1" 
	rlAssertGrep "  Template ID: retrieveKey" "$temp_out1"
	rlAssertGrep "  Template Description: Template for submitting a key retrieval or key recovery request" "$temp_out1"
	rlAssertGrep "  Template ID: generatekey" "$temp_out1"
	rlAssertGrep "  Template Description: Template for submitting a request for generating a symmetric key" "$temp_out1"
	rlAssertGrep "  Template ID: generateKey" "$temp_out1"
	rlAssertGrep "  Template Description: Template for submitting a request for generating a symmetric key" "$temp_out1"
	rlAssertGrep "  Template ID: archiveKey" "$temp_out1"
	rlAssertGrep "  Template Description: Template for submitting a key archival request" "$temp_out1"
	rlPhaseEnd
	
	rlPhaseStartCleanup "pki kra-key-template-find cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlPhaseEnd
}
