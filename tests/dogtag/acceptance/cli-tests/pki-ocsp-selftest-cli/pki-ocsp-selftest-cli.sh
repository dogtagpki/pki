#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ocsp-selftest
#   Description: pki ocsp selftest tests
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
. /opt/rhqa_pki/env.sh

run_pki-ocsp-selftest_tests()
{
	rlPhaseStartSetup "Create Temporary Directory"
	rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
	rlRun "pushd $TmpDir"
	rlPhaseEnd

	rlPhaseStartTest "pki ocsp-selftest --help Test: Show all the options of pki ocsp-selftest"
	local temp_out="$TmpDir/pki_ocsp_selftest"
	rlLog "Executing pki ocsp-selftest --help"
	rlRun "pki ocsp-selftest --help 1> $temp_out" 0 "pki ocsp-selftest --help"
	rlAssertGrep "Commands:"	"$temp_out"
	rlAssertGrep " ocsp-selftest-find      Find selftests" "$temp_out"
	rlAssertGrep " ocsp-selftest-run       Run selftests" "$temp_out"
	rlAssertGrep " ocsp-selftest-show      Show selftest" "$temp_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_ocsp_selftest-001: pki ocsp-selftest with characters should return invalid module"
	local temp_out1="$TmpDir/pki_ocsp_selftest001"
	local rand=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
	rlLog "Executing pki ocsp-selftest \"$junk\" characters"
	rlRun "pki ocsp-selftest \"$junk\" 2> $temp_out1" 1,255 "Command pki ocsp-selftest with junk characters"
	rlAssertGrep "Error: Invalid module" "$temp_out1"
	rlPhaseEnd
	
	rlPhaseStartCleanup "pki ocsp-selftest cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlPhaseEnd
}
