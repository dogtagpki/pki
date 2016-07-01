#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ca-profile-cli
#   Description: PKI CA PROFILE CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki key cli commands needs to be tested:
#  pki ca-profile --help
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

# pki key ran without any options should show all the command line options of pki ca-profile
run_pki-ca-profile_tests()
{
	rlPhaseStartSetup "Create Temporary Directory"
	rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
	rlRun "pushd $TmpDir"
	rlPhaseEnd

	rlPhaseStartTest "pki-ca profile config test: Show all the options of pki ca-profile"
	local temp_out="$TmpDir/pki-ca-profile-help"
	rlLog "Executing pki ca-profile --help"
	rlRun "pki ca-profile --help 1> $temp_out" 0 "pki ca-profile --help"
	rlAssertGrep "Commands:" "$temp_out"
    	rlAssertGrep " ca-profile-find         Find profiles" "$temp_out"
	rlAssertGrep " ca-profile-show         Show profiles" "$temp_out"
    	rlAssertGrep " ca-profile-add          Add profiles" "$temp_out"
    	rlAssertGrep " ca-profile-mod          Modify profiles" "$temp_out"
    	rlAssertGrep " ca-profile-del          Remove profiles" "$temp_out"
    	rlAssertGrep " ca-profile-enable       Enable profiles" "$temp_out"
    	rlAssertGrep " ca-profile-disable      Disable profiles" "$temp_out"
    	rlPhaseEnd
	
	rlPhaseStartTest "pki-ca-profile-001: pki ca-profile with junk characters should return invalid module"
	local temp_out1="$TmpDir/pki_ca-profile001"
    	local junk=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
	rlLog "Executing pki ca-profile \"$junk\" characters"
	rlRun "pki ca-profile \"$junk\" 2> $temp_out1" 1,255 "Command pki ca-profile with junk characters"
	rlAssertGrep "Error: Invalid module" "$temp_out1"
	rlPhaseEnd

	rlPhaseStartCleanup "pki ca-profile cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlPhaseEnd
}
