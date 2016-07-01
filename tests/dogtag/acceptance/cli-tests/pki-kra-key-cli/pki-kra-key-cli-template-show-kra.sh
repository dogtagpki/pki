#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-kra-key-cli
#   Description: PKI KRA KEY CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki key cli commands needs to be tested:
#  pki kra-key-template-show
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

run_pki-kra-key-template-show-kra_tests()
{
	rlPhaseStartSetup "Create Temporary Directory"
	rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
	rlRun "pushd $TmpDir"
	rlPhaseEnd
	local keytemplates=("retrieveKey" "generatekey" "archiveKey")
	local temp_out1="$TmpDir/pki_kra_key_template_show_001"

	rlPhaseStartTest "pki kra-key-template-show --help Test: Show all the options of pki kra-key-template-show"
	local temp_out="$TmpDir/pki_key-template-show"
	rlLog "Executing pki kra-key-template-show --help"
	rlRun "pki kra-key-template-show --help 1> $temp_out" 0 "pki key-template-show --help"
	rlAssertGrep "usage: kra-key-template-show <Template ID> \[OPTIONS...\]" "$temp_out"
	rlAssertGrep "    --help                                           Show help options" "$temp_out"
	rlAssertGrep "    --output-file <File to write the template to.>   Location where the" "$temp_out"
	rlAssertGrep "                                                     template has to be" "$temp_out"
	rlAssertGrep "                                                     stored." "$temp_out"
	rlPhaseEnd

	rlPhaseStartTest "pki_kra_key_template_show-001: verify when valid key-template is provided key-template-show should details of the template"
	for i in "${keytemplates[@]}"; do
	rlRun "pki kra-key-template-show $i > $temp_out1" 0 "Executing pki kra-key-template-show $i"
	done
	rlPhaseEnd


	rlPhaseStartTest "pki_tey_template_show-002: verify when invalid key-template is provided key-template-show should fail"
	local template=InvalidTemplate
	rlRun "pki kra-key-template-show $template > $temp_out1 2>&1" 255,1 "Executing pki kra-key-template-show $template"
	rlAssertGrep "Error: /usr/share/pki/key/templates/$template.xml (No such file or directory)" "$temp_out1"
	rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_template_show-003: verify template files are saved and the xml file is valid"
        for i in "${keytemplates[@]}"; do
        rlRun "pki kra-key-template-show $i --output $i-xml"  0 "Save $i template in $i-xml"
        rlLog "Validate $i-.xml"
        rlRun "xmlstarlet val -w $i-xml 1> $temp_out"
        rlAssertGrep "$i-xml - valid" "$temp_out"
        done
        rlPhaseEnd

        rlPhaseStartTest "pki_kra_key_template_show-004: Pass junk data as template and verify template-show fails"
        template = $tmp_junk_data
        rlRun "pki kra-key-template-show $tmp_junk_data 2> $temp_out" 255,1 "Passing junk data to template-show"
        rlAssertGrep "Error: /usr/share/pki/key/templates/$tmp_junk_data\.xml (No such file or directory)" "$temp_out"
        rlPhaseEnd

	rlPhaseStartCleanup "pki kra-key-template-show cleanup: Delete temp dir"
	rlRun "popd"
	rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlPhaseEnd
}
