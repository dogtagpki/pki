#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-ca-user-cli
#   Description: PKI user-cert CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki ca-user-cert cli commands needs to be tested:
#  pki-ca-user-cert
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

# pki ca-user-cert ran without any options should show all the command line options of pki cert
run_pki-ca-user-cert()
{
	subsystemId=$1
        SUBSYSTEM_TYPE=$2
        MYROLE=$3
        rlPhaseStartSetup "Create Temporary Directory "
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

        get_topo_stack $MYROLE $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        ca_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
        prefix=$CA_INST
        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$MYROLE" = "MASTER" ] ; then
                if [[ $CA_INST == SUBCA* ]]; then
                        prefix=$CA_INST
                        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
                else
                        prefix=ROOTCA
                        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
                fi
        else
                prefix=$MYROLE
                ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
        fi
if [ "$ca_instance_created" = "TRUE" ] ;  then
SUBSYSTEM_HOST=$(eval echo \$${MYROLE})

	rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-001: pki ca-user-cert help option"
	local temp_out="$TmpDir/pki_user-cert"
	rlLog "Executing pki user-cert --help"
	rlRun "pki ca-user-cert --help 1> $temp_out" 0 "pki ca-user-cert --help"
	rlAssertGrep "Commands:"  "$temp_out"
	rlAssertGrep "ca-user-cert-find       Find user certificates" "$temp_out"
	rlAssertGrep "ca-user-cert-show       Show user certificate" "$temp_out"
	rlAssertGrep "ca-user-cert-add        Add user certificate" "$temp_out"
	rlAssertGrep "ca-user-cert-del        Remove user certificate" "$temp_out"
	rlPhaseEnd
	
	rlPhaseStartTest "pki_ca_user_cli_ca_user_cert-002: pki ca-user-cert with junk characters should return invalid module"
	local temp_out1="$TmpDir/pki_ca-user-cert001"
	local rand=`cat /dev/urandom | tr -dc 'a-zA-Z0-9*?$@#!%^&*()' | fold -w 40 | head -n 1`
	rlLog "Executing pki ca-user-cert \"$rand\" characters"
	rlRun "pki ca-user-cert \"$rand\" 2> $temp_out1" 255 "Command pki ca-user-cert with junk characters"
	rlAssertGrep "Error: Invalid module" "$temp_out1"
	rlPhaseEnd
	
	rlPhaseStartCleanup "pki user-cert cleanup: Delete temp dir"
	rlRun "popd"
	rlPhaseEnd
else
	rlLog "CA instance is not installed"
fi
}
