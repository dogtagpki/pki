#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/installer-tests/tks-installer.sh
#   Description: PKI TKS Installer Test
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
# Include files
. ./acceptance/quickinstall/rhcs-set-time.sh
. ./acceptance/quickinstall/rhcs-install.sh
. ./acceptance/quickinstall/rhcs-install-lib.sh
. /opt/rhqa_pki/env.sh
run_rhcs_tks_installer_tests()
{
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3
	if [ "$TOPO9" = "TRUE" ] ; then
        	ADMIN_CERT_LOCATION=$(eval echo \$${subsystemId}_ADMIN_CERT_LOCATION)
	        prefix=$subsystemId
        	CLIENT_PKCS12_PASSWORD=$(eval echo \$${subsystemId}_CLIENT_PKCS12_PASSWORD)
	elif [ "$MYROLE" = "MASTER" ] ; then
        	if [[ $subsystemId == SUBCA* ]]; then
                	ADMIN_CERT_LOCATION=$(eval echo \$${subsystemId}_ADMIN_CERT_LOCATION)
	                prefix=$subsystemId
        	        CLIENT_PKCS12_PASSWORD=$(eval echo \$${subsystemId}_CLIENT_PKCS12_PASSWORD)	
        	else
                	ADMIN_CERT_LOCATION=$ROOTCA_ADMIN_CERT_LOCATION
	                prefix=ROOTCA
        	        CLIENT_PKCS12_PASSWORD=$ROOTCA_CLIENT_PKCS12_PASSWORD
        	fi
	else
        	ADMIN_CERT_LOCATION=$(eval echo \$${MYROLE}_ADMIN_CERT_LOCATION)
	        prefix=$MYROLE
	        CLIENT_PKCS12_PASSWORD=$(eval echo \$${MYROLE}_CLIENT_PKCS12_PASSWORD)
	fi

	SUBSYSTEM_HOST=$(eval echo \$${MYROLE})
	INSTANCECFG=/tmp/tks_instance.inf
	##### Create a temporary directory to save output files #####
	rlPhaseStartSetup "pki_run_rhcs_tks_installer_tests: Create temporary directory"
        	rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        	rlRun "pushd $TmpDir"
	rlPhaseEnd
 	rlPhaseStartTest "pki_run_rhcs_tks_installer_tests-001: Installing and Uninstalling TKS"
 		 local number=3
		 local BEAKERMASTER=`hostname`
		 local CA=ROOTCA
                 run_rhcs_install_packages
                 run_install_subsystem_RootCA 
		 run_install_subsystem_TKS $number $BEAKERMASTER $CA
                 rlRun "pkidaemon status tomcat > $TmpDir/tks-install.out"
                 exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                 rlAssertGrep "$exp_message2_1" "$TmpDir/tks-install.out"
                 exp_message2_2="PKI Subsystem Type:   (Security Domain)"
                 rlAssertGrep "$exp_message2_2" "$TmpDir/tks-install.out"
                 rlLog "Uninstall TKS tests"
                 rlRun "pkidestroy -s TKS -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)" > $TmpDir/uninstallKRA.out
                 exp_message2_3 "Uninstallation complete" "$TmpDir/uninstallTKS.out"
                 rlAssertGrep "$exp_message2_3" "$TmpDir/uninstallTKS.out"
 
         rlPhaseEnd
	rlPhaseStartTest "pki_run_rhcs_tks_installer_tests-002: SSL cert parameters"
		cp $INSTANCECFG $TmpDir/tmpconfig1.in
		sed -i -e "/pki_ssl_server_key_type/d" $TmpDir/tmpconfig1.in
		sed -i -e "/pki_ssl_server_token/d" $TmpDir/tmpconfig1.in
		sed -i -e "/pki_ssl_server_signing_algorithm/d" $TmpDir/tmpconfig1.in
		sed -i -e "/pki_ssl_server_key_algorithm/d" $TmpDir/tmpconfig1.in
		sed -i -e "/pki_ssl_server_key_size/d" $TmpDir/tmpconfig1.in
		sed -i -e "/pki_ssl_server_nickname/d" $TmpDir/tmpconfig1.in
		sed -i -e "/pki_ssl_server_subject_dn/d" $TmpDir/tmpconfig1.in
		rlRun "pkispawn -s TKS -f $TmpDir/tmpconfig1.in  > $TmpDir/tks_ssl.out 2>&1" 1 "Should fail"
                exp_messg3="Installation Failed."
                rlAssertGrep "$exp_messg3" "$TmpDir/tks_ssl.out"
	rlPhaseEnd
}
