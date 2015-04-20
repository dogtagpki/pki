#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/installer-tests/ocsp-installer.sh
#   Description: PKI OCSP Installer Test
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
run_rhcs_ocsp_installer_tests()
{
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3
	if [ "$TOPO9" = "TRUE" ] ; then
	        prefix=$subsystemId
	elif [ "$MYROLE" = "MASTER" ] ; then
		if [[ $subsystemId == SUBCA* ]]; then
	                prefix=$subsystemId
		else
	                prefix=ROOTCA
		fi
	else
	        prefix=$MYROLE
	fi

	SUBSYSTEM_HOST=$(eval echo \$${MYROLE})
	INSTANCECFG=/tmp/ocsp_instance.inf
	##### Create a temporary directory to save output files #####
	rlPhaseStartSetup "pki_run_rhcs_ocsp_installer_tests: Create temporary directory"
		rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
		rlRun "pushd $TmpDir"
	rlPhaseEnd
	rlPhaseStartTest "pki_run_rhcs_ocsp_installer_tests-001: Installing and Uninstalling OCSP"
		 local number=3
		 local BEAKERMASTER=`hostname`
		 local CA=ROOTCA
                 run_rhcs_install_packages
                 run_install_subsystem_RootCA
		 run_install_subsystem_ocsp $number $BEAKERMASTER $CA
                 rlRun "pkidaemon status tomcat > $TmpDir/ocsp-install.out"
                 exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                 rlAssertGrep "$exp_message2_1" "$TmpDir/ocsp-install.out"
                 exp_message2_2="PKI Subsystem Type:  OCSP"
                 rlAssertGrep "$exp_message2_2" "$TmpDir/ocsp-install.out"
                 rlLog "Uninstall OCSP tests"
                 rlRun "pkidestroy -s OCSP -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)" > $TmpDir/uninstallOCSP.out
                 exp_message2_3="Uninstallation complete"
                 rlAssertGrep "$exp_message2_3" "$TmpDir/uninstallOCSP.out"
         rlPhaseEnd
	rlPhaseStartTest "pki_run_rhcs_ocsp_installer_tests-002: SSL cert parameters"
		cp $INSTANCECFG $TmpDir/tmpconfig1.in
		sed -i -e "/pki_ssl_server_key_type/d" $TmpDir/tmpconfig1.in
		rlRun "sleep 5"
		sed -i -e "/pki_ssl_server_token/d" $TmpDir/tmpconfig1.in
		rlRun "sleep 5"
		sed -i -e "/pki_ssl_server_signing_algorithm/d" $TmpDir/tmpconfig1.in
		rlRun "sleep 5"
		sed -i -e "/pki_ssl_server_key_algorithm/d" $TmpDir/tmpconfig1.in
		rlRun "sleep 5"
		sed -i -e "/pki_ssl_server_key_size/d" $TmpDir/tmpconfig1.in
		rlRun "sleep 5"
		sed -i -e "/pki_ssl_server_nickname/d" $TmpDir/tmpconfig1.in
		rlRun "sleep 5"
		sed -i -e "/pki_ssl_server_subject_dn/d" $TmpDir/tmpconfig1.in
		rlRun "sleep 5"
		rlRun "pkispawn -s OCSP -f $TmpDir/tmpconfig1.in  > $TmpDir/ocsp_ssl.out 2>&1" 1 "Should fail"
                exp_messg3="Installation failed."
                rlAssertGrep "$exp_messg3" "$TmpDir/ocsp_ssl.out"
		rlRun "pkidestroy -s OCSP -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)" 0 "Uninstalled OCSP"
                rlRun "sleep 20"
		rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)" 0 "Uninstalled CA"
                rlRun "sleep 20"
	rlPhaseEnd
	rlPhaseStartTest "pki_run_rhcs_ocsp_installer_tests-003: Token password parameter has special characters"
                token_password="{\&+\$\@*!"
		INSTANCECFG_CA=/tmp/ca_instance.inf
                rlRun "pkispawn -s CA -f $INSTANCECFG_CA" 0 "Install CA"
                rlRun "sleep 20"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile3.in"
                 sed -i -e "/pki_token_password=/s/=.*/=$token_password/g" $TmpDir/tmpconfigfile3.in
                 rlRun "pkispawn -s OCSP -f $TmpDir/tmpconfigfile3.in"
                rlRun "pkidaemon status tomcat > $TmpDir/ocsp-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ocsp-install.out"
                exp_message2_2="PKI Subsystem Type:  OCSP"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ocsp-install.out"
                  #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s OCSP -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlRun "sleep 20"
         rlPhaseEnd

        rlPhaseStartTest "pki_run_rhcs_ocsp_installer_tests-004: Client pkcs12 password parameter has special characters"
                client_password="{\&+\$\@*!"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile4.in"
                 sed -i -e "/pki_client_pkcs12_password=/s/=.*/=$client_password/g" $TmpDir/tmpconfigfile4.in
                 rlRun "pkispawn -s OCSP -f $TmpDir/tmpconfigfile4.in"
                rlRun "pkidaemon status tomcat > $TmpDir/kra-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ocsp-install.out"
                exp_message2_2="PKI Subsystem Type:  OCSP"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ocsp-install.out"
                  #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s OCSP -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlRun "sleep 20"
         rlPhaseEnd

        rlPhaseStartTest "pki_run_rhcs_ocsp_installer_tests-005: Admin password parameter has special characters"
                admin_password="{\&+\$\@*!"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile5.in"
                 sed -i -e "/pki_admin_password=/s/=.*/=$admin_password/g" $TmpDir/tmpconfigfile5.in
                 rlRun "pkispawn -s OCSP -f $TmpDir/tmpconfigfile5.in"
                rlRun "pkidaemon status tomcat > $TmpDir/ocsp-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ocsp-install.out"
                exp_message2_2="PKI Subsystem Type:  OCSP"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ocsp-install.out"
                  #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s OCSP -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlRun "sleep 20"
         rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ocsp_installer_tests-006: Backup password parameter has special characters"
                backup_password="{\&+\$\@*!%"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile6.in"
                 sed -i -e "/pki_backup_password=/s/=.*/=$backup_password/g" $TmpDir/tmpconfigfile6.in
                 rlRun "pkispawn -s OCSP -f $TmpDir/tmpconfigfile6.in"
                rlRun "pkidaemon status tomcat > $TmpDir/ocsp-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ocsp-install.out"
                exp_message2_2="PKI Subsystem Type:  OCSP"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ocsp-install.out"
                  #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s OCSP -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlRun "sleep 20"
         rlPhaseEnd

        rlPhaseStartTest "pki_run_rhcs_ocsp_installer_tests-007: Client database password parameter has special characters"
                clientdb_password="{\&+\$\@*!"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile7.in"
                 sed -i -e "/pki_client_database_password=/s/=.*/=$clientdb_password/g" $TmpDir/tmpconfigfile7.in
                 rlRun "pkispawn -s OCSP -f $TmpDir/tmpconfigfile7.in"
                rlRun "pkidaemon status tomcat > $TmpDir/ocsp-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ocsp-install.out"
                exp_message2_2="PKI Subsystem Type:  OCSP"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ocsp-install.out"
                  #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s OCSP -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlRun "sleep 20"
         rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ocsp_installer_tests-008: Security domain password parameter has special characters - Ticket 668"
                sec_password="{\&+\$\@*!"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile8.in"
                 sed -i -e "/pki_security_domain_password=/s/=.*/=$sec_password/g" $TmpDir/tmpconfigfile8.in
                 rlRun "pkispawn -s OCSP -f $TmpDir/tmpconfigfile8.in > $TmpDir/ocsp8.out 2>&1"
                rlRun "pkidaemon status tomcat > $TmpDir/ocsp-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ocsp-install.out"
                exp_message2_2="PKI Subsystem Type:  OCSP"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ocsp-install.out"
                  #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s OCSP -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)" 0 "Unistall OCSP"
                rlRun "sleep 20"
                rlLog "https://fedorahosted.org/pki/ticket/668"
         rlPhaseEnd

	rlPhaseStartSetup "pki_run_rhcs_ocsp_installer_tests-cleanup"
        #Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	rlRun "remove-ds.pl -f -i slapd-pki-ocsp3-ldap" 0 "OCSP ldap instance removed"
        rlRun "remove-ds.pl -f -i slapd-pki-ca-ldap" 0 "CA ldap instance removed"
	rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)" 0 "Uninstalled CA"
        rlPhaseEnd
}
