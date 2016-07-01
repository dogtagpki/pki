#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/installer-tests/ca-installer.sh
#   Description: PKI CA Installer Test
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Saili Pandit <saipandi@redhat.com>
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
# Include files
. ./acceptance/quickinstall/rhcs-set-time.sh
. ./acceptance/quickinstall/rhcs-install.sh
. ./acceptance/quickinstall/rhcs-install-lib.sh
. /opt/rhqa_pki/env.sh

run_rhcs_ca_installer_tests()
{
	subsystemId=$1
	SUBSYSTEM_TYPE=$2
	MYROLE=$3
	if [ "$TOPO9" = "TRUE" ] ; then
		ADMIN_CERT_LOCATION=$(eval echo \$${subsystemId}_ADMIN_CERT_LOCATION)
		prefix=$subsystemId
		CLIENT_PKCS12_PASSWORD=$(eval echo \$${subsystemId}_CLIENT_PKCS12_PASSWORD)
		admin_cert_nickname=$(eval echo \$${subsystemId}_ADMIN_CERT_NICKNAME)
	elif [ "$MYROLE" = "MASTER" ] ; then
		if [[ $subsystemId == SUBCA* ]]; then
			ADMIN_CERT_LOCATION=$(eval echo \$${subsystemId}_ADMIN_CERT_LOCATION)
			prefix=$subsystemId
			CLIENT_PKCS12_PASSWORD=$(eval echo \$${subsystemId}_CLIENT_PKCS12_PASSWORD)
			admin_cert_nickname=$(eval echo \$${subsystemId}_ADMIN_CERT_NICKNAME)
		else
			ADMIN_CERT_LOCATION=$ROOTCA_ADMIN_CERT_LOCATION
			prefix=ROOTCA
			CLIENT_PKCS12_PASSWORD=$ROOTCA_CLIENT_PKCS12_PASSWORD
			admin_cert_nickname=$ROOTCA_ADMIN_CERT_NICKNAME
		fi
	else
		ADMIN_CERT_LOCATION=$(eval echo \$${MYROLE}_ADMIN_CERT_LOCATION)
		prefix=$MYROLE
		CLIENT_PKCS12_PASSWORD=$(eval echo \$${MYROLE}_CLIENT_PKCS12_PASSWORD)
		admin_cert_nickname=$(eval echo \$${MYROLE}_ADMIN_CERT_NICKNAME)
	fi

	SUBSYSTEM_HOST=$(eval echo \$${MYROLE})
	INSTANCECFG=/tmp/ca_instance.inf

	##### Create a temporary directory to save output files #####
	rlPhaseStartSetup "pki_run_rhcs_ca_installer_tests: Create temporary directory"
		rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
		rlRun "pushd $TmpDir"
	rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-001: Installing and Uninstalling CA"
                run_rhcs_install_packages
                if [ "$prefix" = "ROOTCA" ]; then
                        run_install_subsystem_RootCA
                elif [[ $subsystemId = SUBCA* ]]; then
                        run_install_subsystem_subca
		fi
                rlRun "pkidaemon status tomcat > $TmpDir/ca-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ca-install.out"
                exp_message2_2="PKI Subsystem Type:  Root CA (Security Domain)"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ca-install.out"
                rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)" > $TmpDir/uninstallCA.out
                exp_message2_3="Uninstallation complete"
                rlAssertGrep "$exp_message2_3" "$TmpDir/uninstallCA.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-002: Http port less than 1024"
		local PORT=1023
	        rlLog "Copying config file into temp file"
                rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile1"
                sed -i -e "/pki_https_port/s/=.*/=${PORT}/g" $TmpDir/tmpconfigfile1
                rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile1 > $TmpDir/port_output_file.out 2>&1" 1 "Should not succeed"
                exp_message_1="pkispawn    : ERROR    ....... port $PORT has invalid selinux context hi_reserved_port_t"
                rlAssertGrep "$exp_message_1" "$TmpDir/port_output_file.out"
                exp_message_2="Installation failed"
                rlAssertGrep "$exp_message_2" "$TmpDir/port_output_file.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-003: CA certificate nickname is configurable"
                rlLog "Checking if the nicknames for the CA certificates are configurable"
                rlRun "pkispawn -s CA -f $INSTANCECFG"
                rlRun "certutil -L -d /var/lib/pki/$ROOTCA_TOMCAT_INSTANCE_NAME/alias > $TmpDir/cert_nicknames.out"
                exp_messg1_1="$ROOTCA_OCSP_SIGNING_NICKNAME"
                rlAssertGrep "$exp_messg1_1" "$TmpDir/cert_nicknames.out"
                exp_messg1_2="$ROOTCA_AUDIT_SIGNING_NICKNAME"
                rlAssertGrep "$exp_messg1_2" "$TmpDir/cert_nicknames.out"
                exp_messg1_3="$ROOTCA_SUBSYTEM_NICKNAME"
                rlAssertGrep "$exp_messg1_3" "$TmpDir/cert_nicknames.out"
                exp_messg1_4="$ROOTCA_SSL_SERVER_NICKNAME"
                rlAssertGrep "$exp_messg1_4" "$TmpDir/cert_nicknames.out"
                exp_messg1_5="$ROOTCA_SIGNING_NICKNAME"
                rlAssertGrep "$exp_messg1_5" "$TmpDir/cert_nicknames.out"
        rlPhaseEnd

        rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-004: security domain parameters"
		rlLog "Checking if a new security domain gets created for the CA"
                local password=$(grep "internal=" /var/lib/pki/$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)/conf/password.conf | cut -d '=' -f 2)
                local expfile=$TmpDir/expectfile.in
		rlLog "spawn -noecho "pki -U https://$SUBSYSTEM_HOST:$(eval echo \$${prefix}_SECURE_PORT) -d $(eval echo \$${prefix}_CERTDB_DIR) -w $password securitydomain-show""
                echo "spawn -noecho "pki -U https://$SUBSYSTEM_HOST:$(eval echo \$${prefix}_SECURE_PORT) -d $(eval echo \$${prefix}_CERTDB_DIR) -w $password securitydomain-show"" > $expfile
                echo "expect \"WARNING: UNTRUSTED ISSUER encountered on '$(eval echo \$${subsystemId}_SSL_SERVER_CERT_SUBJECT_NAME)' indicates a non-trusted CA cert '$(eval echo \$${subsystemId}_SIGNING_CERT_SUBJECT_NAME)'
 Import CA certificate (Y/n)? \"" >> $expfile
                echo "send -- \"Y\r\"" >> $expfile
                echo "expect \"CA server URI \[http://$HOSTNAME:8080/ca\]: \"" >> $expfile
                echo "send -- \"http://$HOSTNAME:$(eval echo \$${prefix}_UNSECURE_PORT)/ca\r\"" >> $expfile
                echo "expect eof" >> $expfile
                echo "catch wait result" >> $expfile
                echo "exit [lindex \$result 3]" >> $expfile
                rlRun "/usr/bin/expect -f $expfile >  $TmpDir/pki_run_rhcs_ca_installer_tests-security_domain.out 2>&1" 0 "Should be able to get security domain information"
                exp_messg1_1="Domain: $(hostname -d)"
                rlAssertGrep "$exp_messg1_1" "$TmpDir/pki_run_rhcs_ca_installer_tests-security_domain.out"
                exp_messg1_2="Host ID: CA $(hostname) $(eval echo \$${prefix}_SECURE_PORT)"
                rlAssertGrep "$exp_messg1_2" "$TmpDir/pki_run_rhcs_ca_installer_tests-security_domain.out"
                exp_messg1_3="Hostname: $(hostname)"
                rlAssertGrep "$exp_messg1_3" "$TmpDir/pki_run_rhcs_ca_installer_tests-security_domain.out"
                exp_messg1_4="Port: $(eval echo \$${prefix}_UNSECURE_PORT)"
                exp_messg1_5="Secure Port: $(eval echo \$${prefix}_SECURE_PORT)"
                exp_messg1_6="Domain Manager: TRUE"
		rlLog "cleanup"
		rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
	rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-005: same subject dn for two certs"
                   local subjectdn="cn=Common Name, O=Redhat"
                   rlLog "Copying config file into temp file"
                   rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile2.in"
                   sed -i -e "/pki_ca_signing_subject_dn=/s/=.*/=${subjectdn}/g" $TmpDir/tmpconfigfile2.in
                   sed -i -e "/pki_ocsp_signing_subject_dn=/s/=.*/=${subjectdn}/g" $TmpDir/tmpconfigfile2.in
                   rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile2.in > $TmpDir/nickname-test.out 2>&1" 1 "Should not succeed"
                   exp_message_2="Installation failed"
                   rlAssertGrep "$exp_message_2" "$TmpDir/nickname-test.out"
                   rlLog "cleanup"
                   rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                   rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1184"
	rlPhaseEnd

#  	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-006: same nickname for two certs"
#                  local nickname=commonname
#                   rlLog "Copying config file into temp file"
#                   rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile3.in"
#                   sed -i -e "/pki_ca_signing_nickname=/s/=.*/=${nickname}/g" $TmpDir/tmpconfigfile3.in
#                   sed -i -e "/pki_ocsp_signing_nickname=/s/=.*/=${nickname}/g" $TmpDir/tmpconfigfile3.in
#                   rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile3.in > $TmpDir/nickname_test.out 2>&1" 1 "Should fail"
#                   exp_message_1="certutil: could not decode certificate: SEC_ERROR_REUSED_ISSUER_AND_SERIAL: You are attempting to import a cert with the same issuer/serial as an existing cert, but that is not the same cert."
#                   rlAssertGrep "$exp_message_1" "$TmpDir/nickname_test.out"
#                   exp_message_2="Installation failed"
#                   rlAssertGrep "$exp_message_2" "$TmpDir/nickname_test.out"
#                   rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1184"
#  		 rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
#        rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-007: wrong ldap port"
                   local port=999
                   rlLog "Copying config file into temp file"
                   rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile4.in"
                   sed -i -e "/pki_ds_ldap_port=/s/=.*/=${port}/g" $TmpDir/tmpconfigfile4.in
                   rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile4.in > $TmpDir/ldap_port_test.out 2>&1" 1 "Should fail"
                   exp_message_1="ERROR:  Unable to access directory server: Can't contact LDAP server"
                   rlAssertGrep "$exp_message_1" "$TmpDir/ldap_port_test.out"
        rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-008: give existing base dn"
                  rlLog "Copying config file into temp file"
                  rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile5.in"
                  rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile5.in > $TmpDir/existing_base_dn_1.out"
                  exp_messg1="The URL for the subsystem is:"
                  rlAssertGrep "$exp_messg1" "$TmpDir/existing_base_dn_1.out"
                  exp_messg2="https://$(hostname):$(eval echo \$${prefix}_SECURE_PORT)"
                  rlAssertGrep "$exp_messg2" "$TmpDir/existing_base_dn_1.out"
                  sed -i -e "/pki_ds_remove_data=/s/=.*/=False/g" $TmpDir/tmpconfigfile5.in
		  rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                  rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile5.in > $TmpDir/existing_base_dn_2.out 2>&1" 1 "Should fail"
                  exp_messg3="Installation failed."
                  rlAssertGrep "$exp_messg3" "$TmpDir/existing_base_dn_2.out"
		  rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
          rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-009: checking the pkcs12 password"
		rlRun "pkispawn -s CA -f $INSTANCECFG"
                local password=$(eval echo \$${prefix}_CLIENT_PKCS12_PASSWORD)
                rlRun "pk12util -l $CLIENT_DIR/$(eval echo \$${prefix}_ADMIN_CERT_NICKNAME).p12 -W $password > $TmpDir/pkcs12_password.out"
                exp_messg1="Friendly Name: $(eval echo \$${prefix}_ADMIN_CERT_NICKNAME)"
                rlAssertGrep "$exp_messg1" "$TmpDir/pkcs12_password.out"
                exp_messg2="$(eval echo \$${prefix}_ADMIN_CERT_SUBJECT_NAME)"
                rlAssertGrep "$exp_messg2" "$TmpDir/pkcs12_password.out"
		#cleanup
		rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
          rlPhaseEnd

          rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-010: backup keys parameter"
                  rlLog "Copying config file into temp file"
                  rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile7.in"
                  rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile7.in"
                  rlRun "ls /var/lib/pki/$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)/alias > $TmpDir/ldap_backup_keys_test1.out"
                  exp_messg1_1="ca_backup_keys.p12"
                  rlAssertGrep "$exp_messg1_1" "$TmpDir/ldap_backup_keys_test1.out"
                  sed -i -e "/pki_backup_keys=/s/=.*/=False/g" $TmpDir/tmpconfigfile7.in
		  rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                  rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile7.in"
                  rlRun "ls /var/lib/pki/$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)/alias/ca_backup_keys.p12 > $TmpDir/ldap_backup_keys_test2.out" 2 "Should Fail"
		  rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
        rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-011: backup password"
                  rlLog "Copying config file into temp file"
                  rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile8.in"
                  rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile8.in"
                  rlRun "pk12util -l /var/lib/pki/$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)/alias/ca_backup_keys.p12 -W $(eval echo \$${prefix}_BACKUP_PASSWORD) > $TmpDir/backup_passwd_test.out"
                  exp_messg1_1="Friendly Name: $(eval echo \$${prefix}_SIGNING_CERT_SUBJECT_NAME)"
                  rlAssertGrep "$exp_messg1_1" "$TmpDir/backup_passwd_test.out"
                  exp_messg1_2="Friendly Name: $(eval echo \$${prefix}_OCSP_SIGNING_CERT_SUBJECT_NAME)"
                  rlAssertGrep "$exp_messg1_2" "$TmpDir/backup_passwd_test.out"
                  exp_messg1_3="Friendly Name: $(eval echo \$${prefix}_SUBSYSTEM_CERT_SUBJECT_NAME)"
                  rlAssertGrep "$exp_messg1_3" "$TmpDir/backup_passwd_test.out"
                  exp_messg1_4="Friendly Name: $(eval echo \$${prefix}_AUDIT_SIGNING_CERT_SUBJECT_NAME)"
                  rlAssertGrep "$exp_messg1_4" "$TmpDir/backup_passwd_test.out"
		  rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
	rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-012: client database purge BZ1165873"
                  rlLog "Copying config file into temp file"
                  rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile9.in"
                  rlRun "pkispawn -s CA -f $INSTANCECFG"
                  rlRun "ls $(eval echo \$${prefix}_CERTDB_DIR)" 2 "Should Fail"
		  sed -i -e "/pki_client_database_purge=/s/=.*/=False/g" $TmpDir/tmpconfigfile9.in
		  rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                  rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile9.in"
                  rlRun "ls $(eval echo \$${prefix}_CERTDB_DIR)" 0 "Should succeed"
		  rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
		  rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1165873"
          rlPhaseEnd

	  rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-013: subject name special characters"
                  #two % are required for successful parsing
                  local subjectdn="cn=rh@cs/-$%%!!,O=red^hat"
                  rlLog "Copying config file into temp file"
                  rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile10.in"
                  sed -i -e 's pki_ca_signing_subject_dn=.* pki_ca_signing_subject_dn=cn=rh@cs/-$%%!!,O=red^hat g' $TmpDir/tmpconfigfile10.in
                  rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile10.in > $TmpDir/subjectdn_special_char.out"
                  #expected output & cleanup
                  rlRun "pkidaemon status tomcat > $TmpDir/ca-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ca-install.out"
                exp_message2_2="PKI Subsystem Type:  Root CA (Security Domain)"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ca-install.out"
                  rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)" > $TmpDir/uninstallCA.out
                exp_message2_3="Uninstallation complete"
                rlAssertGrep "$exp_message2_3" "$TmpDir/uninstallCA.out"
          rlPhaseEnd

          rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-014: invalid key size for certificate"
                  local keysize=1234
                  rlLog "Copying config file into temp file"
                  rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile11.in"
                  sed -i -e "/pki_ca_signing_key_size=/s/=.*/=$keysize/g" $TmpDir/tmpconfigfile11.in
                  rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile11.in > $TmpDir/invalid_key.out 2>&1" 1 "Should fail"
                  exp_messg1="Installation failed."
                  rlAssertGrep "$exp_messg1" "$TmpDir/invalid_key.out"
                   #expected output & cleanup
                  rlLog "cleanup"
                  rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                  rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1184"
	rlPhaseEnd

#### Un comment this test only after the bug https://fedorahosted.org/pki/ticket/1185 is fixed. ####
#  	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-015: same port for http and https"
#                  local port=30002
#                  rlLog "Copying config file into temp file"
#                  rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile12.in"
#                  sed -i -e "/pki_http_port=/s/=.*/=$port/g" $TmpDir/tmpconfigfile12.in
#                  sed -i -e "/pki_https_port=/s/=.*/=$port/g" $TmpDir/tmpconfigfile12.in
#                  rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile12.in > $TmpDir/same_ports.out 2>&1" 1 "Should fail" 
#                                                                     
#                  Installing CA into /var/lib/pki/pki-subca.  
#                    Storing deployment configuration into /etc/sysconfig/pki/tomcat/pki-subca/ca/deployment.cfg.  
#                    Traceback (most recent call last):  
#                    File "/usr/lib64/python2.7/logging/__init__.py", line 851, in emit  
#                    msg = self.format(record)  
#                    File "/usr/lib64/python2.7/logging/__init__.py", line 724, in format  
#                    return fmt.format(record)  
#                    File "/usr/lib64/python2.7/logging/__init__.py", line 467, in format  
#                    s = self._fmt % record.__dict__  
#                    KeyError: 'indent'  
#                    Logged from file selinux_setup.py, line 133  
#                    Installation failed.  
#                  exp_messg1="Installation failed."
#                  rlAssertGrep "$exp_messg1" "$TmpDir/same_ports.out"
#                   should give a more desciptive error
#                    expected output & cleanup
#                    ask about this test
#                  rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1185"
#          rlPhaseEnd

         rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-016: long security domain name"
                 local secdomain_name="This is the security domain for a root ca which is the at the highest level in the CA hierarchy"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile13.in"
                 sed -i -e "/pki_security_domain_name=/s/=.*/=$secdomain_name/g" $TmpDir/tmpconfigfile13.in
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile13.in"
		 rlRun "sleep 10"
		 local password=$(grep "internal=" /var/lib/pki/$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)/conf/password.conf | cut -d "=" -f 2)
                 rlRun "pki -U https://$SUBSYSTEM_HOST:$(eval echo \$${prefix}_SECURE_PORT) -d /var/lib/pki/$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)/alias -w $password securitydomain-show > $TmpDir/long_sec_domain_name.out"
                 exp_messg1="Domain: $secdomain_name"
                 rlAssertGrep "$exp_messg1" "$TmpDir/long_sec_domain_name.out"
                 #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
        rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-017: wrong ds password"
                  local password=random
                  rlLog "Copying config file into temp file"
                  rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile14.in"
                  sed -i -e "/pki_ds_password=/s/=.*/=$password/g" $TmpDir/tmpconfigfile14.in
                  rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile14.in > $TmpDir/wrong_ds_passwd.out 2>&1" 1 "Should fail"
                  #expected o/p and cleanup
                  exp_messg1="ERROR:  Unable to access directory server: Invalid credentials"
                  rlAssertGrep "$exp_messg1" "$TmpDir/wrong_ds_passwd.out"
	rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-018: instance creation as non root user"
                 local username=rhcs
                  rlRun "useradd $username"
                  rlRun "cp $INSTANCECFG /home/$username/tmpconfigfile15.in"
                  rlRun "su -c \"pkispawn -s CA -f /home/$username/tmpconfigfile15.in > /home/$username/nonroot.out 2>&1\" $username" 1 "pkispawn as non-root user should fail"
                  exp_messg1="'/usr/sbin/pkispawn' must be run as root!"
                  rlAssertGrep "$exp_messg1" "/home/$username/nonroot.out"
                  rlRun "userdel -r $username"
          rlPhaseEnd


	  rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-019: special characters in certificate nickname"
                 local nickname=rh@cs/-$%%!!red^hat
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile16.in"
                 sed -i -e 's pki_ca_signing_nickname=.* pki_ca_signing_nickname=rh@cs/-$%%!!red^hat g' $TmpDir/tmpconfigfile16.in
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile16.in > $TmpDir/subjectdn_special_char.out"

                 #expected output & cleanup
                rlRun "pkidaemon status tomcat > $TmpDir/ca-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ca-install.out"
                exp_message2_2="PKI Subsystem Type:  Root CA (Security Domain)"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ca-install.out"
                rlLog "cleanup"
                  rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)" > $TmpDir/uninstallCA.out
                exp_message2_3="Uninstallation complete"
                rlAssertGrep "$exp_message2_3" "$TmpDir/uninstallCA.out"
         rlPhaseEnd

          rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-020: ds password not provided"
                  rlLog "Copying config file into temp file"
                  rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile17.in"
                  sed -i -e "/pki_ds_password=/d" $TmpDir/tmpconfigfile17.in
                  rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile17.in > $TmpDir/no_ds_password.out 2>&1" 1 "Should fail"
                  exp_messg1="pkispawn    : ERROR    A value for 'pki_ds_password' MUST be defined in '$TmpDir/tmpconfigfile17.in'"
                  rlAssertGrep "$exp_messg1" "$TmpDir/no_ds_password.out"
                  # expected output & cleanup
          rlPhaseEnd

         rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-021: token and token password"
		 rlRun "pkispawn -s CA -f $INSTANCECFG"
                 local password_token=$(eval echo \$${prefix}_TOKEN_PASSWORD)
                 local password=$(eval echo \$${prefix}_CLIENT_PKCS12_PASSWORD)
                 rlRun "pk12util -l $CLIENT_DIR/$(eval echo \$${prefix}_ADMIN_CERT_NICKNAME).p12 -W $password -K $password_token > $TmpDir/token_password.out"
                 exp_messg1="Friendly Name: $(eval echo \$${prefix}_ADMIN_CERT_NICKNAME)"
                 rlAssertGrep "$exp_messg1" "$TmpDir/token_password.out"
                 exp_messg2="$(eval echo \$${prefix}_ADMIN_CERT_SUBJECT_NAME)"
                 rlAssertGrep "$exp_messg2" "$TmpDir/token_password.out"
		rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
         rlPhaseEnd

         rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-022: invalid email in admin parameters BZ1165875"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile19.in"
                 sed -i -e "/pki_admin_email=/s/=.*/=pki-ca-test/g" $TmpDir/tmpconfigfile19.in
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile19.in > $TmpDir/invalid_email.out 2>&1" 1 "Should fail"
		 exp_messg="Installation failed"
		 rlAssertGrep "$exp_messg" "$TmpDir/invalid_email.out"
		 rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
		 rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1165875"
         rlPhaseEnd

         rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-023: skip configuration"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile20.in"
                 sed -i -e "/pki_skip_configuration=/s/=.*/=True/g" $TmpDir/tmpconfigfile20.in
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile20.in > $TmpDir/skip_config.out"
                 exp_messg1_1="The CA subsystem of the '$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)' instance"
                 rlAssertGrep "$exp_messg1_1" "$TmpDir/skip_config.out"
                 exp_messg1_2="must still be configured!"
                 rlAssertGrep "$exp_messg1_2" "$TmpDir/skip_config.out"
         rlPhaseEnd
        rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-024: skip installation"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile21.in"
                 sed -i -e "/pki_skip_installation=/s/=.*/=True/g" $TmpDir/tmpconfigfile21.in
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile21.in > $TmpDir/skip_install.out"
                 exp_message1="Administrator's username:             $(eval echo \$${prefix}_ADMIN_USER)"
                 rlAssertGrep "$exp_message1" "$TmpDir/skip_install.out"
                 exp_message2="$(eval echo \$${prefix}_DOMAIN)"
                 rlAssertGrep "$exp_message2" "$TmpDir/skip_install.out"
                 exp_message3_1="To check the status of the subsystem:"
                 rlAssertGrep "$exp_message3_1" "$TmpDir/skip_install.out"
                 exp_message3_2="systemctl status pki-tomcatd@$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME).service"
                 rlAssertGrep "$exp_message3_2" "$TmpDir/skip_install.out"
                 exp_message4_1="To restart the subsystem:"
                 rlAssertGrep "$exp_message4_1" "$TmpDir/skip_install.out"
                 exp_message4_2=" systemctl restart pki-tomcatd@$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME).service"
                 rlAssertGrep "$exp_message4_2" "$TmpDir/skip_install.out"
                 exp_message5="The URL for the subsystem is:"
                 rlAssertGrep "$exp_message5" "$TmpDir/skip_install.out"
                 exp_message5_1="https://$(hostname):$(eval echo \$${prefix}_SECURE_PORT)/ca"
                 rlAssertGrep "$exp_message5_1" "$TmpDir/skip_install.out"
                 rlLog "cleanup"
                 rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
        rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-025: installation when another instance is already running"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile22.in"
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile22.in > $TmpDir/install_1.out"
                 exp_messg1="systemctl status pki-tomcatd@$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME).service"
                 rlAssertGrep "$exp_messg1" "$TmpDir/install_1.out"
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile22.in > $TmpDir/install_2.out 2>&1" 1 "Should Fail"
                 exp_messg2="pkispawn    : ERROR    ....... PKI subsystem 'CA' for instance '$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)' already exists!"
                 rlAssertGrep "$exp_messg2" "$TmpDir/install_2.out"
		 rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
         rlPhaseEnd

         rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-026: empty nickname for a certificate"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile23.in"
                 sed -i -e "/pki_ca_signing_nickname=/s/=.*/=/g" $TmpDir/tmpconfigfile23.in
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile23.in"
                 rlRun "certutil -L -d /var/lib/pki/$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)/alias > $TmpDir/empty_nickname.out"
                 exp_messg1="(NULL)"
                 rlAssertGrep "$exp_messg1" "$TmpDir/empty_nickname.out"
                  #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                  #installation goes fine but a null cert gets created which gives segmentation fault on doing a pk12util
                 rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/1184"
         rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-027: Token password parameter has special characters"
                token_password="{\&+\$\@*!"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile27.in"
                 sed -i -e "/pki_token_password=/s/=.*/=$token_password/g" $TmpDir/tmpconfigfile27.in
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile27.in"
		rlRun "pkidaemon status tomcat > $TmpDir/ca-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ca-install.out"
                exp_message2_2="PKI Subsystem Type:  Root CA (Security Domain)"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ca-install.out"
                  #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                 rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/668"
         rlPhaseEnd

        rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-028: Client pkcs12 password parameter has special characters"
                client_password="{\&+\$\@*!"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile28.in"
                 sed -i -e "/pki_client_pkcs12_password=/s/=.*/=$client_password/g" $TmpDir/tmpconfigfile28.in
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile28.in"
		rlRun "pkidaemon status tomcat > $TmpDir/ca-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ca-install.out"
                exp_message2_2="PKI Subsystem Type:  Root CA (Security Domain)"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ca-install.out"
                  #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                 rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/668"
         rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-029: Admin password parameter has special characters"
                admin_password="{\&+\$\@*!"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile29.in"
                 sed -i -e "/pki_admin_password=/s/=.*/=$admin_password/g" $TmpDir/tmpconfigfile29.in
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile29.in"
                rlRun "pkidaemon status tomcat > $TmpDir/ca-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ca-install.out"
                exp_message2_2="PKI Subsystem Type:  Root CA (Security Domain)"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ca-install.out"
                  #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                 rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/668"
         rlPhaseEnd

        rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-030: Backup password parameter has special characters"
                backup_password="{\&+\$\@*!%"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile30.in"
                 sed -i -e "/pki_backup_password=/s/=.*/=$backup_password/g" $TmpDir/tmpconfigfile30.in
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile30.in > $TmpDir/ca30.out 2>&1"
                rlRun "pkidaemon status tomcat > $TmpDir/ca-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ca-install.out"
                exp_message2_2="PKI Subsystem Type:  Root CA (Security Domain)"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ca-install.out"
                  #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                 rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/668"
         rlPhaseEnd

        rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-031: Client database password parameter has special characters"
                clientdb_password="{\&+\$\@*!"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile31.in"
                 sed -i -e "/pki_client_database_password=/s/=.*/=$clientdb_password/g" $TmpDir/tmpconfigfile31.in
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile31.in"
                rlRun "pkidaemon status tomcat > $TmpDir/ca-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ca-install.out"
                exp_message2_2="PKI Subsystem Type:  Root CA (Security Domain)"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ca-install.out"
                  #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                 rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/668"
         rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-032: Interactive CA installation"
                rlLog "Interactive pkispawn of CA"
                local expfile=$TmpDir/expectfile.in
                echo "set timeout 5" > $expfile
                echo "set force_conservative 0" >> $expfile
                echo "set send_slow {1 .1}" >> $expfile
                echo "spawn -noecho pkispawn" >> $expfile
                echo "expect \"Subsystem \(CA/KRA/OCSP/TKS/TPS\) \[CA\]: \"" >> $expfile
                echo "send -- \"\r\"" >> $expfile
                echo "expect \"Instance \[pki-tomcat\]: \"" >> $expfile
                echo "send -- \"$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)\r\"" >> $expfile
                echo "expect \"HTTP port \[8080\]: \"" >> $expfile
                echo "send -- \"$(eval echo \$${prefix}_UNSECURE_PORT)\r\"" >> $expfile
                echo "expect \"Secure HTTP port \[8443\]: \"" >> $expfile
                echo "send -- \"$(eval echo \$${prefix}_SECURE_PORT)\r\"" >> $expfile
                echo "expect \"AJP port \[8009\]: \"" >> $expfile
                echo "send -- \"$(eval echo \$${prefix}_AJP_PORT)\r\"" >> $expfile
                echo "expect \"Management port \[8005\]: \"" >> $expfile
                echo "send -- \"$(eval echo \$${prefix}_TOMCAT_SERVER_PORT)\r\"" >> $expfile
                echo "expect \"Username \[caadmin\]: \"" >> $expfile
                echo "send -- \"$(eval echo \$${prefix}_ADMIN_USER)\r\"" >> $expfile
                echo "expect \"Password: \"" >> $expfile
                echo "send -- \"$(eval echo \$${prefix}_ADMIN_PASSWORD)\r\"" >> $expfile
                echo "expect \"Verify password: \"" >> $expfile
                echo "send -- \"$(eval echo \$${prefix}_ADMIN_PASSWORD)\r\"" >> $expfile
                echo "expect \"Import certificate (Yes\/No) \[N\]? \"" >> $expfile
                if [ $(eval echo \$${prefix}_ADMIN_IMPORT_CERT) = "False" ]; then
                        echo "send -- \"\r\"" >> $expfile
                else
                        echo "send -- \"Y\r\"" >> $expfile
                fi
                echo "expect \"Export certificate to \[/root/.dogtag/pki-tomcat/ca_admin.cert\]: \"" >> $expfile
                echo "send -- \"/root/.dogtag/$(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)/ca_admin.cert\r\"" >> $expfile
                echo "expect \"Hostname \[`hostname`\]: \"" >> $expfile
                echo "send -- \"$LDAP_HOSTNAME\r\"" >> $expfile
                echo "expect \"Use a secure LDAPS connection (Yes\/No\/Quit) \[N\]? \"" >> $expfile
                echo "send -- \"\r\"" >> $expfile
                echo "expect \"Port \[389\]: \"" >> $expfile
                echo "send -- \"$(eval echo \$${prefix}_LDAP_PORT)\r\"" >> $expfile
                echo "expect \"Bind DN \[cn=Directory Manager\]: \"" >> $expfile
                echo "send -- \"$LDAP_ROOTDN\r\"" >> $expfile
                echo "expect \"Password: \"" >> $expfile
                echo "send -- \"$LDAP_ROOTDNPWD\r\"" >> $expfile
                echo "expect \"Base DN \[o=pki-tomcat-CA\]: \"" >> $expfile
                echo "send -- \"$(eval echo \$${prefix}_DB_SUFFIX)\r\"" >> $expfile
                echo "expect \"Name \[`hostname -d` Security Domain\]: \"" >> $expfile
                echo "send -- \"\r\"" >> $expfile
                echo "expect \"Begin installation (Yes/No/Quit)? \"" >> $expfile
                echo "send -- \"Yes\r\"" >> $expfile
                echo "expect eof" >> $expfile
                echo "catch wait result" >> $expfile
                echo "exit [lindex \$result 3]" >> $expfile
                rlRun "/usr/bin/expect -f $expfile >  $TmpDir/pkispawn_ca.out 2>&1" 0 "Interactive pkispawn of CA should be successful"
                rlRun "sleep 10"
                rlRun "pkidaemon status tomcat > $TmpDir/ca-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ca-install.out"
                exp_message2_2="PKI Subsystem Type:  Root CA (Security Domain)"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ca-install.out"
                rlLog "cleanup"
                rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
        rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-033: Security domain password parameter has special characters"
                sec_password="{\&+\$\@*!"
                 rlLog "Copying config file into temp file"
                 rlRun "cp $INSTANCECFG $TmpDir/tmpconfigfile32.in"
                 sed -i -e "/pki_security_domain_password=/s/=.*/=$sec_password/g" $TmpDir/tmpconfigfile32.in
                 rlRun "pkispawn -s CA -f $TmpDir/tmpconfigfile32.in"
                rlRun "pkidaemon status tomcat > $TmpDir/ca-install.out"
                exp_message2_1="PKI Instance Name:   $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
                rlAssertGrep "$exp_message2_1" "$TmpDir/ca-install.out"
                exp_message2_2="PKI Subsystem Type:  Root CA (Security Domain)"
                rlAssertGrep "$exp_message2_2" "$TmpDir/ca-install.out"
                  #expected output & cleanup
                 rlLog "cleanup"
                 rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)"
		rlRun "remove-ds.pl -f -i slapd-pki-ca-ldap" 0 "CA ldap instance removed"
                 rlLog "PKI Ticket: https://fedorahosted.org/pki/ticket/668"
         rlPhaseEnd

	rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-034: CA signed by an external CA - Dogtag Certificate"
                number=1
                csr_file=$TmpDir/ca_signing.csr
                certtype="Dogtag"
                run_rhcs_install_packages
                run_install_subsystem_RootCA
                run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
                rlLog "rhcs_install_CAwithExtCA $number $csr_file $certtype $ROOTCA_ADMIN_CERT_LOCATION $CLIENT_PKCS12_PASSWORD $admin_cert_nickname $SUBSYSTEM_HOST"
                rhcs_install_CAwithExtCA $number $csr_file $certtype $ROOTCA_ADMIN_CERT_LOCATION $CLIENT_PKCS12_PASSWORD $admin_cert_nickname $SUBSYSTEM_HOST
                rlRun "remove-ds.pl -f -i slapd-pki-subca${number}" 0 "SUBCA ldap instance removed"
                rlRun "pkidestroy -s CA -i $(eval echo \$${prefix}_TOMCAT_INSTANCE_NAME)" > $TmpDir/uninstallCA.out
                exp_message2_3="Uninstallation complete"
                rlAssertGrep "$exp_message2_3" "$TmpDir/uninstallCA.out"
                rlRun "pkidestroy -s CA -i $(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME)" > $TmpDir/uninstallCA.out
                exp_message2_3="Uninstallation complete"
                rlAssertGrep "$exp_message2_3" "$TmpDir/uninstallCA.out"
         rlPhaseEnd

        rlPhaseStartTest "pki_run_rhcs_ca_installer_tests-035: CA signed by an external CA - Microsoft CA Certificate"
                number=1
                csr_file=$TmpDir/msca_signing.csr
                certtype="MSCA"
                run_rhcs_install_packages
                rlLog "rhcs_install_CAwithExtCA $number $csr_file $certtype"
                rhcs_install_CAwithExtCA $number $csr_file $certtype
                rlRun "pkidestroy -s CA -i $(eval echo \$SUBCA${number}_TOMCAT_INSTANCE_NAME)" > $TmpDir/uninstallCA.out
                exp_message2_3="Uninstallation complete"
                rlAssertGrep "$exp_message2_3" "$TmpDir/uninstallCA.out"
                rlRun "remove-ds.pl -f -i slapd-pki-subca${number}" 0 "SUBCA ldap instance removed"
         rlPhaseEnd

	rlPhaseStartSetup "pki_run_rhcs_ca_installer_tests-cleanup"
        #Delete temporary directory
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
	if [ "$prefix" = "ROOTCA" ]; then
                rlRun "remove-ds.pl -f -i slapd-pki-ca-ldap" 0 "CA ldap instance removed"
        elif [[ $subsystemId = SUBCA* ]]; then
                rlRun "remove-ds.pl -f -i slapd-pki-subca1" 0 "SUBCA ldap instance removed"
        fi
        rlPhaseEnd
}
