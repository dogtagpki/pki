#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-kra-selftest-cli
#
#   Description: PKI KRA SELFTEST CLI
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki kra-selftest cli commands needs to be tested:
#  pki ca-selftest-admin
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Niranjan Mallapadi <mrniranjan@redhat.com>
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

run_pki-ca-selftest-admin_tests()
{
        # Local Variables
	local cs_Type=$1
	local cs_Role=$2

        # Creating Temporary Directory for pki ca-selftest-admin
        rlPhaseStartSetup "pki ca-selftest-admin Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

	get_topo_stack $cs_Role $TmpDir/topo_file
        local CA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        ca_instance_created="False"
        if [ "$TOPO9" = "TRUE" ] ; then
                prefix=$CA_INST
                ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
        elif [ "$cs_Role" = "MASTER" ] ; then
                if [[ $CA_INST == SUBCA* ]]; then
                        prefix=$CA_INST
                        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
                else
                        prefix=ROOTCA
                        ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
                fi
        else
                prefix=$cs_Role
                ca_instance_created=$(eval echo \$${CA_INST}_INSTANCE_CREATED_STATUS)
        fi
if [ "$ca_instance_created" = "TRUE" ] ;  then

	local tomcat_name=$(eval echo \$${CA_INST}_TOMCAT_INSTANCE_NAME)
        local target_secure_port=$(eval echo \$${CA_INST}_SECURE_PORT)
        local tmp_ca_agent=$CA_INST\_agentV
        local tmp_ca_admin=$CA_INST\_adminV
        local tmp_ca_port=$(eval echo \$${CA_INST}_UNSECURE_PORT)
        local tmp_ca_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$CA_INST\_agentV
        local valid_audit_cert=$CA_INST\_auditV
        local valid_operator_cert=$CA_INST\_operatorV
        local valid_admin_cert=$CA_INST\_adminV
        local revoked_agent_cert=$CA_INST\_agentR
        local revoked_admin_cert=$CA_INST\_adminR
        local expired_admin_cert=$CA_INST\_adminE
        local expired_agent_cert=$CA_INST\_agentE
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
        local cert_info="$TmpDir/cert_info"
        local ca_selftest_show_output=$TmpDir/ca-selftest-admin.out
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
	### Config file
	local ca_config_file="/var/lib/pki/${tomcat_name}/ca/conf/CS.cfg"
	local ca_db="/var/lib/pki/${tomcat_name}/ca/alias/"
	local ca_cert_list="transport,storage,sslserver,subsystem,audit_signing"
	local ca_cert_list="signing,ocsp_signing,sslserver,subsystem,audit_signing"
	local ca_signing_nick=$(cat $ca_config_file | grep ca.signing.nickname | cut -d= -f2)
	local ca_ocsp_signing_nick=$(cat $ca_config_file | grep ca.ocsp_signing.nickname | cut -d= -f2)
	local ca_sslserver_nick=$(cat $ca_config_file | grep ca.sslserver.nickname | cut -d= -f2)
	local ca_subsystem_nick=$(cat $ca_config_file | grep ca.subsystem.nickname | cut -d= -f2)
	local ca_audit_nick=$(cat $ca_config_file | grep ca.audit_signing.nickname | cut -d= -f2)
	local ca_token=$(cat $ca_config_file | grep ca.signing.tokenname | cut -d= -f2)
	local ca_token_internal_passwd=$(cat /var/lib/pki/$tomcat_name/conf/password.conf | grep internal | cut -d= -f2)
	local ca_hsm_passwd=$(cat /var/lib/pki/${tomcat_name}/conf/password.conf | grep internal | cut -d= -f2)
	local signed_ca_audit_log="/var/log/pki/${tomcat_name}/ca/signedAudit/ca_audit"
	local selftest_log="/var/log/pki/${tomcat_name}/ca/selftests.log"
	local selftest_system_verification=$(cat $ca_config_file | grep selftests.container.order.startup | cut -d= -f2)
	rlLog "selftest_system_verification=$selftest_system_verification"

	rlPhaseStartSetup "Take backup of tomcatjss xml"
	local tomcat_jss_xml_dir="/etc/pki/$tomcat_name/Catalina/localhost"
	local tomcat_jss_xml_backup_dir="$TmpDir/tomcat_jss_backup"
	rlLog "Take backup of $tomcat_jss_xml_dir Directory"
	rlRun "cp -a $tomcat_jss_xml_dir $TmpDir/tomcat_jss_backup"
	rlPhaseEnd

	rlPhaseStartTest "Restart CA subsystem and make sure self tests executed successfully when self tests for system certs verification categorized as \"critical\" has valid system certificates."
	local ca_cert_list_exist=$(cat $ca_config_file | grep ^ca.cert.list | cut -d= -f2)
	rlLog "Verify if configuration file exists"
	rlAssertExists "$ca_config_file"
	rlAssertEquals "Verify $ca_config_file has  list of system certificates parameter" "$ca_cert_list" "$ca_cert_list_exist"
	if [ "${ca_token}" = "Internal Key Storage Token" ]; then
		rlRun "certutil -L -d $ca_db -n \"$ca_signing_nick\" > ${TmpDir}/cert.out" 0 "Verifying if ca signing cert exists in certificate db"
		rlRun "certutil -L -d $ca_db -n \"$ca_ocsp_signing_nick\" > ${TmpDir}/cert.out" 0 "Verifying if ocsp signing cert exists in certificate db"
		rlRun "certutil -L -d $ca_db -n \"$ca_sslserver_nick\" > ${TmpDir}/cert.out" 0 "Verifying if sslserver cert exists in certificate db"
		rlRun "certutil -L -d $ca_db -n \"$ca_subsystem_nick\" > ${TmpDir}/cert.out" 0 "Verifying if subsystem cert exists in certificate db"
		rlRun "certutil -L -d $ca_db -n \"$ca_audit_nick\" > ${TmpDir}/cert.out" 0 "Verifying if audit_signing cert exists in certificate db"
	elif [ "${ca_token}" = "NHSM6000" ]; then
		rlRun "echo ${ca_hsm_passwd} > ${TmpDir}/hsm_passwd" 0 "Save hsm passwd in a file"
		rlRun "certutil -L -d $ca_db -h $ca_token -f $TmpDir/hsm_passwd -n \"$ca_signing_nick\" > $TmpDir/cert.out" 0 "Verifying if ca signing cert exists in certificate db"
		rlRun "certutil -L -d $ca_db -h $ca_token -f $TmpDir/hsm_passwd -n \"$ca_ocsp_signing_nick\" > $TmpDir/cert.out" 0 "Verifying if ocsp signing cert exists in certificate db"
		rlRun "certutil -L -d $ca_db -h $ca_token -f $TmpDir/hsm_passwd -n \"$ca_sslserver_nick\" > $TmpDir/cert.out" 0 "Verifying if sslserver cert exists in certificate db"
		rlRun "certutil -L -d $ca_db -h $ca_token -f $TmpDir/hsm_passwd -n \"$ca_subsystem_nick\" > $TmpDir/cert.out" 0 "Verifying if subsystem cert exists in certificate db"
		rlRun "certutil -L -d $ca_db -h $ca_token -f $TmpDir/hsm_passwd -n \"$ca_audit_nick\" > $TmpDir/cert.out" 0 "Verifying if audit_signing cert exists in certificate db"
	fi
	rlLog "Restart $tomcat_name instance"

	local cur_date=$(date +%d/%b/%Y:%H:%M)
	rhcs_stop_instance $tomcat_name
	rlLog "Empty the  current signed ca audit log and selftest log"
	rlRun "echo > ${signed_ca_audit_log}"
	rlRun "echo > $selftest_log"
	rhcs_start_instance $tomcat_name
	rlRun "sleep 30" 0 "Sleep 30 seconds so that selftest.log is updated"
	rlAssertGrep "All CRITICAL self test plugins ran SUCCESSFULLY at startup!" "$selftest_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$ca_signing_nick\] CIMC certificate verification" "$signed_ca_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$ca_ocsp_signing_nick\] CIMC certificate verification" "$signed_ca_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$ca_sslserver_nick\] CIMC certificate verification" "$signed_ca_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$ca_subsystem_nick\] CIMC certificate verification" "$signed_ca_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$ca_audit_nick\] CIMC certificate verification" "$signed_ca_audit_log"
	rlRun "tail -n 10 $signed_ca_audit_log | grep \"AuditEvent=SELFTESTS_EXECUTION\" > $TmpDir/ca-signed-audit.log" 0,1 "Get the current signed audit log"
	rlAssertGrep "Outcome=Success" "$TmpDir/ca-signed-audit.log"
	rlPhaseEnd

	rlPhaseStartTest "CA fails to start when an in-correct (bogus) nickname is provided for a certificate categorized as \"critical\" for the selftest."
	local cur_date_time=$(date +%d-%b-%Y:%H:%M)
	local ca_config_file_backup="/var/lib/pki/$tomcat_name/ca/conf/CS.cfg-$cur_date_time"
	local ca_ocsp_bogus_nick="Bogus-ocspcert"
	rlLog "Backup existing ca CS.cfg"
	rlRun "/usr/bin/cp $ca_config_file -f $ca_config_file_backup" 0 "Backup current CS.cfg"
	rlLog "Stop $tomcat_name"
	rlLog "Empty the current signed ca audit log"
	rlRun "echo > $signed_ca_audit_log"
	rhcs_stop_instance $tomcat_name
	rlRun "sed -i s/"$ca_ocsp_signing_nick"/"$ca_ocsp_bogus_nick"/ $ca_config_file"
	local cur_date=$(date +%d/%b/%Y:%H:%M)
	rhcs_start_instance $tomcat_name
	rlAssertGrep "\[AuditEvent=SELFTESTS_EXECUTION\]\[SubjectID=\$System$\]\[Outcome=Failure\]" "$signed_ca_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$ca_signing_nick\] CIMC certificate verification" "$signed_ca_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Failure\]\[CertNickName=$ca_ocsp_bogus_nick\] CIMC certificate verification" "$signed_ca_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$ca_sslserver_nick\] CIMC certificate verification" "$signed_ca_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$ca_subsystem_nick\] CIMC certificate verification" "$signed_ca_audit_log"
	rlAssertGrep "\[AuditEvent=SELFTESTS_EXECUTION\]\[SubjectID=\$System$\]\[Outcome=Success\]" "$signed_ca_audit_log"
	rlLog "Stop $tomcat_name"
	rhcs_stop_instance $tomcat_name
	rlLog "Revert the changes back to CS.cfg"
	rlRun "/usr/bin/cp $ca_config_file_backup -f $ca_config_file" 0 "Revert back the changes done to CS.cfg"
	rlLog "Remove the backup file"
	rlRun "rm -f $ca_config_file_backup"
	rhcs_start_instance $tomcat_name
	rlLog "RHCS9 BZ: https://bugzilla.redhat.com/show_bug.cgi?id=1221013"
	rlLog "RHCS9 BZ: https://bugzilla.redhat.com/show_bug.cgi?id=1222435"
	rlPhaseEnd

	rlPhaseStartTest "CA should start successfully when an in-correct (bogus) nickname is provided for a certificate categorized as \"non-critical\" for the selftest."
	local cur_date_time=$(date +%d-%b-%Y:%H:%M)
        local ca_config_file_backup="/var/lib/pki/$tomcat_name/ca/conf/CS.cfg-$cur_date_time"
	local selftest_system_verification_change="selftests.container.order.startup=CAPresence:critical, SystemCertsVerification:non-critical"
	local ca_ocsp_bogus_nick="Bogus-ocspcert"
	rlLog "Backup existing ca CS.cfg"
	rlRun "/usr/bin/cp $ca_config_file -f $ca_config_file_backup" 0 "Backup current CS.cfg"
	rlLog "Stop $tomcat_name"
        rlLog "Empty the current signed ca audit log"
        rlRun "rm -f $signed_ca_audit_log"
        rhcs_stop_instance $tomcat_name
	rlLog "Edit selftest with system cert verification as non-critical"
	rlRun "sed -i s/\"$selftest_system_verification\"/\"$selftest_system_verification_change\"/ $ca_config_file"
	rlLog "Specify Invalid CA ocsp cert"
	rlRun "sed -i s/"$ca_ocsp_signing_nick"/"$ca_ocsp_bogus_nick"/ $ca_config_file"
	local cur_date=$(date +%d/%b/%Y:%H:%M)
	rhcs_start_instance $tomcat_name
	rlRun "sleep 60" 0 "Sleep 30 seconds so that audit log is updated"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$ca_signing_nick\] CIMC certificate verification" "$signed_ca_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Failure\]\[CertNickName=$ca_storage_bogus_nick\] CIMC certificate verification" "$signed_ca_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$ca_sslserver_nick\] CIMC certificate verification" "$signed_ca_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$ca_subsystem_nick\] CIMC certificate verification" "$signed_ca_audit_log"
	rlAssertGrep "\[AuditEvent=SELFTESTS_EXECUTION\]\[SubjectID=\$System$\]\[Outcome=Success\]" "$signed_ca_audit_log"
	rlLog "Stop $tomcat_name"
	rhcs_stop_instance $tomcat_name
	rlLog "Revert the changes back to CS.cfg"
	rlRun "/usr/bin/cp $ca_config_file_backup -f $ca_config_file" 0 "Revert back the changes done to CS.cfg"
	rlLog "Remove the backup file"
	rlRun "rm -f $ca_config_file_backup"
	rhcs_start_instance $tomcat_name
	rlLog "CS9 BZ: https://bugzilla.redhat.com/show_bug.cgi?id=1221013"
	rlPhaseEnd

	rlPhaseStartCleanup "pki ca-selftest-admin cleanup: Restore tomcatjss xml and delete temp dir"
	rlLog "Restore ca.xml from $tomcat_jss_xml_backup_dir"
	rlRun "cp -a $TmpDir/tomcat_jss_backup/ca.xml $tomcat_jss_xml_dir/ca.xml" 0 "Copy ca.xml"
	rlLog "Restart $tomcat_name instance"
	rhcs_stop_instance $tomcat_name
	rhcs_start_instance $tomcat_name
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd

else
	rlLog "CA Instance is not installed"
fi
}
