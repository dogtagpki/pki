#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-kra-selftest-cli
#
#   Description: PKI KRA SELFTEST CLI
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki kra-selftest cli commands needs to be tested:
#  pki kra-selftest-admin
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

run_pki-kra-selftest-admin_tests()
{
        # Local Variables
	local cs_Type=$1
	local cs_Role=$2

        # Creating Temporary Directory for pki kra-selftest-admin
        rlPhaseStartSetup "pki kra-selftest-admin Temporary Directory"
        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        rlRun "pushd $TmpDir"
        rlPhaseEnd

	get_topo_stack $cs_Role $TmpDir/topo_file
	local KRA_INST=$(cat $TmpDir/topo_file | grep MY_KRA | cut -d= -f2)
	kra_instance_created="False"
	if [ "$TOPO9" = "TRUE" ] ; then
		prefix=$KRA_INST
		kra_instance_created=$(eval echo \$${KRA_INST}_INSTANCE_CREATED_STATUS)
	elif [ "$cs_Role" = "MASTER" ] ; then
		prefix=KRA3
		kra_instance_created=$(eval echo \$${KRA_INST}_INSTANCE_CREATED_STATUS)	
	else
		prefix=$cs_Role
		kra_instance_created=$(eval echo \$${KRA_INST}_INSTANCE_CREATED_STATUS)
	fi
if [ "$kra_instance_created" = "TRUE" ] ;  then

	local tomcat_name=$(eval echo \$${KRA_INST}_TOMCAT_INSTANCE_NAME)
        local target_secure_port=$(eval echo \$${KRA_INST}_SECURE_PORT)
        local tmp_kra_agent=$KRA_INST\_agentV
        local tmp_kra_admin=$KRA_INST\_adminV
        local tmp_kra_port=$(eval echo \$${KRA_INST}_UNSECURE_PORT)
        local tmp_kra_host=$(eval echo \$${cs_Role})
        local valid_agent_cert=$KRA_INST\_agentV
        local valid_audit_cert=$KRA_INST\_auditV
        local valid_operator_cert=$KRA_INST\_operatorV
        local valid_admin_cert=$KRA_INST\_adminV
        local revoked_agent_cert=$KRA_INST\_agentR
        local revoked_admin_cert=$KRA_INST\_adminR
        local expired_admin_cert=$KRA_INST\_adminE
        local expired_agent_cert=$KRA_INST\_agentE
        local TEMP_NSS_DB="$TmpDir/nssdb"
        local TEMP_NSS_DB_PWD="redhat"
        local exp="$TmpDir/expfile.out"
        local expout="$TmpDir/exp_out"
        local cert_info="$TmpDir/cert_info"
        local kra_selftest_show_output=$TmpDir/kra-selftest-admin.out
        local rand=$RANDOM
        local tmp_junk_data=$(openssl rand -base64 50 |  perl -p -e 's/\n//')
	### Config file
	local kra_config_file="/var/lib/pki/$tomcat_name/kra/conf/CS.cfg"
	local kra_db="/var/lib/pki/$tomcat_name/kra/alias/"
	local kra_cert_list="transport,storage,sslserver,subsystem,audit_signing"
	local kra_transport_nick=$(cat $kra_config_file | grep kra.transport.nickname | cut -d= -f2)
	local kra_storage_nick=$(cat $kra_config_file | grep kra.storage.nickname | cut -d= -f2)
	local kra_sslserver_nick=$(cat $kra_config_file | grep kra.sslserver.nickname | cut -d= -f2)
	local kra_subsystem_nick=$(cat $kra_config_file | grep kra.subsystem.nickname | cut -d= -f2)
	local kra_audit_nick=$(cat $kra_config_file | grep kra.audit_signing.nickname | cut -d= -f2)
	local kra_token=$(cat $kra_config_file | grep kra.transport.tokenname | cut -d= -f2)
	local kra_token_internal_passwd=$(cat /var/lib/pki/$tomcat_name/conf/password.conf | grep internal | cut -d= -f2)
	local kra_hsm_passwd=$(cat /var/lib/pki/$tomcat_name/conf/password.conf | grep internal | cut -d= -f2)
	local kra_token=$(cat $kra_config_file | grep kra.transport.tokenname | cut -d= -f2)
	local signed_kra_audit_log="/var/log/pki/$tomcat_name/kra/signedAudit/kra_cert-kra_audit"
	local selftest_log="/var/log/pki/$tomcat_name/kra/selftests.log"
	local selftest_system_verification=$(cat $kra_config_file | grep selftests.container.order.startup | cut -d= -f2)

	rlPhaseStartSetup "Take backup of tomcatjss xml"
	local tomcat_jss_xml_dir="/etc/pki/$tomcat_name/Catalina/localhost"
	local tomcat_jss_xml_backup_dir="$TmpDir/tomcat_jss_backup"
	rlLog "Take backup of $tomcat_jss_xml_dir Directory"
	rlRun "cp -a $tomcat_jss_xml_dir $TmpDir/tomcat_jss_backup"
	rlPhaseEnd

	rlPhaseStartTest "Restart DRM subsystem and make sure self tests executed successfully when self tests for system certs verification categorized as \"critical\" has valid system certificates."
	local kra_cert_list_exist=$(cat $kra_config_file | grep ^kra.cert.list | cut -d= -f2)
	rlLog "Verify if configuration file exists"
	rlAssertExists "$kra_config_file"
	rlAssertEquals "Verify $kra_config_file has  list of system certificates parameter" "$kra_cert_list" "$kra_cert_list_exist"
	if [ "$kra_token" = "Internal Key Storage Token" ]; then
		rlRun "certutil -L -d $kra_db -n \"$kra_transport_nick\" > $TmpDir/cert.out" 0 "Verifying if transport cert exists in certificate db"
		rlRun "certutil -L -d $kra_db -n \"$kra_storage_nick\" > $TmpDir/cert.out" 0 "Verifying if storage cert exists in certificate db"
		rlRun "certutil -L -d $kra_db -n \"$kra_sslserver_nick\" > $TmpDir/cert.out" 0 "Verifying if sslserver cert exists in certificate db"
		rlRun "certutil -L -d $kra_db -n \"$kra_subsystem_nick\" > $TmpDir/cert.out" 0 "Verifying if audit_signing cert exists in certificate db"
	elif [ "$kra_token" = "NHSM6000" ]; then
		rlRun "echo $kra_hsm_passwd > $TmpDir/hsm_passwd" 0 "Save hsm passwd in a file"
		rlRun "certutil -L -d $kra_db -h $kra_token -f $TmpDir/hsm_passwd -n \"$kra_transport_nick\" > $TmpDir/cert.out" 0 "Verifying if transport cert exists in certificate db"
		rlRun "certutil -L -d $kra_db -h $kra_token -f $TmpDir/hsm_passwd -n \"$kra_storage_nick\" > $TmpDir/cert.out" 0 "Verifying if storage cert exists in certificate db"
		rlRun "certutil -L -d $kra_db -h $kra_token -f $TmpDir/hsm_passwd -n \"$kra_sslserver_nick\" > $TmpDir/cert.out" 0 "Verifying if sslserver cert exists in certificate db"
		rlRun "certutil -L -d $kra_db -h $kra_token -f $TmpDir/hsm_passwd -n \"$kra_subsystem_nick\" > $TmpDir/cert.out" 0 "Verifying if audit_signing cert exists in certificate db"
	fi
	rlLog "Restart $tomcat_name instance"

	local cur_date=$(date +%d/%b/%Y:%H:%M)
	rhcs_stop_instance $tomcat_name
	rlLog "Empty the  current signed kra audit log and selftest log"
	rlRun "echo > $signed_kra_audit_log"
	rlRun "echo > $selftest_log"
	rhcs_start_instance $tomcat_name
	rlRun "sleep 30" 0 "Sleep 30 seconds so that selftest.log is updated"
	rlAssertGrep "All CRITICAL self test plugins ran SUCCESSFULLY at startup!" "$selftest_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$kra_transport_nick\] CIMC certificate verification" "$signed_kra_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$kra_storage_nick\] CIMC certificate verification" "$signed_kra_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$kra_sslserver_nick\] CIMC certificate verification" "$signed_kra_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$kra_subsystem_nick\] CIMC certificate verification" "$signed_kra_audit_log"
	rlRun "tail -n 10 $signed_kra_audit_log | grep \"AuditEvent=SELFTESTS_EXECUTION\" > $TmpDir/kra-signed-audit.log" 0,1 "Get the current signed audit log"
	rlAssertGrep "Outcome=Success" "$TmpDir/kra-signed-audit.log"
	rlPhaseEnd

	rlPhaseStartTest "DRM fails to start when an in-correct (bogus) nickname is provided for a certificate categorized as \"critical\" for the selftest."
	local cur_date_time=$(date +%d-%b-%Y:%H:%M)
	local kra_config_file_backup="/var/lib/pki/$tomcat_name/kra/conf/CS.cfg-$cur_date_time"
	local kra_storage_bogus_nick="Bogus-kraStorage"
	rlLog "Backup existing kra CS.cfg"
	rlRun "/usr/bin/cp $kra_config_file -f $kra_config_file_backup" 0 "Backup current CS.cfg"
	rlLog "Stop $tomcat_name"
	rlLog "Empty the current signed kra audit log"
	rlRun "echo > $signed_kra_audit_log"
	rhcs_stop_instance $tomcat_name
	rlRun "sed -i s/"$kra_storage_nick"/"$kra_storage_bogus_nick"/ $kra_config_file"
	local cur_date=$(date +%d/%b/%Y:%H:%M)
	rhcs_start_instance $tomcat_name
	rlAssertGrep "\[AuditEvent=SELFTESTS_EXECUTION\]\[SubjectID=\$System$\]\[Outcome=Failure\]" "$signed_kra_audit_log"
	rlLog "Stop $tomcat_name"
	rhcs_stop_instance $tomcat_name
	rlLog "Revert the changes back to CS.cfg"
	rlRun "/usr/bin/cp $kra_config_file_backup -f $kra_config_file" 0 "Revert back the changes done to CS.cfg"
	rlLog "Remove the backup file"
	rlRun "rm -f $kra_config_file_backup"
	rhcs_start_instance $tomcat_name
	rlLog "CS9 BZ: https://bugzilla.redhat.com/show_bug.cgi?id=1221013"
	rlPhaseEnd

	rlPhaseStartTest "DRM should start successfully when an in-correct (bogus) nickname is provided for a certificate categorized as \"non-critical\" for the selftest."
	local cur_date_time=$(date +%d-%b-%Y:%H:%M)
        local kra_config_file_backup="/var/lib/pki/$tomcat_name/kra/conf/CS.cfg-$cur_date_time"
	local selftest_system_verification_change="SystemCertsVerification:non-critical"
	rlLog "Backup existing kra CS.cfg"
	local kra_storage_bogus_nick="Bogus-kraStorage"
	rlRun "/usr/bin/cp $kra_config_file -f $kra_config_file_backup" 0 "Backup current CS.cfg"
	rlLog "Stop $tomcat_name"
        rlLog "Empty the current signed kra audit log"
        rlRun "echo > $signed_kra_audit_log"
        rhcs_stop_instance $tomcat_name
	rlLog "Edit selftest with system cert verification as non-critical"
	rlRun "sed -i s/"$selftest_system_verification"/"$selftest_system_verification_change"/ $kra_config_file"
	rlRun "sed -i s/"$kra_storage_nick"/"$kra_storage_bogus_nick"/ $kra_config_file"
	local cur_date=$(date +%d/%b/%Y:%H:%M)
	rhcs_start_instance $tomcat_name
	rlRun "sleep 30" 0 "Sleep 30 seconds so that audit log is updated"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$kra_transport_nick\] CIMC certificate verification" "$signed_kra_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Failure\]\[CertNickName=$kra_storage_bogus_nick\] CIMC certificate verification" "$signed_kra_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$kra_sslserver_nick\] CIMC certificate verification" "$signed_kra_audit_log"
	rlAssertGrep "\[AuditEvent=CIMC_CERT_VERIFICATION\]\[SubjectID=\$System\$\]\[Outcome=Success\]\[CertNickName=$kra_subsystem_nick\] CIMC certificate verification" "$signed_kra_audit_log"
	rlAssertGrep "\[AuditEvent=SELFTESTS_EXECUTION\]\[SubjectID=\$System$\]\[Outcome=Success\]" "$signed_kra_audit_log"
	rlLog "Stop $tomcat_name"
	rhcs_stop_instance $tomcat_name
	rlLog "Revert the changes back to CS.cfg"
	rlRun "/usr/bin/cp $kra_config_file_backup -f $kra_config_file" 0 "Revert back the changes done to CS.cfg"
	rlLog "Remove the backup file"
	rlRun "rm -f $kra_config_file_backup"
	rhcs_start_instance $tomcat_name
	rlLog "CS9 BZ: https://bugzilla.redhat.com/show_bug.cgi?id=1221013"
	rlPhaseEnd

	rlPhaseStartCleanup "pki kra-selftest-admin cleanup: Restore tomcatjss xml and delete temp dir"
	rlLog "Restore kra.xml from $tomcat_jss_xml_backup_dir"
	rlRun "cp -a $TmpDir/tomcat_jss_backup/kra.xml $tomcat_jss_xml_dir/kra.xml" 0 "Copy kra.xml"
	rlLog "Restart $tomcat_name instance"
	rhcs_stop_instance $tomcat_name
	rhcs_start_instance $tomcat_name
        rlRun "popd"
        rlRun "rm -r $TmpDir" 0 "Removing tmp directory"
        rlPhaseEnd

else
	rlLog "KRA Instance is not installed"
fi
}
