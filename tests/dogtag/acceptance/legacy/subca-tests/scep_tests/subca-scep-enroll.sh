#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/legacy-tests/subca-tests/scep_tests
#   Description: SCEP Enrollment with SUBCA
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following pki commands needs to be tested:
#  /usr/bin/sscep
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Asha Akkiangady <aakkiang@redhat.com>
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

run_pki-legacy-subca-scep_tests()
{
        local subsystemType=$1
        local csRole=$2

	rlPhaseStartSetup "Create temporary directory"
	        rlRun "TmpDir=\`mktemp -d\`" 0 "Creating tmp directory"
        	rlRun "pushd $TmpDir"
        rlPhaseEnd

	 # Local Variables
	get_topo_stack $csRole $TmpDir/topo_file
	if [ $cs_Role="MASTER" ]; then
                 SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_SUBCA | cut -d= -f2)
        elif [ $cs_Role="SUBCA2" || $cs_Role="SUBCA1" ]; then
                SUBCA_INST=$(cat $TmpDir/topo_file | grep MY_CA | cut -d= -f2)
        fi
	local tomcat_name=$(eval echo \$${SUBCA_INST}_TOMCAT_INSTANCE_NAME)
        local ca_unsecure_port=$(eval echo \$${SUBCA_INST}_UNSECURE_PORT)
        local ca_secure_port=$(eval echo \$${SUBCA_INST}_SECURE_PORT)
        local ca_host=$(eval echo \$${csRole})
        local valid_agent_user=$SUBCA_INST\_agentV
        local valid_agent_user_password=$SUBCA_INST\_agentV_password
        local valid_admin_user=$SUBCA_INST\_adminV
        local valid_admin_user_password=$SUBCA_INST\_adminV_password
        local valid_audit_user=$SUBCA_INST\_auditV
        local valid_audit_user_password=$SUBCA_INST\_auditV_password
        local valid_operator_user=$SUBCA_INST\_operatorV
        local valid_operator_user_password=$SUBCA_INST\_operatorV_password
	local valid_agent_cert=$SUBCA_INST\_agentV
	local ca_config_file="/var/lib/pki/$tomcat_name/ca/conf/CS.cfg"
	local search_string="ca.scep.enable=false"
	local replace_string="ca.scep.enable=true"

	local scep_enroll_url="http://$ca_host:$ca_unsecure_port/ca/cgi-bin/pkiclient.exe"
	local scep_location="ftp://wiki.idm.lab.bos.redhat.com/dirsec/images-mp1/packages/scep_software/sscep/rhel7-x86_64_modified"
	local scep_enroll_pin="netscape"
	local scep_password="netscape"
	local scep_host_ip=$(ip addr | grep 'state UP' -A2 | tail -n1 | awk '{print $2}' | cut -f1 -d'/')
	
	rlPhaseStartTest "pki_subca_scep_tests-001: Perform scep enrollment with the SUBCA using sha512 fingerprint"
		#Turn on scep
		replace_string_in_a_file $ca_config_file $search_string $replace_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $ca_config_file
			rhcs_stop_instance $tomcat_name
			rhcs_start_instance $tomcat_name
		fi	

		rlRun "wget $scep_location/sscep -O $TmpDir/sscep"
		#delete extisting sscep from /usr/bin if any
		rlLog "Delete existing sscep from /usr/bin = rm -rf /usr/bin/sscep"
		rlRun "rm -rf /usr/bin/sscep"
		#Move sscep to /usr/bin
		rlRun "mv $TmpDir/sscep /usr/bin"
		rlRun "chmod +x /usr/bin/sscep"
		#Get mkrequest
		rlRun "wget $scep_location/mkrequest -O $TmpDir/mkrequest"
		rlRun "mv $TmpDir/mkrequest /usr/bin"
		rlRun "chmod +x /usr/bin/mkrequest"

		#Add a flatfile auth to the SUBCA instance conf dir
		local ca_file_loc="/var/lib/pki/$tomcat_name/ca/conf/flatfile.txt"
		cat > $ca_file_loc << ca_file_loc_EOF
UID:$scep_host_ip
PWD:$scep_password
ca_file_loc_EOF
		#Restart SUBCA
		rhcs_stop_instance $tomcat_name
		rhcs_start_instance $tomcat_name

		local digest="sha512"

                #Copy sscep.conf file
                rlRun "wget $scep_location/sscep.conf -O $TmpDir/sscep.conf"
		#do scep enrollment
		rlRun "scep_do_enroll_with_sscep $scep_enroll_pin $scep_enroll_url $scep_host_ip $TmpDir $digest"

		rlAssertGrep "pkistatus: SUCCESS" "$TmpDir/scep_enroll.out"
		rlAssertGrep "certificate written as $TmpDir/cert.crt" "$TmpDir/scep_enroll.out"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/cert.crt"
		rlAssertGrep "-----END CERTIFICATE-----" "$TmpDir/cert.crt"

		#Verify certificate is created with sha512 signing algorithm
                rlRun "cp $TmpDir/cert.crt $TmpDir/cert.crt.mod"
                rlRun "sed '/^-----BEGIN CERTIFICATE-----/d' $TmpDir/cert.crt.mod > $TmpDir/cert.crt.mod.1"
                rlRun "sed '/^-----END CERTIFICATE-----/d' $TmpDir/cert.crt.mod.1 > $TmpDir/cert.crt.mod.2"
                rlRun "PrettyPrintCert $TmpDir/cert.crt.mod.2 $TmpDir/cert.crt.pretty"
                rlAssertGrep "Signature Algorithm: SHA512withRSA" "$TmpDir/cert.crt.pretty"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_scep_tests-002: Perform scep enrollment with the SUBCA using sha256 fingerprint"
		#Turn on scep
		replace_string_in_a_file $ca_config_file $search_string $replace_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $ca_config_file
			rhcs_stop_instance $tomcat_name
			rhcs_start_instance $tomcat_name
		fi	

		rlRun "wget $scep_location/sscep -O $TmpDir/sscep"
		#delete extisting sscep from /usr/bin if any
		rlLog "Delete existing sscep from /usr/bin = rm -rf /usr/bin/sscep"
		rlRun "rm -rf /usr/bin/sscep"
		#Move sscep to /usr/bin
		rlRun "mv $TmpDir/sscep /usr/bin"
		rlRun "chmod +x /usr/bin/sscep"
		#Get mkrequest
		rlRun "wget $scep_location/mkrequest -O $TmpDir/mkrequest"
		rlRun "mv $TmpDir/mkrequest /usr/bin"
		rlRun "chmod +x /usr/bin/mkrequest"

		#Add a flatfile auth to the SUBCA instance conf dir
		local ca_file_loc="/var/lib/pki/$tomcat_name/ca/conf/flatfile.txt"
		cat > $ca_file_loc << ca_file_loc_EOF
UID:$scep_host_ip
PWD:$scep_password
ca_file_loc_EOF
		#Restart SUBCA
		rhcs_stop_instance $tomcat_name
		rhcs_start_instance $tomcat_name

		local digest=sha256

                #Copy sscep.conf file
                rlRun "wget $scep_location/sscep.conf -O $TmpDir/sscep.conf"
                local orig_fingerprint="FingerPrint\tsha512"
                local replace_fingerprint="FingerPrint\t$digest"
                replace_string_in_a_file $TmpDir/sscep.conf "$orig_fingerprint" "$replace_fingerprint"

		local orig_sigalgorithm="SigAlgorithm\tsha512"
                local replace_sigalgorithm="SigAlgorithm\t$digest"
                replace_string_in_a_file $TmpDir/sscep.conf "$orig_sigalgorithm" "$replace_sigalgorithm"

		#do scep enrollment
		rlRun "scep_do_enroll_with_sscep $scep_enroll_pin $scep_enroll_url $scep_host_ip $TmpDir $digest"

		rlAssertGrep "pkistatus: SUCCESS" "$TmpDir/scep_enroll.out"
		rlAssertGrep "certificate written as $TmpDir/cert.crt" "$TmpDir/scep_enroll.out"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/cert.crt"
		rlAssertGrep "-----END CERTIFICATE-----" "$TmpDir/cert.crt"
                rlRun "cp $TmpDir/cert.crt $TmpDir/cert.crt2.mod"
                rlRun "sed '/^-----BEGIN CERTIFICATE-----/d' $TmpDir/cert.crt2.mod > $TmpDir/cert.crt2.mod.1"
                rlRun "sed '/^-----END CERTIFICATE-----/d' $TmpDir/cert.crt2.mod.1 > $TmpDir/cert.crt2.mod.2"
                rlRun "PrettyPrintCert $TmpDir/cert.crt2.mod.2 $TmpDir/cert.crt2.pretty"
                rlAssertGrep "Signature Algorithm: SHA256withRSA" "$TmpDir/cert.crt2.pretty"
                rlLog "BZ1199692 - https://bugzilla.redhat.com/show_bug.cgi?id=1199692"
	rlPhaseEnd

	
	rlPhaseStartTest "pki_subca_scep_tests-003: Perform scep enrollment with the SUBCA using sha1 fingerprint"
		#Turn on scep
		replace_string_in_a_file $ca_config_file $search_string $replace_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $ca_config_file
			rhcs_stop_instance $tomcat_name
			rhcs_start_instance $tomcat_name
		fi

		rlRun "wget $scep_location/sscep -O $TmpDir/sscep"
		#delete extisting sscep from /usr/bin if any
		rlLog "Delete existing sscep from /usr/bin = rm -rf /usr/bin/sscep"
		rlRun "rm -rf /usr/bin/sscep"
		#Move sscep to /usr/bin
		rlRun "mv $TmpDir/sscep /usr/bin"
		rlRun "chmod +x /usr/bin/sscep"
		#Get mkrequest
		rlRun "wget $scep_location/mkrequest -O $TmpDir/mkrequest"
		rlRun "mv $TmpDir/mkrequest /usr/bin"
		rlRun "chmod +x /usr/bin/mkrequest"

		#Add a flatfile auth to the SUBCA instance conf dir
		local ca_file_loc="/var/lib/pki/$tomcat_name/ca/conf/flatfile.txt"
		cat > $ca_file_loc << ca_file_loc_EOF
UID:$scep_host_ip
PWD:$scep_password
ca_file_loc_EOF
		#Restart SUBCA
		rhcs_stop_instance $tomcat_name
		rhcs_start_instance $tomcat_name

		local digest=sha1

                #Copy sscep.conf file
                rlRun "wget $scep_location/sscep.conf -O $TmpDir/sscep.conf"
                local orig_fingerprint="FingerPrint\tsha512"
                local replace_fingerprint="FingerPrint\t$digest"
                replace_string_in_a_file $TmpDir/sscep.conf "$orig_fingerprint" "$replace_fingerprint"

		local orig_sigalgorithm="SigAlgorithm\tsha512"
                local replace_sigalgorithm="SigAlgorithm\t$digest"
                replace_string_in_a_file $TmpDir/sscep.conf "$orig_sigalgorithm" "$replace_sigalgorithm"

		#do scep enrollment
		rlRun "scep_do_enroll_with_sscep $scep_enroll_pin $scep_enroll_url $scep_host_ip $TmpDir $digest"

		rlAssertGrep "pkistatus: SUCCESS" "$TmpDir/scep_enroll.out"
		rlAssertGrep "certificate written as $TmpDir/cert.crt" "$TmpDir/scep_enroll.out"
		rlAssertGrep "-----BEGIN CERTIFICATE-----" "$TmpDir/cert.crt"
		rlAssertGrep "-----END CERTIFICATE-----" "$TmpDir/cert.crt"
                rlRun "cp $TmpDir/cert.crt $TmpDir/cert.crt3.mod"
                rlRun "sed '/^-----BEGIN CERTIFICATE-----/d' $TmpDir/cert.crt3.mod > $TmpDir/cert.crt3.mod.1"
                rlRun "sed '/^-----END CERTIFICATE-----/d' $TmpDir/cert.crt3.mod.1 > $TmpDir/cert.crt3.mod.2"
                rlRun "PrettyPrintCert $TmpDir/cert.crt3.mod.2 $TmpDir/cert.crt3.pretty"
                rlAssertGrep "Signature Algorithm: SHA256withRSA" "$TmpDir/cert.crt3.pretty"
                rlLog "BZ1199692 - https://bugzilla.redhat.com/show_bug.cgi?id=1199692"
	rlPhaseEnd

	rlPhaseStartTest "pki_subca_scep_tests_cleanup: delete temporary directory and turn off sscep "
		#Delete temporary directory
                rlRun "popd"
                rlRun "rm -r $TmpDir" 0 "Removing tmp directory"

		#Turn off scep
		replace_string_in_a_file $ca_config_file $replace_string $search_string
		if [ $? -eq 0 ] ; then
			chown pkiuser:pkiuser $ca_config_file
			rhcs_stop_instance $tomcat_name
			rhcs_start_instance $tomcat_name
		fi	
	rlPhaseEnd
}
