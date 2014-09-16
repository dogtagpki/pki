#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/bugzilla/
#   Description: tomcatjss bug verification
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Authors: Roshni Pattath <rpattath@redhat.com> 
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
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/pki-cert-cli-lib.sh
. /opt/rhqa_pki/env.sh

########################################################################
#pki-user-cli-user-ca.sh should be first executed prior to bug verification
########################################################################

########################################################################
# Test Suite Globals
########################################################################
run_tomcatjss-bug-verification(){
 
     rlPhaseStartTest "bug_1084224: Tomcatjss missing strictCiphers implementation"
	CA_HOST=$MASTER
	CA_PORT=$(cat /tmp/bugca_instance.inf | grep pki_https_port | cut -d "=" -f2)
	test1="test_screen"
	ca_server_xml_file="/var/lib/pki/pki-ca-bug/conf/server.xml"
	temp_file="$ca_server_xml_file.temp"
        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1084224"
	rlRun "ssltap -sfx $CA_HOST:$CA_PORT > /tmp/original_cipher.out &"
	rlRun "sleep 10"
	rlLog "Executing: wget https://$CA_HOST:1924 --no-check-certificate"
	rlRun "wget https://$CA_HOST:1924 --no-check-certificate"
	cat /tmp/original_cipher.out | grep "cipher_suite = (0x0035) TLS/RSA/AES256-CBC/SHA"	
	if [ $? -eq 0 ]; then
		original_cipher="cipher_suite = (0x0035) TLS/RSA/AES256-CBC/SHA"
		search_string3="+TLS_RSA_WITH_AES_256_CBC_SHA"
		replace_string3="-TLS_RSA_WITH_AES_256_CBC_SHA"
	fi
	cat /tmp/original_cipher.out | grep "cipher_suite = (0x002f) TLS/RSA/AES128-CBC/SHA"
	if [ $? -eq 0 ]; then
		original_cipher="cipher_suite = (0x002f) TLS/RSA/AES128-CBC/SHA"
                search_string3="+TLS_RSA_WITH_AES_128_CBC_SHA"
                replace_string3="-TLS_RSA_WITH_AES_128_CBC_SHA"
	fi
	cat /tmp/original_cipher.out | grep "cipher_suite = (0xc00a) TLS/ECDHE-ECDSA/AES256-CBC/SHA"
	if [ $? -eq 0 ]; then
		original_cipher="cipher_suite = (0xc00a) TLS/ECDHE-ECDSA/AES256-CBC/SHA"
                search_string3="+TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
                replace_string3="-TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
	fi
	cat /tmp/original_cipher.out | grep "cipher_suite = (0xc009) TLS/ECDHE-ECDSA/AES128-CBC/SHA"
	if [ $? -eq 0 ]; then
		original_cipher="cipher_suite = (0xc009) TLS/ECDHE-ECDSA/AES128-CBC/SHA"
                search_string3="+TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
                replace_string3="-TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
	fi
	cat /tmp/original_cipher.out | grep "cipher_suite = (0xc012) TLS/ECDHE-RSA/3DES-EDE-CBC/SHA"
	if [ $? -eq 0 ]; then
		original_cipher="cipher_suite = (0xc012) TLS/ECDHE-RSA/3DES-EDE-CBC/SHA"
                search_string3="+TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
                replace_string3="-TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
	fi
	cat /tmp/original_cipher.out | grep "cipher_suite = (0xc013) TLS/ECDHE-RSA/AES128-CBC/SHA"
	if [ $? -eq 0 ]; then
		original_cipher="cipher_suite = (0xc013) TLS/ECDHE-RSA/AES128-CBC/SHA"
                search_string3="+TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
                replace_string3="-TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
	fi
	cat /tmp/original_cipher.out | grep "cipher_suite = (0xc014) TLS/ECDHE-RSA/AES256-CBC/SHA"
	if [ $? -eq 0 ]; then
		original_cipher="cipher_suite = (0xc014) TLS/ECDHE-RSA/AES256-CBC/SHA"
                search_string3="+TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
                replace_string3="-TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
	fi
	cat /tmp/original_cipher.out | grep "cipher_suite = (0x0032) TLS/DHE-DSS/AES128-CBC/SHA"
	if [ $? -eq 0 ]; then
		original_cipher="cipher_suite = (0x0032) TLS/DHE-DSS/AES128-CBC/SHA"
                search_string3="+TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
                replace_string3="-TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
	fi
	cat /tmp/original_cipher.out | grep "cipher_suite = (0x0038) TLS/DHE-DSS/AES256-CBC/SHA"
	if [ $? -eq 0 ]; then
		original_cipher="cipher_suite = (0x0038) TLS/DHE-DSS/AES256-CBC/SHA"
                search_string3="+TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
                replace_string3="-TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
	fi
	cat /tmp/original_cipher.out | grep "cipher_suite = (0x0033) TLS/DHE-RSA/AES128-CBC/SHA"
	if [ $? -eq 0 ]; then
		original_cipher="cipher_suite = (0x0033) TLS/DHE-RSA/AES128-CBC/SHA"
                search_string3="+TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
                replace_string3="-TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
	fi
	cat /tmp/original_cipher.out | grep "cipher_suite = (0x0039) TLS/DHE-RSA/AES256-CBC/SHA"
	if [ $? -eq 0 ]; then
		original_cipher="cipher_suite = (0x0039) TLS/DHE-RSA/AES256-CBC/SHA"
                search_string3="+TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
                replace_string3="-TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
	fi
	rlRun "systemctl stop pki-tomcatd@pki-ca-bug.service"
	search_string1="strictCiphers=\"false\""
        replace_string1="strictCiphers=\"true\""
	search_string2="sslOptions=\"ssl2=true,ssl3=true,tls=true\""
        replace_string2="sslOptions=\"ssl2=false,ssl3=false,tls=true\""
	search_string4="clientAuth=\"want\""
        replace_string4="clientauth=\"want\""
	rlRun "sed 's/$search_string1/$replace_string1/g' $ca_server_xml_file > $temp_file"
	cp $temp_file $ca_server_xml_file
	rlRun "sed 's/$search_string2/$replace_string2/g' $ca_server_xml_file > $temp_file"
	cp $temp_file $ca_server_xml_file
	rlRun "sed 's/$search_string3/$replace_string3/g' $ca_server_xml_file > $temp_file"
        cp $temp_file $ca_server_xml_file
	rlRun "sed 's/$search_string4/$replace_string4/g' $ca_server_xml_file > $temp_file"
        cp $temp_file $ca_server_xml_file
	chown pkiuser:pkiuser $ca_server_xml_file
        cat $ca_server_xml_file | grep $replace_string1
        if [ $? -eq 0 ] ; then
		rlRun "modutil -dbdir /var/lib/pki/pki-ca-bug/ca/alias -fips true &"
		rlRun "sleep 5"
		rlRun "modutil -dbdir /var/lib/pki/pki-ca-bug/ca/alias -chkfips true > /tmp/chkfips.out"
		rlAssertGrep "FIPS mode enabled." "/tmp/chkfips.out"
		rlRun "systemctl start pki-tomcatd@pki-ca-bug.service"
		rlRun "ssltap -sfx $CA_HOST:$CA_PORT > /tmp/new_cipher.out &"
		rlRun "sleep 10"
		rlLog "Executing: wget https://$CA_HOST:1924 --no-check-certificate"
        rlRun "wget https://$CA_HOST:1924 --no-check-certificate"
		cat $ca_server_xml_file | grep "+TLS_RSA_WITH_AES_256_CBC_SHA"
		if [ $? -eq 0 ]; then
			cat /tmp/new_cipher.out | grep "cipher_suite = (0x0035) TLS/RSA/AES256-CBC/SHA"
			if [ $? -eq 0 ]; then
				rlPass "Bug Verified"
			fi
		fi
		cat $ca_server_xml_file | grep "+TLS_RSA_WITH_AES_128_CBC_SHA"
		if [ $? -eq 0 ]; then
			cat /tmp/new_cipher.out | grep "cipher_suite = (0x002f) TLS/RSA/AES128-CBC/SHA"
                        if [ $? -eq 0 ]; then
                                rlPass "Bug Verified"
                        fi
		fi
		cat $ca_server_xml_file | grep "+TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
		if [ $? -eq 0 ]; then
			cat /tmp/new_cipher.out | grep "cipher_suite = (0xc00a) TLS/ECDHE-ECDSA/AES256-CBC/SHA"
                        if [ $? -eq 0 ]; then
                                rlPass "Bug Verified"
                        fi
		fi
		cat $ca_server_xml_file | grep "+TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA"
		if [ $? -eq 0 ]; then
			cat /tmp/new_cipher.out | grep "cipher_suite = (0xc009) TLS/ECDHE-ECDSA/AES128-CBC/SHA"
                        if [ $? -eq 0 ]; then
                                rlPass "Bug Verified"
                        fi
		fi
		cat $ca_server_xml_file | grep "+TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA"
		if [ $? -eq 0 ]; then
			cat /tmp/new_cipher.out | grep "cipher_suite = (0xc012) TLS/ECDHE-RSA/3DES-EDE-CBC/SHA"
                        if [ $? -eq 0 ]; then
                                rlPass "Bug Verified"
                        fi
		fi
		cat $ca_server_xml_file | grep "+TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA"
		if [ $? -eq 0 ]; then
			cat /tmp/new_cipher.out | grep "cipher_suite = (0xc013) TLS/ECDHE-RSA/AES128-CBC/SHA"
                        if [ $? -eq 0 ]; then
                                rlPass "Bug Verified"
                        fi
		fi
		cat $ca_server_xml_file | grep "+TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA"
		if [ $? -eq 0 ]; then
			cat /tmp/new_cipher.out | grep "cipher_suite = (0xc014) TLS/ECDHE-RSA/AES256-CBC/SHA"
                        if [ $? -eq 0 ]; then
                                rlPass "Bug Verified"
                        fi
		fi
		cat $ca_server_xml_file | grep "+TLS_DHE_DSS_WITH_AES_128_CBC_SHA"
		if [ $? -eq 0 ]; then
			cat /tmp/new_cipher.out | grep "cipher_suite = (0x0032) TLS/DHE-DSS/AES128-CBC/SHA"
                        if [ $? -eq 0 ]; then
                                rlPass "Bug Verified"
                        fi
		fi
		cat $ca_server_xml_file | grep "+TLS_DHE_DSS_WITH_AES_256_CBC_SHA"
		if [ $? -eq 0 ]; then
			cat /tmp/new_cipher.out | grep "cipher_suite = (0x0038) TLS/DHE-DSS/AES256-CBC/SHA"
                        if [ $? -eq 0 ]; then
                                rlPass "Bug Verified"
                        fi
		fi
		cat $ca_server_xml_file | grep "+TLS_DHE_RSA_WITH_AES_128_CBC_SHA"
		if [ $? -eq 0 ]; then
			cat /tmp/new_cipher.out | grep "cipher_suite = (0x0033) TLS/DHE-RSA/AES128-CBC/SHA"
                        if [ $? -eq 0 ]; then
                                rlPass "Bug Verified"
                        fi
		fi
		cat $ca_server_xml_file | grep "+TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
		if [ $? -eq 0 ]; then
			cat /tmp/new_cipher.out | grep "cipher_suite = (0x0039) TLS/DHE-RSA/AES256-CBC/SHA"
                        if [ $? -eq 0 ]; then
                                rlPass "Bug Verified"
                        fi
		fi
		rlAssertNotGrep "$original_cipher" "/tmp/new_cipher.out"
	else
		rlLog "Config file modification failed"
	fi
	rlRun "pkidestroy -s TKS -i pki-ca-bug"
	rlRun "sleep 10"
	rlRun "pkidestroy -s OCSP -i pki-ca-bug"
        rlRun "sleep 10"
	rlRun "pkidestroy -s KRA -i pki-ca-bug"
        rlRun "sleep 10"
	rlRun "pkidestroy -s CA -i pki-ca-bug"
        rlRun "sleep 10"
	rlRun "remove-ds.pl -f -i slapd-pki-ca-bug"
	rlRun "sleep 10"
	rlRun "remove-ds.pl -f -i slapd-pki-kra-bug"
        rlRun "sleep 10"
	rlRun "remove-ds.pl -f -i slapd-pki-ocsp-bug"
        rlRun "sleep 10"
	rlRun "remove-ds.pl -f -i slapd-pki-tks-bug"
        rlRun "sleep 10"
     rlPhaseEnd

}
