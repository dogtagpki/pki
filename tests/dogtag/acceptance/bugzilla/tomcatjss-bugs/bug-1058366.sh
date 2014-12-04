#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/bugzilla/
#   Description: 1058366 bug verification
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
run_bug-1058366-verification(){
 
     rlPhaseStartTest "bug_1058366:  NullPointerException in tomcatjss searching for attribute clientauth"
	CA_HOST=$MASTER
	CA_PORT=$(cat /tmp/bugca_instance.inf | grep pki_http_port | cut -d "=" -f2)
	test1="test_screen"
	ca_server_xml_file="/var/lib/pki/pki-ca-bug/conf/server.xml"
	temp_file="$ca_server_xml_file.temp"
	log_file="/tmp/log_messages"
        rlLog "https://bugzilla.redhat.com/show_bug.cgi?id=1058366"
	rlRun "systemctl stop pki-tomcatd@pki-ca-bug.service"
	rlRun "sleep 10"
	search_string1="clientAuth=\"want\""
	search_string2="clientauth=\"want\""
	search_string3="enableOCSP=\"false\""
        replace_string3="enableOCSP=\"true\""
	search_string4="ocspResponderURL=\"http://$MASTER:9080/ca/ocsp\""
	replace_string4="ocspResponderURL=\"http://$MASTER:$CA_PORT/ca/ocsp\""
	
	rlAssertGrep "$search_string1" "$ca_server_xml_file"
	rlAssertNotGrep "$search_string2" "$ca_server_xml_file"
	rlRun "sed 's/$search_string3/$replace_string3/g' $ca_server_xml_file > $temp_file"
	rlRun "sleep 10"
        cp $temp_file $ca_server_xml_file
	rlRun "sleep 10"
	rlRun "sed 's#$search_string4#$replace_string4#g' $ca_server_xml_file > $temp_file"
	rlRun "sleep 10"
        cp $temp_file $ca_server_xml_file
	rlRun "sleep 10"
	chown pkiuser:pkiuser $ca_server_xml_file
	rlRun "sleep 10"
        cat $ca_server_xml_file | grep $replace_string3
        if [ $? -eq 0 ] ; then
		rlRun "systemctl start pki-tomcatd@pki-ca-bug.service"
		rlRun "sleep 10"
		rlRun "journalctl > $log_file"
		rlRun "sleep 10"
		rlAssertNotGrep "NullPointerException" "$log_file"
		rlRun "systemctl stop pki-tomcatd@pki-ca-bug.service"
		rlRun "sleep 10"
		rlRun "sed 's/$replace_string3/$search_string3/g' $ca_server_xml_file > $temp_file"
	        rlRun "sleep 10"
        	cp $temp_file $ca_server_xml_file
		rlRun "systemctl start pki-tomcatd@pki-ca-bug.service"
                rlRun "sleep 10"
	fi
     rlPhaseEnd

}
