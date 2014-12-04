#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/dogtag/acceptance/bugzilla/jss-bugs
#   Description: 1040640 bug verification
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
#bug_setup.sh should be first executed prior to bug verification
########################################################################

########################################################################
# Test Suite Globals
########################################################################
run_bug-1040640-verification(){
 
     rlPhaseStartTest "Bug 1040640 -  Incorrect OIDs for SHA2 algorithms"
	BUGCA_DOMAIN=`hostname -d`
	pkcs10_cert_req_old="$BUGCA_CERTDB_DIR/certReq.p10"
	pkcs10_cert_req_out_old="$BUGCA_CERTDB_DIR/certReq.p10.cmc"
	cmc_conf_file_old="$BUGCA_CERTDB_DIR/p10cmc.conf"
	http_client_rsa_conf_old="$BUGCA_CERTDB_DIR/HttpClientRSA.cfg"
	http_client_out_old="$BUGCA_CERTDB_DIR/certReq.p10.cmc.response"
	asn1_out_old="$BUGCA_CERTDB_DIR/asn1.out"
        rlRun "PKCS10Client -d $BUGCA_CERTDB_DIR -p $BUGCA_CERTDB_DIR_PASSWORD -o $pkcs10_cert_req_old -n \"CN=test1\" -a rsa -l 2048"
	echo "numRequests=1" >> $cmc_conf_file_old
	echo "input=$pkcs10_cert_req_old" >> $cmc_conf_file_old
	echo "output=$pkcs10_cert_req_out_old" >> $cmc_conf_file_old
	echo "nickname=PKI Administrator for $BUGCA_DOMAIN" >> $cmc_conf_file_old
	echo "dbdir=$BUGCA_CERTDB_DIR" >> $cmc_conf_file_old
	echo "password=Secret123" >> $cmc_conf_file_old
	echo "format=pkcs10" >> $cmc_conf_file_old
	rlRun "CMCRequest $cmc_conf_file_old"
	rlRun "sleep 10"
	echo "host=$MASTER" >> $http_client_rsa_conf_old
	echo "port=$BUGCA_HTTP_PORT" >> $http_client_rsa_conf_old
	echo "secure=false" >> $http_client_rsa_conf_old
	echo "input=$pkcs10_cert_req_out_old" >> $http_client_rsa_conf_old
	echo "output=$http_client_out_old" >> $http_client_rsa_conf_old
	echo "dbdir=$BUGCA_CERTDB_DIR" >> $http_client_rsa_conf_old
	echo "clientmode=false" >> $http_client_rsa_conf_old
	echo "password=Secret123" >> $http_client_rsa_conf_old
	echo "nickname=PKI Administrator for $BUGCA_DOMAIN" >> $http_client_rsa_conf_old
	echo "servlet=/ca/ee/ca/profileSubmitCMCFull" >> $http_client_rsa_conf_old
	rlRun "HttpClient $http_client_rsa_conf_old"
	rlRun "sleep 10"
	rlRun "yum -y install dumpasn1"
	rlRun "dumpasn1 $http_client_out_old > $asn1_out_old"
	rlAssertNotGrep "2 16 840 1 101 3 4 1" "$asn1_out_old"
	rlAssertGrep "2 16 840 1 101 3 4 2 1" "$asn1_out_old"
     rlPhaseEnd

}
