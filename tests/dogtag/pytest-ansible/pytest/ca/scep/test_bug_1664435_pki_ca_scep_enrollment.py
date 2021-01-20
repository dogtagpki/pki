#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: PKI CA SCEP Enrollment Bugzilla 1664435
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   PKI CA SCEP Enrollment Bugzilla 1664435
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Gaurav Swami <gswami@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2021 Red Hat, Inc. All rights reserved.
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
"""
import logging
import os
import sys
import pytest
import time

try:
	from pki.testlib.common import constants
except Exception as e:
	if os.path.isfile('/tmp/test_dir/constants.py'):
		sys.path.append('/tmp/test_dir')
		import constants
log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


def test_topo00_setup_for_ldap_ca(ansible_module):
	"""
	:Title: Topology-00 setup for ldap, ca
	:Description: setup ldap, ca
	:Requirement:
	:CaseComponent:
	:Setup: Use the subsystems setup in ansible to run subsystem commands
	:Steps:
		1. Install Ldap server
		2. Install CA
	:Expected Results:
		1. It should install ldap, ca.
	"""
	# Setup DS instance
	ansible_module.command('cp -R /tmp/test_dir/ /tmp/test_conf')
	out = ansible_module.shell('dscreate from-file /tmp/test_conf/ldap.cfg')
	for result in out.values():
		assert result['rc'] == 0
		log.info("Setup DS instance.")
	
	# Setup CA instance
	install_ca = ansible_module.shell('pkispawn -s CA -f /tmp/test_conf/ca.cfg')
	for result in install_ca.values():
		assert result['rc'] == 0
		log.info("CA Installed successfully")


def test_pki_ca_scep_setup(ansible_module):
	"""
	:Title: Setup SCEP enrollment environment
	:Description: Setup SCEP enrollment environment
	:Requirement:
	:Setup: Use the subsystems setup in ansible to run subsystem commands
	:Steps:
		1. Enable scep from CA's CS.cfg:
		   ca.scep.enable='false' to ca.scep.enable='true'
		2. Download the sscep, mkrequest and sscep.config file
		3. Provide the executable permission

	:Expected results:
		1. Setup should happen successfully
	"""
	ca_cfg_path = '/var/lib/pki/{}/ca/conf/CS.cfg'.format(constants.CA_INSTANCE_NAME)
	sscep_conf_path = '/etc/sscep/sscep.conf'
	
	ansible_module.package(name='sscep', state='latest')
	
	# Enable SCEP
	ansible_module.lineinfile(path=ca_cfg_path, regexp='ca.scep.enable=false',
	                          line='ca.scep.enable=true')
	ansible_module.lineinfile(path=ca_cfg_path, regexp='ca.scep.allowedEncryptionAlgorithms=DES3',
	                          line='ca.scep.allowedEncryptionAlgorithms=DES')
	ansible_module.lineinfile(path=ca_cfg_path, regexp='ca.scep.allowedHashAlgorithms=SHA256,SHA512',
	                          line='ca.scep.allowedHashAlgorithms=MD5')
	ansible_module.lineinfile(path=ca_cfg_path, regexp='ca.scep.encryptionAlgorithm=DES3',
	                          line='ca.scep.encryptionAlgorithm=DES')
	ansible_module.lineinfile(path=ca_cfg_path, regexp='ca.scep.hashAlgorithm=SHA256',
	                          line='ca.scep.hashAlgorithm=MD5')
	
	# Restart the server
	ansible_module.command('systemctl restart pki-tomcatd@{}'.format(constants.CA_INSTANCE_NAME))
	time.sleep(8)
	
	# Check sscep file exist
	ansible_module.lineinfile(path=sscep_conf_path, regexp='FingerPrint*', line='FingerPrint	md5')
	ansible_module.lineinfile(path=sscep_conf_path, regexp='EncAlgorithm*', line='EncAlgorithm    des')
	ansible_module.lineinfile(path=sscep_conf_path, regexp='SigAlgorithm*', line='SigAlgorithm    md5')


def test_pki_ca_scep_enrollment_bz_1664435_1908541(ansible_module):
	"""
	:id: cdd43e1f-2e99-45e7-91fb-f48d71c5faaf
	:Title: Setup SCEP enrollment.
	:Description: Setup SCEP enrollment.
	:Requirement:
	:Setup: Use the subsystems setup in ansible to run subsystem commands
	:Steps:
		1. Setup ip_address and pin in flatfile.txt
		2. Run #./mkrequest -ip 10.0.97.7 1212
		3. Run #./sscep getca -u http://pki1.example.com:20080/ca/cgi-bin/pkiclient.exe -c ca.crt
		4. Run #./sscep enroll -u http://pki1.example.com:20080/ca/cgi-bin/pkiclient.exe -c ca.crt
				  -k local.key -r local.csr -l cert.crt
	:Expected results:
		1. Certificate Enrollment should successful with sha512 fingerprint
	"""
	flatfile_cfg = '/var/lib/pki/{}/ca/conf/flatfile.txt'.format(constants.CA_INSTANCE_NAME)
	
	ip = ansible_module.shell("hostname -i | awk '{print $3}'")
	ip_add = list(ip.keys())[0]
	pwd = '1212'
	
	# Setup ip_address and pin
	ansible_module.lineinfile(path=flatfile_cfg, regexp='^#UID:',
	                          line='UID:{}'.format(ip_add))
	ansible_module.lineinfile(path=flatfile_cfg, regexp='^#PWD:',
	                          line='PWD:{}'.format(pwd))
	
	# Run mkrequest
	cmd = ansible_module.command('mkrequest -ip {} {}'.format(ip_add, pwd))
	time.sleep(5)
	
	# Run sscep getca
	ansible_module.command('sscep getca -u http://{}:{}/ca/cgi-bin/pkiclient.exe -c ca.crt'.
	                       format(constants.MASTER_HOSTNAME,
	                              constants.CA_HTTP_PORT))
	log.info('Successfully exported ca.crt with sscep')
	time.sleep(5)
	
	# Run sscep enroll with sha512 fingerprint
	cmd = ansible_module.command('sscep enroll -u http://{}:{}/ca/cgi-bin/pkiclient.exe '
	                             '-c ca.crt -k local.key -r local.csr -l cert.crt'.
	                             format(constants.MASTER_HOSTNAME, constants.CA_HTTP_PORT))
	for result in cmd.values():
		if result['rc'] == 0:
			assert 'pkistatus: SUCCESS' in result['stdout']
			assert 'sscep: valid response from server' in result['stdout']
			log.info('Successfully enrolled cert with {}'.format(result['cmd']))
		else:
			log.error(result['stdout'])
			log.error(result['stderr'])
			pytest.fail()
	time.sleep(5)
	
	# Validate the enrolled cert for fingerprint match
	cmd = ansible_module.shell('openssl x509 -in cert.crt -text -noout')
	for result in cmd.values():
		assert 'Signature Algorithm: sha512WithRSAEncryption' in result['stdout']
		log.info('Successfully matched the sha512 fingerprint')
	time.sleep(5)
	
	# Remove the generated cert and key
	ansible_module.shell('rm -rf local.key local.csr cert.crt ca.crt')
	log.info('Successfully removed the cert and key from server')
	