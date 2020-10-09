#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Bug - 1787115 Copy SKI from CSR to Certificate Signed.
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Gaurav Swami <gswami@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2020 Red Hat, Inc. All rights reserved.
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

import os
import sys
import pytest

import re
import tempfile

from pki.testlib.common.utils import ProfileOperations, log

try:
	from pki.testlib.common import constants
except Exception as e:
	if os.path.isfile('/tmp/test_dir/constants.py'):
		sys.path.append('/tmp/test_dir/')
		import constants

profile = 'caCACert'
profop = ProfileOperations(nssdb=constants.NSSDB)


def test_profile_update_SKI_parameters(ansible_module):
	"""
		:id: 8f761dd1-219e-404a-a1ea-333cf2a606b9
		:Title: Bug 1787115 - SubjectAltNameExtInput does not display text fields to the enrollment page
		:Description: Bug 1787115 - SubjectAltNameExtInput does not display text fields to the enrollment page
		:Requirement:
		:CaseComponent: \-
		:Setup:
			1. Use the subsystems setup in ansible to run subsystem commands

		:Steps:
			1. Disable profile caCACert.
			2. Edit caCACert profile to add parameter 'policyset.caCertSet.8.default.params.useSKIFromCertRequest=true'
			3. Enable profile.

		:ExpectedResults:
			1. profile should be disabled.
			2. caCACert profile must include parameter 'policyset.caCertSet.8.default.params.useSKIFromCertRequest=true'
			3. profile should be enabled.

	"""
	tmp_file = tempfile.mktemp(suffix='tmp_', prefix='_profile')
	add_param = {'policyset.caCertSet.8.default.params.useSKIFromCertRequest': 'true'}
	profile_show = ansible_module.pki(cli='ca-profile-show',
	                                  nssdb=constants.NSSDB,
	                                  port=constants.CA_HTTP_PORT,
	                                  dbpassword=constants.CLIENT_DATABASE_PASSWORD,
	                                  certnick='"{}"'.format(constants.CA_ADMIN_NICK),
	                                  extra_args='{} --raw'.format(profile))
	
	for _, result in profile_show.items():
		if result['rc'] == 0:
			newProfile = result['stdout']
			if newProfile:
				with open(tmp_file, "a+") as f:
					f.write(newProfile + '\n')
					for key, value in add_param.items():
						f.write(str(key) + '=' + str(value) + '\n')
					f.close
			else:
				log.error("Failed to get caServerCert Profile")
				log.error("Failed to run: {}".format(result['cmd']))
				log.error(result['stdout'])
				log.error(result['stderr'])
				pytest.fail()
	
	profop.disable_profile(ansible_module, profile)
	
	ansible_module.copy(src=tmp_file, dest='/tmp/caCACert.tmp')
	
	update_prof = ansible_module.pki(cli='ca-profile-mod',
	                                 nssdb=constants.NSSDB,
	                                 port=constants.CA_HTTP_PORT,
	                                 dbpassword=constants.CLIENT_DATABASE_PASSWORD,
	                                 certnick='"{}"'.format(constants.CA_ADMIN_NICK),
	                                 extra_args='/tmp/caCACert.tmp --raw')
	for result in update_prof.values():
		if result['rc'] == 0:
			log.info('Profile Changed Successfully.')
		else:
			log.error("Failed to Update Profile.")
			pytest.fail("Failed to Update Profile.")
	
	enabled = profop.enable_profile(ansible_module, profile_name=profile)
	assert enabled
	
	ca_server_cert = ansible_module.pki(cli='ca-profile-show',
	                                    nssdb=constants.NSSDB,
	                                    port=constants.CA_HTTP_PORT,
	                                    dbpassword=constants.CLIENT_DATABASE_PASSWORD,
	                                    certnick='"{}"'.format(constants.CA_ADMIN_NICK),
	                                    extra_args='{} --raw'.format(profile))
	
	for res in ca_server_cert.values():
		if res['rc'] == 0:
			assert "policyset.caCertSet.8.default.params.useSKIFromCertRequest=true" in res['stdout']
		else:
			pytest.fail("Failed to run caServerCert profile.")


def test_SKI_Validation_CSR_Signed_Certificate(ansible_module):
	"""
			:id: c57e8960-9545-4b1c-9728-be570766037c
			:Title: Bug 1787115 - SubjectAltNameExtInput does not display text fields to the enrollment page
			:Description: Bug 1787115 - SubjectAltNameExtInput does not display text fields to the enrollment page
			:Requirement:
			:CaseComponent: \-
			:Setup:
				1. Use the subsystems setup in ansible to run subsystem commands.

			:Steps:
				1. Genrate CSR with external SKID extension
				2. Submit the certificate request with CSR file.
				3. Approve the certificate request
				4. Export signed certificate.
				5. Check the certificate Subject Key Identifier matches with  Subject Key Identifier from CSR.

			:ExpectedResults:
				1. CSR should be generate with SKI extension.
				2. CSR should be submitted succeesfully.
				3. Request should be approved succeesfully.
				4. Signed Certificate should be exported succeesfully.
				5. CSR and Signed Certificate SKI extension should identical.
	"""
	request_id = None
	submitted_req = False
	SKI_CSR = '/opt/pki/certdb/SKI.csr'
	SKI_CRT = '/opt/pki/certdb/SKI.crt'
	CA_SKID = '0xcba7aa1e3d2784153d47'  # random hexadecimal number starts with 0x
	
	command = ['echo {} > /opt/pki/certdb/passwd.txt'.format(constants.CLIENT_DATABASE_PASSWORD),
	           'openssl rand -out {}/noise.bin 2048'.format(constants.NSSDB)]
	for x in command:
		output = ansible_module.shell(x)
		print("Create noise file: %s", x)
	
	certutil_args = {'-d ': '{}'.format(constants.NSSDB), '-f': '{}/passwd.txt'.format(constants.NSSDB),
	                 '-z': '{}/noise.bin'.format(constants.NSSDB), '-k': 'rsa', '-g': '2048', '-Z': 'SHA256',
	                 '-s': 'CN=pki1.example.com,O=EXAMPLE',
	                 '--keyUsage': 'critical,dataEncipherment,keyEncipherment,digitalSignature',
	                 '--extKeyUsage': 'serverAuth', '-o': '{}.der'.format(SKI_CSR), '--extSKID': ''}
	
	log.info("Generating certificate request using certutil tool")
	data = []
	for key, value in certutil_args.items():
		data.append(key)
		data.append(value)
		command = 'certutil' + ' ' + '-R' + " " + " ".join(data)
	
	log.info("Running Certutil command : %s", command)
	csr_output = ansible_module.expect(command=command, responses={
		"Enter value for the key identifier fields,enter to omit:": "{}".format(CA_SKID),
		"Is this a critical extension [y/N]?": "y"})
	for result in csr_output.values():
		if result['rc'] == 0:
			assert 'Generating key.  This may take a few moments...' in result['stdout']
		else:
			pytest.fail("Failed to Run Command {}".format(command))
	
	ansible_module.shell('openssl req -inform der -in {}.der -out {}'.format(SKI_CSR, SKI_CSR))
	
	sub_req = ansible_module.pki(cli='ca-cert-request-submit',
	                             nssdb=constants.NSSDB,
	                             port=constants.CA_HTTP_PORT,
	                             dbpassword=constants.CLIENT_DATABASE_PASSWORD,
	                             certnick='"{}"'.format(constants.CA_ADMIN_NICK),
	                             extra_args='--profile {}  --csr-file {}'.format(profile, SKI_CSR))
	for result in sub_req.values():
		log.info("Running {}".format(result['cmd']))
		if result['rc'] == 0:
			assert "Submitted certificate request" in result['stdout']
			assert "Request ID" in result['stdout']
			assert "Request Status: pending" in result['stdout']
			try:
				request_id = re.search('Request ID: [\w]*',
				                       result['stdout']).group().encode('utf-8')
				request_id = request_id.decode().split(":")[1].strip()
			except Exception as e:
				print(e)
				sys.exit(1)
		else:
			log.error("Failed to Submit Certificate Request.")
			log.error("Failed to run: {}".format(result['cmd']))
			pytest.fail()
	
	submitted_req = True
	
	if submitted_req:
		approve_new_req = ansible_module.pki(cli='ca-cert-request-review',
		                                     nssdb=constants.NSSDB,
		                                     port=constants.CA_HTTP_PORT,
		                                     dbpassword=constants.CLIENT_DATABASE_PASSWORD,
		                                     certnick='"{}"'.format(constants.CA_ADMIN_NICK),
		                                     extra_args='{}  --action approve'.format(request_id))
		for result in approve_new_req.values():
			log.info("Running : {}".format(result['cmd']))
			if result['rc'] == 0:
				cert_id = re.findall('Certificate ID:.*', result['stdout'])
				cert_request_id = int(cert_id[0].split(":")[1].strip(), 16)
				assert 'Approved certificate request {}'.format(request_id) in result['stdout']
				assert 'Type: enrollment' in result['stdout']
				assert 'Operation Result: success' in result['stdout']
				log.info("Successfully approved certificate request.")
			else:
				log.error("Failed to display certificate request.")
				pytest.fail("Failed to run pki ca-cert-request-review {} --action approve".format(request_id))
	
	cert_show = ansible_module.pki(cli='ca-cert-export',
	                               nssdb=constants.NSSDB,
	                               port=constants.CA_HTTP_PORT,
	                               dbpassword=constants.CLIENT_DATABASE_PASSWORD,
	                               extra_args='{}  --output {}'.format(cert_request_id, SKI_CRT))
	
	ansible_module.package(name='dumpasn1', state='latest')
	ansible_module.shell('AtoB  {} {}'.format(SKI_CRT, SKI_CRT))
	dumpasn1 = ansible_module.command('dumpasn1 -a -d -v -l  {}'.format(SKI_CRT))
	for res in dumpasn1.values():
		log.info("Running : {}".format(res['cmd']))
		if res['rc'] == 0:
			assert "OCTET STRING CB A7 AA 1E 3D 27 84 15 3D 47" in res['stdout']
			log.info("SKI extension is Identical in CSR and Signed Certificate.")
		else:
			log.error("Failed verify the SKI match between CSR and Signed Certificate.")
	
	ansible_module.command('rm -rf {} {}'.format(SKI_CRT, SKI_CSR))
	