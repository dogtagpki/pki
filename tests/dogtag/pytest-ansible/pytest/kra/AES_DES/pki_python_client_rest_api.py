"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Test Python Client is the python API
#   This py script is used by the main script test_cc_aes_crypto to run directly on dest machine.
#
#   Purpose : Purpose of this script to execute python client api which is used in the test cases
#   Steps :
#   1> Copy this script to the destinaton machine and run with the required paramerter and check the output
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Deepak Punia
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2018 Red Hat, Inc. All rights reserved.
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

# !/usr/bin/python

import pki.crypto as crypto
import pki.key as key
from pki.client import PKIConnection
from pki.kra import KRAClient
import random
import os
import sys

try:
    from pki.testlib.common import constants
except Exception as e:
    if os.path.isfile('/tmp/test_dir/constants.py'):
        sys.path.append('/tmp/test_dir')
        import constants


connection = PKIConnection('https', constants.MASTER_HOSTNAME,
                           constants.KRA_HTTPS_PORT, 'kra', cert_paths=constants.ROOT_CA_CERT_PATH)
connection.set_authentication_cert("/tmp/admin_cert.pem")

crypt = crypto.NSSCryptoProvider(constants.NSSDB, constants.CLIENT_DATABASE_PASSWORD)
transport_nick = "DRM Transport Certificate - {}".format(constants.CA_SECURITY_DOMAIN_NAME)
kraclient = KRAClient(connection, crypt)

crypt.initialize()

keyclient = kraclient.keys
keyclient.set_transport_cert(transport_nick)

session_key = crypt.generate_session_key()
wrapped_session_key = crypt.asymmetric_wrap(session_key,keyclient.transport_cert)

clientKeyID = 'test_key{}'.format(random.randint(1111, 99999999))
key_size = 128

algorithm = key.KeyClient.AES_ALGORITHM = "AES"

algo = key.KeyClient(connection, crypt)
print("keyset={}".format(algo.get_client_keyset()))

usages = [key.SymKeyGenerationRequest.DECRYPT_USAGE,
          key.SymKeyGenerationRequest.ENCRYPT_USAGE]
response = keyclient.generate_symmetric_key(clientKeyID,
                                            size=key_size,
                                            algorithm=algorithm,
                                            usages=usages)
key_id = response.get_key_id()
print("Key_id=", key_id)

key_info = keyclient.get_active_key_info(clientKeyID)
print(key_info)
