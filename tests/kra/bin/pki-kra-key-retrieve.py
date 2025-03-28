#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import logging
import os

import cryptography.hazmat.backends
import cryptography.hazmat.primitives.padding
import cryptography.x509

import pki.kra
import pki.account
import pki.client
import pki.crypto

logger = logging.getLogger(__name__)
logging.basicConfig(format='%(levelname)s: %(message)s')

parser = argparse.ArgumentParser()
parser.add_argument(
    '-U',
    help='Server URL',
    dest='url')
parser.add_argument(
    '--ca-bundle',
    help='Path to CA bundle',
    dest='ca_bundle')
parser.add_argument(
    '--client-cert',
    help='Path to client certificate',
    dest='client_cert')
parser.add_argument(
    '--client-key',
    help='Path to client key',
    dest='client_key')
parser.add_argument(
    '--api',
    help='API version: v1, v2',
    dest='api_version')
parser.add_argument(
    '--client-key-id',
    help='Client key ID',
    dest='client_key_id')
parser.add_argument(
    '--transport',
    help='Transport certificate filename',
    dest='transport')
parser.add_argument(
    '--output',
    help='Output filename',
    dest='output_filename')
parser.add_argument(
    '-v',
    '--verbose',
    help='Run in verbose mode.',
    dest='verbose',
    action='store_true')
parser.add_argument(
    '--debug',
    help='Run in debug mode.',
    dest='debug',
    action='store_true')

args = parser.parse_args()

if args.debug:
    logging.getLogger().setLevel(logging.DEBUG)

elif args.verbose:
    logging.getLogger().setLevel(logging.INFO)

with open(args.transport, 'rb') as f:
    transport_pem = f.read()

transport_cert = cryptography.x509.load_pem_x509_certificate(
    transport_pem,
    cryptography.hazmat.backends.default_backend())

crypto = pki.crypto.CryptographyCryptoProvider(
    transport_cert=transport_cert)
crypto.initialize()

pki_client = pki.client.PKIClient(
    url=args.url,
    ca_bundle=args.ca_bundle,
    api_version=args.api_version)

pki_client.set_client_auth(
    client_cert=args.client_cert,
    client_key=args.client_key)

kra_client = pki.kra.KRAClient(pki_client)

account_client = pki.account.AccountClient(kra_client)
account_client.login()

key_client = pki.key.KeyClient(kra_client)

# find key ID from client's key ID
result = key_client.list_keys(client_key_id=args.client_key_id)
key_info = result.key_infos[0]
key_id = key_info.get_key_id()

session_key = crypto.generate_session_key()

wrapped_session_key = crypto.asymmetric_wrap(
    session_key,
    transport_cert)

# use AES_128_CBC to match pki kra-key-retrieve
# see Java KeyClient.getEncryptAlgorithmOID()
key_client.encrypt_alg_oid = pki.crypto.AES_128_CBC_OID

key = key_client.retrieve_key(
    key_id,
    wrapped_session_key)

account_client.logout()

key_data = crypto.symmetric_unwrap(
    key.encrypted_data,
    session_key,
    nonce_iv=key.nonce_data)

with open(args.output_filename, 'wb') as f:
    f.write(key_data)
