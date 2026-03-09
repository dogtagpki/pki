#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import logging
import os

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15
from cryptography.hazmat.primitives.ciphers import algorithms, modes, Cipher
from cryptography.hazmat.primitives.padding import PKCS7

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
    '--input',
    help='Input filename',
    dest='input_filename')
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

with open(args.input_filename, 'rb') as f:
    input_data = f.read()

transport_cert = x509.load_pem_x509_certificate(
    transport_pem,
    default_backend())

crypto = pki.crypto.CryptographyCryptoProvider()
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

# use AES_128_CBC to match pki kra-key-archve
# see Java KeyClient.getEncryptAlgorithmOID()
encrypt_alg_oid = pki.crypto.AES_128_CBC_OID
encrypt_alg = algorithms.AES
encrypt_mode = modes.CBC
encrypt_size = 128

nonce_iv = os.urandom(encrypt_alg.block_size // 8)
session_key = os.urandom(encrypt_size // 8)

padder = PKCS7(encrypt_alg.block_size).padder()
padded_data = padder.update(input_data) + padder.finalize()

cipher = Cipher(
    encrypt_alg(session_key),
    encrypt_mode(nonce_iv),
    backend=default_backend())

encryptor = cipher.encryptor()
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

wrapped_session_key = transport_cert.public_key().encrypt(
    session_key,
    PKCS1v15())

key_client.archive_encrypted_data(
    args.client_key_id,
    pki.key.KeyClient.PASS_PHRASE_TYPE,
    encrypted_data,
    wrapped_session_key,
    algorithm_oid=encrypt_alg_oid,
    nonce_iv=nonce_iv)

account_client.logout()
