#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import logging

import pki.ca
import pki.cert
import pki.client

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
    '--api',
    help='API version: v1, v2',
    dest='api_version')
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

pki_client = pki.client.PKIClient(
    url=args.url,
    ca_bundle=args.ca_bundle,
    api_version=args.api_version)

ca_client = pki.ca.CAClient(pki_client)
cert_client = pki.cert.CertClient(ca_client)

certs = cert_client.list_certs()

first = True

for cert in certs:

    if first:
        first = False
    else:
        print()

    print('  Serial Number: ' + cert.serial_number)
    print('  Subject DN: ' + cert.subject_dn)
    print('  Status: ' + cert.status)
