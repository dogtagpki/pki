#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import logging

import pki.kra
import pki.account
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

pki_client.set_client_auth(
    client_cert=args.client_cert,
    client_key=args.client_key)

kra_client = pki.kra.KRAClient(pki_client)

account_client = pki.account.AccountClient(kra_client)
account_client.login()

key_client = pki.key.KeyClient(kra_client)
result = key_client.list_keys()

first = True

for key_info in result.key_infos:

    if first:
        first = False
    else:
        print()

    print('  Key ID: %s' % key_info.get_key_id())

    if key_info.client_key_id:
        print('  Client Key ID: %s' % key_info.client_key_id)

    print('  Algorithm: %s' % key_info.algorithm)
    print('  Size: %s' % key_info.size)
    print('  Owner: %s' % key_info.owner_name)

    if key_info.status:
        print('  Status: %s' % key_info.status)

account_client.logout()
