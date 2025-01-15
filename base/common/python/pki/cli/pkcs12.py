# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the Lesser GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2016 Red Hat, Inc.
# All rights reserved.
#

import argparse
import logging
import os
import re
import shutil
import sys
import tempfile

import pki.cli
import pki.nssdb

logger = logging.getLogger(__name__)


class PKCS12CLI(pki.cli.CLI):

    def __init__(self):
        super(PKCS12CLI, self).__init__(
            'pkcs12', 'PKCS #12 utilities')

        self.add_module(PKCS12ImportCLI())


class PKCS12ImportCLI(pki.cli.CLI):

    def __init__(self):
        super(PKCS12ImportCLI, self).__init__(
            'import', 'Import PKCS #12 file into NSS database')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument('--pkcs12')
        self.parser.add_argument('--pkcs12-file')
        self.parser.add_argument('--password')
        self.parser.add_argument('--pkcs12-password')
        self.parser.add_argument('--password-file')
        self.parser.add_argument('--pkcs12-password-file')
        self.parser.add_argument(
            '--no-trust-flags',
            action='store_true')
        self.parser.add_argument(
            '--no-user-certs',
            action='store_true')
        self.parser.add_argument(
            '--no-ca-certs',
            action='store_true')
        self.parser.add_argument(
            '--overwrite',
            action='store_true')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')

    def print_help(self):
        print('Usage: pki pkcs12-import [OPTIONS]')
        print()
        print('      --pkcs12 <path>                PKCS #12 file')
        print('      --pkcs12-file <path>           DEPRECATED: PKCS #12 file')
        print('      --password <password>          PKCS #12 password')
        print('      --pkcs12-password <password>   DEPRECATED: PKCS #12 password')
        print('      --password-file <path>         PKCS #12 password file')
        print('      --pkcs12-password-file <path>  DEPRECATED: PKCS #12 password file')
        print('      --no-trust-flags               Do not include trust flags')
        print('      --no-user-certs                Do not import user certificates')
        print('      --no-ca-certs                  Do not import CA certificates')
        print('      --overwrite                    Overwrite existing certificates')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        pkcs12_file = args.pkcs12

        if args.pkcs12_file:
            logger.warning('The --pkcs12-file option has been deprecated.'
                           'Use --pkcs12 instead.')
            pkcs12_file = args.pkcs12_file

        pkcs12_password = args.password

        if args.pkcs12_password:
            logger.warning('The --pkcs12-password option has been deprecated.'
                           'Use --password instead.')
            pkcs12_password = args.pkcs12_password

        password_file = args.password_file

        if args.pkcs12_password_file:
            logger.warning('The --pkcs12-password-file option has been deprecated.'
                           'Use --password-file instead.')
            password_file = args.pkcs12_password_file

        no_trust_flags = args.no_trust_flags
        import_user_certs = not args.no_user_certs
        import_ca_certs = not args.no_ca_certs
        overwrite = args.overwrite

        if not pkcs12_file:
            logger.error('Missing PKCS #12 file')
            self.print_help()
            sys.exit(1)

        if not pkcs12_password and not password_file:
            logger.error('Missing PKCS #12 password')
            self.print_help()
            sys.exit(1)

        main_cli = self.parent.parent

        # Due to JSS limitation, CA certificates need to be imported
        # using certutil in order to preserve the nickname stored in
        # the PKCS #12 file.

        logger.info('Certificates in PKCS #12 file:')

        certs = []

        tmpdir = tempfile.mkdtemp()

        try:
            # find all certs in PKCS #12 file
            output_file = os.path.join(tmpdir, 'pkcs12-cert-find.txt')
            with open(output_file, 'wb') as f:

                cmd = ['pkcs12-cert-find']

                if pkcs12_file:
                    cmd.extend(['--pkcs12', pkcs12_file])

                if pkcs12_password:
                    cmd.extend(['--password', pkcs12_password])

                if password_file:
                    cmd.extend(['--password-file', password_file])

                if logger.isEnabledFor(logging.DEBUG):
                    cmd.extend(['--debug'])

                elif logger.isEnabledFor(logging.INFO):
                    cmd.extend(['--verbose'])

                main_cli.execute_java(cmd, stdout=f)

            # parse results
            with open(output_file, 'r', encoding='utf-8') as f:
                cert_info = {}

                for line in f:
                    match = re.match(r'  Certificate ID: (.*)$', line)
                    if match:
                        cert_info = {}
                        cert_info['id'] = match.group(1)
                        certs.append(cert_info)
                        continue

                    match = re.match(r'  Friendly Name: (.*)$', line)
                    if match:
                        nickname = match.group(1)
                        cert_info['nickname'] = nickname
                        logger.info('- %s', nickname)
                        continue

                    match = re.match(r'  Trust Flags: (.*)$', line)
                    if match:
                        cert_info['trust_flags'] = match.group(1)
                        continue

                    match = re.match(r'  Has Key: (.*)$', line)
                    if match:
                        cert_info['has_key'] = match.group(1) == 'true'
                        continue

        finally:
            shutil.rmtree(tmpdir)

        # import CA certificates if requested
        if import_ca_certs:

            logger.info('Importing CA certificates:')

            tmpdir = tempfile.mkdtemp()

            try:
                cert_file = os.path.join(tmpdir, 'ca-cert.pem')

                nssdb = pki.nssdb.NSSDatabase(
                    main_cli.nss_database,
                    token=main_cli.token,
                    password=main_cli.nss_password,
                    password_file=main_cli.nss_password_file,
                    password_conf=main_cli.nss_password_conf)

                for cert_info in certs:

                    has_key = cert_info['has_key']
                    if has_key:
                        continue

                    cert_id = cert_info['id']
                    nickname = cert_info['nickname']
                    logger.info('- %s', nickname)

                    cert = nssdb.get_cert(nickname=nickname)

                    if cert:
                        if not overwrite:
                            logger.warning('Certificate already exists: %s', nickname)
                            continue

                        nssdb.remove_cert(nickname=nickname)

                    if 'trust_flags' in cert_info:
                        trust_flags = cert_info['trust_flags']
                    else:
                        # default trust flags for CA certificates
                        trust_flags = 'CT,C,C'

                    logger.info('Exporting %s (%s) from PKCS #12 file', nickname, cert_id)

                    cmd = ['pkcs12-cert-export']

                    if pkcs12_file:
                        cmd.extend(['--pkcs12-file', pkcs12_file])

                    if pkcs12_password:
                        cmd.extend(['--pkcs12-password', pkcs12_password])

                    if password_file:
                        cmd.extend(['--pkcs12-password-file', password_file])

                    cmd.extend(['--cert-file', cert_file])

                    cmd.extend(['--cert-id', cert_id])

                    if logger.isEnabledFor(logging.DEBUG):
                        cmd.extend(['--debug'])

                    elif logger.isEnabledFor(logging.INFO):
                        cmd.extend(['-v'])

                    main_cli.execute_java(cmd)

                    logger.info('Importing %s', nickname)

                    nssdb.add_cert(
                        nickname=nickname,
                        cert_file=cert_file,
                        trust_attributes=trust_flags)

            finally:
                shutil.rmtree(tmpdir)

        # import user certificates if requested
        if import_user_certs:

            logger.info('Importing user certificates:')

            nicknames = []
            for cert_info in certs:

                has_key = cert_info['has_key']
                if not has_key:
                    continue

                nickname = cert_info['nickname']
                logger.info('- %s', nickname)

                if nickname not in nicknames:
                    nicknames.append(nickname)

            cmd = ['pkcs12-import']

            if pkcs12_file:
                cmd.extend(['--pkcs12', pkcs12_file])

            if pkcs12_password:
                cmd.extend(['--password', pkcs12_password])

            if password_file:
                cmd.extend(['--password-file', password_file])

            if no_trust_flags:
                cmd.extend(['--no-trust-flags'])

            if overwrite:
                cmd.extend(['--overwrite'])

            if logger.isEnabledFor(logging.DEBUG):
                cmd.extend(['--debug'])

            elif logger.isEnabledFor(logging.INFO):
                cmd.extend(['-v'])

            cmd.extend(nicknames)

            with open(os.devnull, 'w', encoding='utf-8') as f:
                main_cli.execute_java(cmd, stdout=f)
