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

from __future__ import absolute_import
from __future__ import print_function
import getopt
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

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'v', [
                'pkcs12=', 'password=', 'password-file=',
                'pkcs12-file=', 'pkcs12-password=', 'pkcs12-password-file=',
                'no-trust-flags', 'no-user-certs', 'no-ca-certs', 'overwrite',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        pkcs12_file = None
        pkcs12_password = None
        password_file = None
        no_trust_flags = False
        import_user_certs = True
        import_ca_certs = True
        overwrite = False

        for o, a in opts:
            if o == '--pkcs12':
                pkcs12_file = a

            elif o == '--pkcs12-file':
                pkcs12_file = a

            elif o == '--password':
                pkcs12_password = a

            elif o == '--pkcs12-password':
                pkcs12_password = a

            elif o == '--password-file':
                password_file = a

            elif o == '--pkcs12-password-file':
                password_file = a

            elif o == '--no-trust-flags':
                no_trust_flags = True

            elif o == '--no-user-certs':
                import_user_certs = False

            elif o == '--no-ca-certs':
                import_ca_certs = False

            elif o == '--overwrite':
                overwrite = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

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
                    main_cli.database,
                    token=main_cli.token,
                    password=main_cli.password,
                    password_file=main_cli.password_file,
                    password_conf=main_cli.password_conf)

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
