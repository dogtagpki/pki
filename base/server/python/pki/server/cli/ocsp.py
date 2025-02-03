# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2016 Red Hat, Inc.
# All rights reserved.
#

import argparse
import io
import logging
import os
import shutil
import sys
import tempfile

import pki.cli
import pki.server.cli.audit
import pki.server.cli.config
import pki.server.cli.db
import pki.server.cli.group
import pki.server.cli.subsystem
import pki.server.cli.user

logger = logging.getLogger(__name__)


class OCSPCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('ocsp', 'OCSP management commands')

        self.add_module(pki.server.cli.subsystem.SubsystemCreateCLI(self))
        self.add_module(pki.server.cli.subsystem.SubsystemDeployCLI(self))
        self.add_module(pki.server.cli.subsystem.SubsystemUndeployCLI(self))
        self.add_module(pki.server.cli.subsystem.SubsystemRedeployCLI(self))
        self.add_module(pki.server.cli.audit.AuditCLI(self))
        self.add_module(OCSPCloneCLI())
        self.add_module(OCSPCRLCLI())
        self.add_module(pki.server.cli.config.SubsystemConfigCLI(self))
        self.add_module(pki.server.cli.db.SubsystemDBCLI(self))
        self.add_module(pki.server.cli.group.GroupCLI(self))
        self.add_module(pki.server.cli.user.UserCLI(self))


class OCSPCloneCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('clone', 'OCSP clone management commands')

        self.add_module(OCSPClonePrepareCLI())


class OCSPClonePrepareCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('prepare', 'Prepare OCSP clone')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--pkcs12-file')
        self.parser.add_argument('--pkcs12-password')
        self.parser.add_argument('--pkcs12-password-file')
        self.parser.add_argument(
            '--no-key',
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
        print('Usage: pki-server ocsp-clone-prepare [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --pkcs12-file <path>           PKCS #12 file to store certificates and keys.')
        print('      --pkcs12-password <password>   Password for the PKCS #12 file.')
        print('      --pkcs12-password-file <path>  File containing the PKCS #12 password.')
        print('      --no-key                       Do not include private key.')
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

        instance_name = args.instance
        pkcs12_file = args.pkcs12_file

        pkcs12_password = None

        if args.pkcs12_password:
            pkcs12_password = args.pkcs12_password.encode()

        if args.pkcs12_password_file:
            with io.open(args.pkcs12_password_file, 'rb') as f:
                pkcs12_password = f.read()

        no_key = args.no_key

        if not pkcs12_file:
            logger.error('Missing PKCS #12 file')
            self.print_help()
            sys.exit(1)

        if not pkcs12_password:
            logger.error('Missing PKCS #12 password')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)
        instance.load()

        subsystem = instance.get_subsystem('ocsp')
        if not subsystem:
            logger.error('No OCSP subsystem in instance %s.', instance_name)
            sys.exit(1)

        tmpdir = tempfile.mkdtemp()

        try:
            pkcs12_password_file = os.path.join(tmpdir, 'pkcs12_password.txt')
            with open(pkcs12_password_file, 'wb') as f:
                f.write(pkcs12_password)

            subsystem.export_system_cert(
                'subsystem', pkcs12_file, pkcs12_password_file, no_key=no_key)
            subsystem.export_system_cert(
                'signing', pkcs12_file, pkcs12_password_file, no_key=no_key, append=True)
            subsystem.export_system_cert(
                'audit_signing', pkcs12_file, pkcs12_password_file, no_key=no_key, append=True)
            instance.export_external_certs(
                pkcs12_file, pkcs12_password_file, append=True)

        finally:
            shutil.rmtree(tmpdir)


class OCSPCRLCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('crl', 'OCSP CRL management commands')

        self.add_module(OCSPCRLIssuingPointCLI())


class OCSPCRLIssuingPointCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('issuingpoint', 'OCSP CRL issuing point management commands')

        self.add_module(OCSPCRLIssuingPointFindCLI())
        self.add_module(OCSPCRLIssuingPointAddCLI())


class OCSPCRLIssuingPointFindCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('find', 'Find OCSP CRL issuing points')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--size')
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
        print('Usage: pki-server ocsp-crl-issuingpoint-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat)')
        print('      --size <size>                  Page size')
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

        instance_name = args.instance
        size = args.size

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ocsp')

        if not subsystem:
            logger.error('No OCSP subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.find_crl_issuing_point(size=size)


class OCSPCRLIssuingPointAddCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('add', 'Add OCSP CRL issuing point')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--cert-chain')
        self.parser.add_argument('--cert-format')
        self.parser.add_argument(
            '--ignore-duplicate',
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
        print('Usage: pki-server ocsp-crl-issuingpoint-add [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --cert-chain <path>            Path to PKCS #7 certificate chain')
        print('      --cert-format <format>         Certificate format: PEM (default), DER')
        print('      --ignore-duplicate             Ignore duplicate.')
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

        instance_name = args.instance
        cert_chain_file = args.cert_chain
        cert_format = args.cert_format
        ignore_duplicate = args.ignore_duplicate

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ocsp')

        if not subsystem:
            logger.error('No OCSP subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.add_crl_issuing_point(
            cert_chain_file=cert_chain_file,
            cert_format=cert_format,
            ignore_duplicate=ignore_duplicate)
