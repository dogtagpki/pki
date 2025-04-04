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
# Copyright (C) 2014 Red Hat, Inc.
# All rights reserved.
#

import argparse
import logging
import os
import shlex
import subprocess
import sys

import pki.cli
import pki.cli.password
import pki.cli.pkcs12
import pki.nssdb

logger = logging.getLogger(__name__)


PYTHON_COMMANDS = ['password-generate', 'pkcs12-import']


class PKICLI(pki.cli.CLI):

    def __init__(self):
        super(PKICLI, self).__init__(
            'pki', 'PKI command-line interface')

        self.properties = {}

        self.nss_database = None
        self.nss_password = None
        self.nss_password_file = None
        self.nss_password_conf = None

        self.token = None
        self.nickname = None
        self.username = None
        self.password = None
        self.password_file = None

        self.url = None
        self.protocol = None
        self.hostname = None
        self.port = None
        self.subsystem = None
        self.api = None
        self.output = None
        self.message_format = None

        self.reject_cert_status = False
        self.ignore_cert_status = False
        self.ignore_banner = False
        self.skip_revocation_check = False

        self.add_module(pki.cli.password.PasswordCLI())
        self.add_module(pki.cli.pkcs12.PKCS12CLI())

    def create_parser(self, subparsers=None):

        # create main parser
        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)

        self.parser.add_argument(
            '--client-type',
            default='java')
        self.parser.add_argument(
            '-D',
            action='append')

        self.parser.add_argument('-d')
        self.parser.add_argument('-c')
        self.parser.add_argument('-C')
        self.parser.add_argument('-f')
        self.parser.add_argument('--token')
        self.parser.add_argument('-n')
        self.parser.add_argument('-u')
        self.parser.add_argument('-w')
        self.parser.add_argument('-W')

        self.parser.add_argument('-U')
        self.parser.add_argument('-P')
        self.parser.add_argument('-h')
        self.parser.add_argument('-p')
        self.parser.add_argument('-t')
        self.parser.add_argument('--api')
        self.parser.add_argument('--output')
        self.parser.add_argument('--message-format')
        self.parser.add_argument('--reject-cert-status')
        self.parser.add_argument('--ignore-cert-status')
        self.parser.add_argument(
            '--ignore-banner',
            action='store_true')
        self.parser.add_argument(
            '--skip-revocation-check',
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
        self.parser.add_argument(
            '--version',
            action='store_true')

        self.parser.add_argument(
            'remainder',
            nargs=argparse.REMAINDER)

        # create parsers in modules
        super().create_parser()

    def get_full_module_name(self, module_name):
        return module_name

    def print_help(self):
        print('Usage: pki [OPTIONS]')

        print()
        print('      --client-type <type>       PKI client type (default: java)')
        print('   -D <name>=<value>             System propery')

        print('   -d <path>                     NSS database location ' +
              '(default: ~/.dogtag/nssdb)')
        print('   -c <password>                 NSS database password ' +
              '(mutually exclusive to -C and -f options)')
        print('   -C <password file>            NSS database password file ' +
              '(mutually exclusive to -c and -f options)')
        print('   -f <password config>          NSS database password configuration ' +
              '(mutually exclusive to -c and -C options)')
        print('      --token <name>             Security token name')
        print('   -n <nickname>                 Nickname for client certificate authentication ' +
              '(mutually exclusive to -u option)')
        print('   -u <username>                 Username for basic authentication ' +
              '(mutually exclusive to -n option)')
        print('   -w <password>                 Password for basic authentication ' +
              '(mutually exclusive to -W option)')
        print('   -W <file>                     Password file for basic authentication ' +
              '(mutually exclusive to -w option)')

        print('   -U <URL>                      PKI server URL')
        print('   -P <protocol>                 Protocol (default: https)')
        print('   -h <hostname>                 Hostname')
        print('   -p <port>                     Port (default: 8443)')
        print('   -t <subsystem>                Subsystem type (deprecated)')

        print('      --api <version>            API version: v1, v2')
        print('      --output <folder>          Folder to store HTTP messages')
        print('      --message-format <format>  Message format: json (default), xml')

        print('      --reject-cert-status       Comma-separated list of rejected ' +
              'certificate validity statuses')
        print('      --ignore-cert-status       Comma-separated list of ignored ' +
              'certificate validity statuses')
        print('      --ignore-banner            Ignore banner')
        print('      --skip-revocation-check    Do not perform revocation check')
        print()
        print('  -v, --verbose                  Run in verbose mode.')
        print('      --debug                    Show debug messages.')
        print('      --help                     Show help message.')
        print('      --version                  Show version number.')
        print()

        super(PKICLI, self).print_help()

    def print_version(self):
        print('PKI Command-Line Interface %s' % pki.implementation_version())

    def set_nss_default_db_type(self):
        """Validate NSS_DEFAULT_DB_TYPE

        Value is globally configured in /usr/share/pki/etc/pki.conf and
        sourced by shell wrapper scripts.
        """
        dbtype = os.environ.get('NSS_DEFAULT_DB_TYPE')
        if not dbtype:
            raise KeyError("NSS_DEFAULT_DB_TYPE env var is not set or empty.")
        if dbtype not in {'dbm', 'sql'}:
            raise ValueError(
                "Unsupported NSS_DEFAULT_DB_TYPE value '{}'".format(dbtype)
            )
        return dbtype

    def execute_java(self, args, stdout=sys.stdout):

        self.set_nss_default_db_type()

        cmd = []

        java_home = os.getenv('JAVA_HOME')
        cmd.extend([java_home + '/bin/java'])

        pki_lib = os.getenv('PKI_LIB')
        cmd.extend([
            '-cp', pki_lib + '/*'
        ])

        java_fips_cmd = os.getenv('JAVA_FIPS_ENABLED')
        if java_fips_cmd:
            cmd.extend([
                java_fips_cmd
            ])

        for name in self.properties:
            option = '-D' + name + '=' + self.properties[name]
            cmd.append(option)

        logging_config = os.getenv('PKI_LOGGING_CONFIG')
        if logging_config and 'java.util.logging.config.file' not in self.properties:
            cmd.append('-Djava.util.logging.config.file=' + logging_config)

        cmd.append('com.netscape.cmstools.cli.MainCLI')

        # restore options for Java commands

        if self.nss_database:
            cmd.extend(['-d', self.nss_database])

        if self.nss_password is not None:
            cmd.extend(['-c', self.nss_password])

        if self.nss_password_file:
            cmd.extend(['-C', self.nss_password_file])

        if self.nss_password_conf:
            cmd.extend(['-f', self.nss_password_conf])

        if not pki.nssdb.internal_token(self.token):
            cmd.extend(['--token', self.token])

        if self.nickname:
            cmd.extend(['-n', self.nickname])

        if self.username:
            cmd.extend(['-u', self.username])

        if self.password is not None:
            cmd.extend(['-w', self.password])

        if self.password_file:
            cmd.extend(['-W', self.password_file])

        if self.url:
            cmd.extend(['-U', self.url])

        if self.protocol:
            cmd.extend(['-P', self.protocol])

        if self.hostname:
            cmd.extend(['-h', self.hostname])

        if self.port:
            cmd.extend(['-p', self.port])

        if self.subsystem:
            cmd.extend(['-t', self.subsystem])

        if self.api:
            cmd.extend(['--api', self.api])

        if self.output:
            cmd.extend(['--output', self.output])

        if self.message_format:
            cmd.extend(['--message-format', self.message_format])

        if self.reject_cert_status:
            cmd.extend(['--reject-cert-status', self.reject_cert_status])

        if self.ignore_cert_status:
            cmd.extend(['--ignore-cert-status', self.ignore_cert_status])

        if self.skip_revocation_check:
            cmd.extend(['--skip-revocation-check'])

        if self.ignore_banner:
            cmd.extend(['--ignore-banner'])

        if logger.isEnabledFor(logging.DEBUG):
            cmd.extend(['--debug'])

        elif logger.isEnabledFor(logging.INFO):
            cmd.extend(['-v'])

        cmd.extend(args)

        logger.debug('Command: %s', ' '.join(cmd))

        subprocess.check_call(cmd, stdout=stdout)

    def execute(self, argv, args=None):

        # append global options
        value = os.getenv('PKI_CLI_OPTIONS')
        args = shlex.split(value)
        args.extend(argv)

        args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.version:
            self.print_version()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        client_type = args.client_type

        if args.D:
            for param in args.D:
                name, value = param.split('=', 1)
                self.properties[name] = value

        self.nss_database = args.d
        self.nss_password = args.c
        self.nss_password_file = args.C
        self.nss_password_conf = args.f

        self.token = args.token
        self.nickname = args.n
        self.username = args.u
        self.password = args.w
        self.password_file = args.W

        self.url = args.U
        self.protocol = args.P
        self.hostname = args.h
        self.port = args.p
        self.subsystem = args.t
        self.api = args.api
        self.output = args.output
        self.message_format = args.message_format

        self.reject_cert_status = args.reject_cert_status
        self.ignore_cert_status = args.ignore_cert_status
        self.ignore_banner = args.ignore_banner
        self.skip_revocation_check = args.skip_revocation_check

        command = None
        if len(args.remainder) > 0:
            command = args.remainder[0]
        logger.debug('Command: %s', command)

        if not command:
            self.print_help()
            return

        if client_type == 'python' or command in PYTHON_COMMANDS:
            module = self.find_module(command)
            logger.debug('Module: %s', module.get_full_name())

            module_args = args.remainder[1:]
            logger.debug('Arguments: %s', ' '.join(module_args))

            module.execute(module_args)

        elif client_type == 'java':
            self.execute_java(args.remainder)

        else:
            raise Exception('Unsupported client type: ' + client_type)


if __name__ == '__main__':

    logging.basicConfig(format='%(levelname)s: %(message)s')

    cli = PKICLI()

    try:
        cli.create_parser()

        # exclude script name
        cli.execute(sys.argv[1:])

    except subprocess.CalledProcessError as e:

        if logger.isEnabledFor(logging.DEBUG):
            logger.exception('Command: %s', ' '.join(e.cmd))

        elif logger.isEnabledFor(logging.INFO):
            logger.error('Command: %s', ' '.join(e.cmd))

        sys.exit(e.returncode)

    except KeyboardInterrupt:
        print()
        sys.exit(-1)
