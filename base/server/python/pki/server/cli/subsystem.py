# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#     Abhijeet Kasurde <akasurde@redhat.com>
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
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
# Copyright (C) 2015-2016 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function

import getopt
import getpass
import inspect
import logging
import os
import subprocess
import sys
import textwrap

import pki.cli
import pki.nssdb
import pki.server

logger = logging.getLogger(__name__)


class SubsystemCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('subsystem', 'Subsystem management commands')

        self.add_module(SubsystemDisableCLI())
        self.add_module(SubsystemEnableCLI())
        self.add_module(SubsystemFindCLI())
        self.add_module(SubsystemShowCLI())

        self.add_module(SubsystemCertCLI())

    @staticmethod
    def print_subsystem(subsystem):
        print('  Subsystem ID: %s' % subsystem.name)
        print('  Instance ID: %s' % subsystem.instance.name)
        print('  Enabled: %s' % subsystem.is_enabled())


class SubsystemFindCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('find', 'Find subsystems')

    def usage(self):
        print('Usage: pki-server subsystem-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.usage()
                sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        self.print_message('%s entries matched' % len(instance.get_subsystems()))

        first = True
        for subsystem in instance.get_subsystems():
            if first:
                first = False
            else:
                print()

            SubsystemCLI.print_subsystem(subsystem)


class SubsystemShowCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('show', 'Show subsystem')

    def usage(self):
        print('Usage: pki-server subsystem-show [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.usage()
                sys.exit(1)

        if len(args) != 1:
            logger.error('Missing subsystem ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name, instance_name)
            sys.exit(1)

        SubsystemCLI.print_subsystem(subsystem)


class SubsystemCreateCLI(pki.cli.CLI):
    '''
    Create {subsystem} subsystem
    '''

    help = '''\
        Usage: pki-server {subsystem}-create [OPTIONS] <subsystem ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''  # noqa: E501

    def __init__(self, parent):
        super().__init__(
            'create',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.name.upper()))

        self.parent = parent

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.name))

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.name

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if subsystem:
            raise Exception('%s subsystem already exists' % subsystem_name.upper())

        subsystem = pki.server.subsystem.PKISubsystemFactory.create(instance, subsystem_name)
        instance.add_subsystem(subsystem)

        subsystem.create(exist_ok=True)
        subsystem.create_conf(exist_ok=True)
        subsystem.create_logs(exist_ok=True)


class SubsystemDeployCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('deploy', 'Deploy %s subsystem' % parent.name.upper())
        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-deploy [OPTIONS] [name]' % self.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --wait                         Wait until started.')
        print('      --max-wait <seconds>           Maximum wait time (default: 60).')
        print('      --timeout <seconds>            Connection timeout.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'wait', 'max-wait=', 'timeout=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        name = self.parent.name
        instance_name = 'pki-tomcat'
        wait = False
        max_wait = 60
        timeout = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--wait':
                wait = True

            elif o == '--max-wait':
                max_wait = int(a)

            elif o == '--timeout':
                timeout = int(a)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            name = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        descriptor = os.path.join(pki.server.PKIServer.SHARE_DIR,
                                  '%s/conf/Catalina/localhost/%s.xml' % (name, name))
        doc_base = os.path.join(pki.server.PKIServer.SHARE_DIR,
                                '%s/webapps/%s' % (name, name))

        instance.deploy_webapp(
            name,
            descriptor,
            doc_base,
            wait=wait,
            max_wait=max_wait,
            timeout=timeout)


class SubsystemUndeployCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('undeploy', 'Undeploy %s subsystem' % parent.name.upper())
        self.parenet = parent

    def print_help(self):
        print('Usage: pki-server %s-undeploy [OPTIONS] [name]' % self.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --wait                         Wait until stopped.')
        print('      --max-wait <seconds>           Maximum wait time (default: 60).')
        print('      --timeout <seconds>            Connection timeout.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'wait', 'max-wait=', 'timeout=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        name = self.parent.name
        instance_name = 'pki-tomcat'
        wait = False
        max_wait = 60
        timeout = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--wait':
                wait = True

            elif o == '--max-wait':
                max_wait = int(a)

            elif o == '--timeout':
                timeout = int(a)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            name = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        instance.undeploy_webapp(
            name,
            wait=wait,
            max_wait=max_wait,
            timeout=timeout)


class SubsystemRedeployCLI(pki.cli.CLI):
    '''
    Redeploy {subsystem} subsystem
    '''

    help = '''\
        Usage: pki-server {subsystem}-redeploy [OPTIONS] [name]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --wait                         Wait until started.
              --max-wait <seconds>           Maximum wait time (default: 60).
              --timeout <seconds>            Connection timeout.
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'redeploy',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.name.upper()))

        self.parent = parent

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.name))

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'wait', 'max-wait=', 'timeout=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        name = self.parent.name
        instance_name = 'pki-tomcat'
        wait = False
        max_wait = 60
        timeout = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--wait':
                wait = True

            elif o == '--max-wait':
                max_wait = int(a)

            elif o == '--timeout':
                timeout = int(a)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            name = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        descriptor = os.path.join(pki.server.PKIServer.SHARE_DIR,
                                  '%s/conf/Catalina/localhost/%s.xml' % (name, name))
        doc_base = os.path.join(pki.server.PKIServer.SHARE_DIR,
                                '%s/webapps/%s' % (name, name))

        instance.undeploy_webapp(
            name,
            wait=True,
            max_wait=max_wait,
            timeout=timeout)

        instance.deploy_webapp(
            name,
            descriptor,
            doc_base,
            wait=wait,
            max_wait=max_wait,
            timeout=timeout)


class SubsystemEnableCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('enable', 'Enable subsystem')

    def usage(self):
        print('Usage: pki-server subsystem-enable [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --all                       Enable all subsystems.')
        print('      --silent                    Run in silent mode.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'all', 'silent',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        all_subsystems = False
        silent = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--all':
                all_subsystems = True

            elif o == '--silent':
                silent = True

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.usage()
                sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        if all_subsystems:
            for subsystem in instance.get_subsystems():
                if not subsystem.is_enabled():
                    subsystem.enable()

            if not silent:
                self.print_message('Enabled all subsystems')

            return

        if len(args) != 1:
            logger.error('Missing subsystem ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name, instance_name)
            sys.exit(1)

        if subsystem.is_enabled():
            if not silent:
                self.print_message(
                    'Subsystem "%s" is already enabled' % subsystem_name)
        else:
            subsystem.enable()
            if not silent:
                self.print_message('Enabled "%s" subsystem' % subsystem_name)

        if not silent:
            SubsystemCLI.print_subsystem(subsystem)


class SubsystemDisableCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('disable', 'Disable subsystem')

    def usage(self):
        print('Usage: pki-server subsystem-disable [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --all                       Disable all subsystems.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'all',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        all_subsystems = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--all':
                all_subsystems = True

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.usage()
                sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        if all_subsystems:
            for subsystem in instance.get_subsystems():
                if subsystem.is_enabled():
                    subsystem.disable()

            self.print_message('Disabled all subsystems')

            return

        if len(args) != 1:
            logger.error('Missing subsystem ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name, instance_name)
            sys.exit(1)

        if not subsystem.is_enabled():
            self.print_message('Subsystem "%s" is already '
                               'disabled' % subsystem_name)
        else:
            subsystem.disable()
            self.print_message('Disabled "%s" subsystem' % subsystem_name)

        SubsystemCLI.print_subsystem(subsystem)


class SubsystemCertCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('cert', 'Subsystem certificate management commands')

        self.add_module(SubsystemCertFindCLI())
        self.add_module(SubsystemCertShowCLI())
        self.add_module(SubsystemCertExportCLI())
        self.add_module(SubsystemCertUpdateCLI())
        self.add_module(SubsystemCertValidateCLI())

    @staticmethod
    def print_subsystem_cert(cert, show_all=False):
        print('  Serial No: %s' % cert['serial_number'])
        print('  Cert ID: %s' % cert['id'])
        print('  Nickname: %s' % cert['nickname'])

        token = cert['token']
        if not token:
            token = pki.nssdb.INTERNAL_TOKEN_FULL_NAME

        print('  Token: %s' % token)

        if show_all:
            print('  Certificate: %s' % cert['data'])
            print('  Request: %s' % cert['request'])


class SubsystemCertFindCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('find', 'Find subsystem certificates')

    def print_help(self):
        print('Usage: pki-server subsystem-cert-find [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --show-all                  Show all attributes.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'show-all',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        show_all = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--show-all':
                show_all = True

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) != 1:
            logger.error('Missing subsystem ID')
            self.print_help()
            sys.exit(1)

        subsystem_name = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name, instance_name)
            sys.exit(1)

        certs = subsystem.get_cert_infos()

        self.print_message('%s entries matched' % len(certs))

        first = True
        for cert in certs:
            if first:
                first = False
            else:
                print()

            if cert['nickname']:
                cert_info = subsystem.get_nssdb_cert_info(cert['id'])
                if cert_info:
                    cert.update(cert_info)

            SubsystemCertCLI.print_subsystem_cert(cert, show_all)


class SubsystemCertShowCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('show', 'Show subsystem certificate')

    def usage(self):
        print('Usage: pki-server subsystem-cert-show [OPTIONS] <subsystem ID> <cert ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --show-all                  Show all attributes.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'show-all',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        show_all = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--show-all':
                show_all = True

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.usage()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing subsystem ID')
            self.usage()
            sys.exit(1)

        if len(args) < 2:
            logger.error('Missing cert ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]
        cert_id = args[1]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name, instance_name)
            sys.exit(1)
        cert = subsystem.get_subsystem_cert(cert_id)
        self.print_message('"{}" subsystem "{}" certificate'.format(subsystem_name, cert_id))
        SubsystemCertCLI.print_subsystem_cert(cert, show_all)


class SubsystemCertExportCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('export', 'Export subsystem certificate')

    def print_help(self):
        print('Usage: pki-server subsystem-cert-export [OPTIONS] <subsystem ID> [cert ID]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --cert-file <path>             Output file to store the exported certificate '
              'in PEM format.')
        print('      --csr-file <path>              Output file to store the exported CSR in PEM '
              'format.')
        print('      --pkcs12-file <path>           Output file to store the exported certificate '
              'and key in PKCS #12 format.')
        print('      --pkcs12-password <password>   Password for the PKCS #12 file.')
        print('      --pkcs12-password-file <path>  Input file containing the password for the '
              'PKCS #12 file.')
        print('      --append                       Append into an existing PKCS #12 file.')
        print('      --no-trust-flags               Do not include trust flags')
        print('      --no-key                       Do not include private key')
        print('      --no-chain                     Do not include certificate chain')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'cert-file=', 'csr-file=',
                'pkcs12-file=', 'pkcs12-password=', 'pkcs12-password-file=',
                'append', 'no-trust-flags', 'no-key', 'no-chain',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        cert_file = None
        csr_file = None
        pkcs12_file = None
        pkcs12_password = None
        pkcs12_password_file = None
        append = False
        include_trust_flags = True
        include_key = True
        include_chain = True

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--cert-file':
                cert_file = a

            elif o == '--csr-file':
                csr_file = a

            elif o == '--pkcs12-file':
                pkcs12_file = a

            elif o == '--pkcs12-password':
                pkcs12_password = a

            elif o == '--pkcs12-password-file':
                pkcs12_password_file = a

            elif o == '--append':
                append = True

            elif o == '--no-trust-flags':
                include_trust_flags = False

            elif o == '--no-key':
                include_key = False

            elif o == '--no-chain':
                include_chain = False

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing subsystem ID')
            self.print_help()
            sys.exit(1)

        subsystem_name = args[0]

        if not (cert_file or csr_file or pkcs12_file):
            logger.error('Missing output file')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name, instance_name)
            sys.exit(1)
        subsystem_cert = None

        if len(args) >= 2:
            cert_id = args[1]
            subsystem_cert = subsystem.get_subsystem_cert(cert_id)

        if (cert_file or csr_file) and not subsystem_cert:
            logger.error('Missing cert ID')
            self.print_help()
            sys.exit(1)

        if cert_file:
            cert_data = subsystem_cert.get('data')
            if cert_data is None:
                logger.error("Unable to find certificate data for %s", cert_id)
                sys.exit(1)

            cert_data = pki.nssdb.convert_cert(cert_data, 'base64', 'pem')
            with open(cert_file, 'w', encoding='utf-8') as f:
                f.write(cert_data)

        if csr_file:
            cert_request = subsystem_cert.get('request')
            if cert_request is None:
                logger.error('Unable to find certificate request for %s', cert_id)
                sys.exit(1)

            csr_data = pki.nssdb.convert_csr(cert_request, 'base64', 'pem')
            with open(csr_file, 'w', encoding='utf-8') as f:
                f.write(csr_data)

        if pkcs12_file:

            if not pkcs12_password and not pkcs12_password_file:
                pkcs12_password = getpass.getpass(prompt='Enter password for PKCS #12 file: ')

            nicknames = []

            if subsystem_cert:
                nicknames.append(subsystem_cert['nickname'])

            else:
                subsystem_certs = subsystem.find_system_certs()
                for subsystem_cert in subsystem_certs:
                    nicknames.append(subsystem_cert['nickname'])

            nssdb = instance.open_nssdb()
            try:
                nssdb.export_pkcs12(
                    pkcs12_file=pkcs12_file,
                    pkcs12_password=pkcs12_password,
                    pkcs12_password_file=pkcs12_password_file,
                    nicknames=nicknames,
                    append=append,
                    include_trust_flags=include_trust_flags,
                    include_key=include_key,
                    include_chain=include_chain)

            finally:
                nssdb.close()


class SubsystemCertUpdateCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('update', 'Update subsystem certificate')

    def usage(self):
        print('Usage: pki-server subsystem-cert-update [OPTIONS] <subsystem ID> <cert ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --cert <certificate>        New certificate to be added')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'cert=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        cert_file = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.usage()
                sys.exit()

            elif o == '--cert':
                cert_file = a

            else:
                logger.error('Unknown option: %s', o)
                self.usage()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing subsystem ID')
            self.usage()
            sys.exit(1)

        if len(args) < 2:
            logger.error('Missing cert ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]
        cert_id = args[1]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name, instance_name)
            sys.exit(1)
        system_cert = subsystem.get_subsystem_cert(cert_id)

        logger.info('Retrieving certificate %s from %s',
                    system_cert['nickname'], system_cert['token'])

        token = system_cert['token']
        nssdb = instance.open_nssdb(token)

        if cert_file:
            if not os.path.isfile(cert_file):
                logger.error('%s certificate does not exist.', cert_file)
                self.usage()
                sys.exit(1)

            data = nssdb.get_cert(
                nickname=system_cert['nickname'],
                output_format='base64')

            if data:
                logger.info('Removing old %s certificate from database.',
                            system_cert['nickname'])
                nssdb.remove_cert(nickname=system_cert['nickname'])

            logger.info('Adding new %s certificate into database.', system_cert['nickname'])
            nssdb.add_cert(
                nickname=system_cert['nickname'],
                cert_file=cert_file)

        # Retrieve the cert info from NSSDB
        # Note: This reloads `data` object if --cert option is provided
        data = nssdb.get_cert(
            nickname=system_cert['nickname'],
            output_format='base64')
        system_cert['data'] = data

        # format cert data for LDAP database
        lines = [data[i:i + 64] for i in range(0, len(data), 64)]
        data = '\r\n'.join(lines) + '\r\n'

        logger.info('Retrieving certificate request from CA database')

        # TODO: add support for remote CA
        ca = instance.get_subsystem('ca')
        if not ca:
            logger.error('No CA subsystem in instance %s.', instance_name)
            sys.exit(1)

        results = ca.find_cert_requests(cert=data)

        if results:
            cert_request = results[-1]
            request = cert_request['request']

            # format cert request for CS.cfg
            lines = request.splitlines()
            if lines[0] == '-----BEGIN CERTIFICATE REQUEST-----':
                lines = lines[1:]
            if lines[-1] == '-----END CERTIFICATE REQUEST-----':
                lines = lines[:-1]
            request = ''.join(lines)
            system_cert['request'] = request

        else:
            logger.warning('Certificate request not found')

        # store cert request
        subsystem.store_system_cert_request(system_cert)
        subsystem.save()

        self.print_message('Updated "%s" subsystem certificate' % cert_id)


class SubsystemCertValidateCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('validate', 'Validate subsystem certificates', deprecated=True)

    def usage(self):
        print('Usage: pki-server subsystem-cert-validate [OPTIONS] <subsystem ID> [<cert_id>]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        logger.warning(
            'The pki-server subsystem-cert-validate has been deprecated. '
            'Use pki-server cert-validate instead.')

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.usage()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing subsystem ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]

        if len(args) >= 2:
            cert_id = args[1]
        else:
            cert_id = None

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name, instance_name)
            sys.exit(1)

        if cert_id is not None:
            certs = [subsystem.get_subsystem_cert(cert_id)]
        else:
            certs = subsystem.find_system_certs()

        first = True
        certs_valid = True

        for cert in certs:

            if first:
                first = False
            else:
                print()

            certs_valid &= self.validate_certificate(subsystem, cert)

        if certs_valid:
            self.print_message("Validation succeeded")
            sys.exit(0)
        else:
            self.print_message("Validation failed")
            sys.exit(1)

    def validate_certificate(self, subsystem, cert):

        logger.info(cert)

        print('  Cert ID: %s' % cert['id'])

        if not cert['data']:
            print('  Status: ERROR: missing certificate data')
            return False

        nickname = cert['nickname']
        if not nickname:
            print('  Status: ERROR: missing nickname')
            return False

        print('  Nickname: %s' % nickname)

        usage = cert['certusage']
        if not usage:
            print('  Status: ERROR: missing usage')
            return False

        print('  Usage: %s' % usage)

        token = cert['token']
        if not token:
            token = pki.nssdb.INTERNAL_TOKEN_FULL_NAME

        print('  Token: %s' % token)

        try:
            subsystem.validate_system_cert(cert['id'])
            print('  Status: VALID')

            return True

        except subprocess.CalledProcessError as e:
            if e.output:
                status = e.output.decode('utf-8')
            else:
                status = 'ERROR'
            print('  Status: %s' % status)
            return False
