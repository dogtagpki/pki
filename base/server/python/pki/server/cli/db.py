# Authors:
#     Fraser Tweedale <ftweedal@redhat.com>
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
import getpass
import inspect
import logging
import subprocess
import sys
import textwrap
import urllib.parse

import pki.cli
import pki.server.instance

logger = logging.getLogger(__name__)


class DBCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('db', 'Database management commands')

        self.add_module(DBUpgradeCLI())
        self.add_module(DBSchemaUpgradeCLI())


class DBSchemaUpgradeCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('schema-upgrade', 'Upgrade PKI database schema')

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '-D',
            '--bind-dn',
            default='cn=Directory Manager')
        self.parser.add_argument('-w', '--bind-password')
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
        print('Usage: pki-server db-schema-upgrade [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).')
        print('  -w, --bind-password <password>     Password to connect to DB.')
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
        bind_dn = args.bind_dn
        bind_password = args.bind_password

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)
        instance.load()

        if not instance.get_subsystems():
            logger.error('No subsystem in instance %s', instance_name)
            sys.exit(1)

        if not bind_password:
            bind_password = getpass.getpass(prompt='Enter password: ')

        try:
            self.update_schema(instance.get_subsystems()[0], bind_dn, bind_password)

        except subprocess.CalledProcessError as e:
            logger.error('Unable to update schema: %s', e)
            raise e

        self.print_message('Upgrade complete')

    def update_schema(self, subsystem, bind_dn, bind_password):

        for filename in pki.server.SCHEMA_FILES:
            logger.info('Updating schema with %s', filename)
            subsystem.import_ldif(bind_dn, bind_password, filename)


class DBUpgradeCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('upgrade', 'Upgrade PKI server database')

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--as-current-user',
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
        print('Usage: pki-server db-upgrade [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
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

        debug = False
        verbose = False

        if args.debug:
            debug = True
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            verbose = True
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        as_current_user = args.as_current_user

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        # upgrade all subsystems
        for subsystem in instance.get_subsystems():

            cmd = [subsystem.name + '-db-upgrade']

            if verbose:
                cmd.append('--verbose')
            elif debug:
                cmd.append('--debug')

            subsystem.run(cmd, as_current_user=as_current_user)


class SubsystemDBCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('db', '%s database management commands' % parent.name.upper())

        self.parent = parent
        self.add_module(SubsystemDBConfigCLI(self))
        self.add_module(SubsystemDBInfoCLI(self))
        self.add_module(SubsystemDBCreateCLI(self))
        self.add_module(SubsystemDBInitCLI(self))
        self.add_module(SubsystemDBEmptyCLI(self))
        self.add_module(SubsystemDBRemoveCLI(self))
        self.add_module(SubsystemDBUpgradeCLI(self))

        self.add_module(SubsystemDBAccessCLI(self))
        self.add_module(SubsystemDBIndexCLI(self))
        self.add_module(SubsystemDBReplicationCLI(self))
        self.add_module(SubsystemDBVLVCLI(self))

    @staticmethod
    def print_config(subsystem):

        name = 'internaldb.%s'

        hostname = subsystem.config.get(name % 'ldapconn.host')
        print('  Hostname: %s' % hostname)

        port = subsystem.config.get(name % 'ldapconn.port')
        print('  Port: %s' % port)

        secure = subsystem.config.get(name % 'ldapconn.secureConn')
        print('  Secure: %s' % secure)

        auth = subsystem.config.get(name % 'ldapauth.authtype')
        print('  Authentication: %s' % auth)

        if auth == 'BasicAuth':
            bindDN = subsystem.config.get(name % 'ldapauth.bindDN')
            print('  Bind DN: %s' % bindDN)

            bindPWPrompt = subsystem.config.get(name % 'ldapauth.bindPWPrompt')
            print('  Bind Password Prompt: %s' % bindPWPrompt)

        if auth == 'SslClientAuth':
            nickname = subsystem.config.get(name % 'ldapauth.clientCertNickname')
            print('  Client Certificate: %s' % nickname)

        database = subsystem.config.get(name % 'database')
        print('  Database: %s' % database)

        baseDN = subsystem.config.get(name % 'basedn')
        print('  Base DN: %s' % baseDN)

        multipleSuffix = subsystem.config.get(name % 'multipleSuffix.enable')
        print('  Multiple suffix: %s' % multipleSuffix)

        maxConns = subsystem.config.get(name % 'maxConns')
        print('  Maximum connections: %s' % maxConns)

        minConns = subsystem.config.get(name % 'minConns')
        print('  Minimum connections: %s' % minConns)


class SubsystemDBConfigCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'config',
            '%s database configuration management commands' % parent.parent.name.upper())

        self.parent = parent
        self.add_module(SubsystemDBConfigShowCLI(self))
        self.add_module(SubsystemDBConfigModifyCLI(self))


class SubsystemDBConfigShowCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'show',
            'Display %s database configuration' % parent.parent.parent.name.upper())

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
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
        print('Usage: pki-server %s-db-config-show [OPTIONS]' % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
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

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        SubsystemDBCLI.print_config(subsystem)


class SubsystemDBConfigModifyCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__(
            'mod',
            'Modify %s database configuration' % parent.parent.parent.name.upper())

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--hostname')
        self.parser.add_argument(
            '--port',
            type=int)
        self.parser.add_argument('--secure')
        self.parser.add_argument('--auth')
        self.parser.add_argument('--bindDN')
        self.parser.add_argument('--bindPWPrompt')
        self.parser.add_argument('--nickname')
        self.parser.add_argument('--database')
        self.parser.add_argument('--baseDN')
        self.parser.add_argument('--multiSuffix')
        self.parser.add_argument(
            '--maxConns',
            type=int)
        self.parser.add_argument(
            '--minConns',
            type=int)
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
        print('Usage: pki-server %s-db-config-mod [OPTIONS]' % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --hostname <hostname>          Set hostname.')
        print('      --port <port>                  Set port number.')
        print('      --secure <True|False>          Set secure connection.')
        print('      --auth <type>                  Set authentication type')
        print('                                     (valid values: BasicAuth, SslClientAuth).')
        print('      --bindDN <bind DN>             Set bind DN.')
        print('      --bindPWPrompt <prompt>        Set bind password prompt.')
        print('      --nickname <nickname>          Set client certificate nickname.')
        print('      --database <database>          Set database name.')
        print('      --baseDN <base DN>             Set base DN.')
        print('      --multiSuffix <True|False>     Set multiple suffix.')
        print('      --maxConns <max connections>   Set maximum connections.')
        print('      --minConns <min connections>   Set minimum connections.')
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
        hostname = args.hostname
        port = str(args.port)

        secure = None
        if args.secure:
            if args.secure.lower() not in ['true', 'false']:
                raise ValueError('Invalid input: --secure accepts True or False')
            secure = args.secure.lower() == 'true'

        auth = None
        if args.auth:
            if args.auth not in ['BasicAuth', 'SslClientAuth']:
                raise ValueError('Invalid input: %s' % args.auth)
            auth = args.auth

        bindDN = args.bindDN
        bindPWPrompt = args.bindPWPrompt
        nickname = args.nickname
        database = args.database
        baseDN = args.baseDN

        multiSuffix = None
        if args.multiSuffix:
            if args.multiSuffix.lower() not in ['true', 'false']:
                raise ValueError('Invalid input: --multiSuffix accepts True or False')
            multiSuffix = args.multiSuffix.lower() == 'true'

        maxConns = args.maxConns
        minConns = args.minConns

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        name = 'internaldb.%s'

        if hostname:
            subsystem.set_config(name % 'ldapconn.host', hostname)

        if port:
            subsystem.set_config(name % 'ldapconn.port', port)

        if secure is not None:
            if secure:
                subsystem.set_config(name % 'ldapconn.secureConn', 'true')
            else:
                subsystem.set_config(name % 'ldapconn.secureConn', 'false')

        if auth:
            subsystem.set_config(name % 'ldapauth.authtype', auth)

        if bindDN:
            subsystem.set_config(name % 'ldapauth.bindDN', bindDN)

        if bindPWPrompt:
            subsystem.set_config(name % 'ldapauth.bindPWPrompt', bindPWPrompt)

        if nickname:
            subsystem.set_config(name % 'ldapauth.clientCertNickname', nickname)

        if database:
            subsystem.set_config(name % 'database', database)

        if baseDN:
            subsystem.set_config(name % 'basedn', baseDN)

        if multiSuffix is not None:
            if multiSuffix:
                subsystem.set_config(name % 'multipleSuffix.enable', 'true')
            else:
                subsystem.set_config(name % 'multipleSuffix.enable', 'false')

        if maxConns:
            subsystem.set_config(name % 'maxConns', maxConns)

        if minConns:
            subsystem.set_config(name % 'minConns', minConns)

        subsystem.save()

        SubsystemDBCLI.print_config(subsystem)


class SubsystemDBInfoCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('info', 'Display %s database info' % parent.parent.name.upper())

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--as-current-user',
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
        print('Usage: pki-server %s-db-info [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
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
        subsystem_name = self.parent.parent.name
        as_current_user = args.as_current_user

        cmd = [subsystem_name + '-db-info']

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.run(cmd, as_current_user=as_current_user)


class SubsystemDBCreateCLI(pki.cli.CLI):
    '''
    Create {subsystem} database
    '''

    help = '''\
        Usage: pki-server {subsystem}-db-create [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'create',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.name.upper()))

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
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
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.name))

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
        subsystem_name = self.parent.parent.name

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.create_database()


class SubsystemDBInitCLI(pki.cli.CLI):
    '''
    Initialize {subsystem} database
    '''

    help = '''\
        Usage: pki-server {subsystem}-db-init [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --skip-config                  Skip DS server configuration.
              --skip-schema                  Skip DS schema setup.
              --skip-base                    Skip base entry setup.
              --skip-containers              Skip container entries setup.
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'init',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.name.upper()))

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--skip-config',
            action='store_true')
        self.parser.add_argument(
            '--skip-schema',
            action='store_true')
        self.parser.add_argument(
            '--skip-base',
            action='store_true')
        self.parser.add_argument(
            '--skip-containers',
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
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.name))

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
        subsystem_name = self.parent.parent.name

        skip_config = args.skip_config
        skip_schema = args.skip_schema
        skip_base = args.skip_base
        skip_containers = args.skip_containers

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.init_database(
            skip_config=skip_config,
            skip_schema=skip_schema,
            skip_base=skip_base,
            skip_containers=skip_containers)


class SubsystemDBEmptyCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('empty', 'Empty %s database' % parent.parent.name.upper())

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--force',
            action='store_true')
        self.parser.add_argument(
            '--as-current-user',
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
        print('Usage: pki-server %s-db-empty [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --force                        Force database removal.')
        print('      --as-current-user              Run as current user.')
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
        subsystem_name = self.parent.parent.name
        force = args.force
        as_current_user = args.as_current_user

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.empty_database(
            force=force,
            as_current_user=as_current_user)


class SubsystemDBRemoveCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('remove', 'Remove %s database' % parent.parent.name.upper())

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--force',
            action='store_true')
        self.parser.add_argument(
            '--as-current-user',
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
        print('Usage: pki-server %s-db-remove [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --force                        Force database removal.')
        print('      --as-current-user              Run as current user.')
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
        subsystem_name = self.parent.parent.name
        force = args.force
        as_current_user = args.as_current_user

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.remove_database(
            force=force,
            as_current_user=as_current_user)


class SubsystemDBUpgradeCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemDBUpgradeCLI, self).__init__(
            'upgrade',
            'Upgrade %s database' % parent.parent.name.upper())

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--as-current-user',
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
        print('Usage: pki-server %s-db-upgrade [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
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
        subsystem_name = self.parent.parent.name
        as_current_user = args.as_current_user

        cmd = [subsystem_name + '-db-upgrade']

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.run(cmd, as_current_user=as_current_user)


class SubsystemDBAccessCLI(pki.cli.CLI):
    '''
    {subsystem} database access management commands
    '''

    def __init__(self, parent):
        super(SubsystemDBAccessCLI, self).__init__(
            'access',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.name.upper()))

        self.parent = parent
        self.add_module(SubsystemDBAccessGrantCLI(self))
        self.add_module(SubsystemDBAccessRevokeCLI(self))


class SubsystemDBAccessGrantCLI(pki.cli.CLI):
    '''
    Grant {subsystem} database access
    '''

    help = '''\
        Usage: pki-server {subsystem}-db-access-grant [OPTIONS] <DN>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --as-current-user              Run as current user.
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super(SubsystemDBAccessGrantCLI, self).__init__(
            'grant',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.name.upper()))

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--as-current-user',
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
        self.parser.add_argument('dn')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

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
        subsystem_name = self.parent.parent.parent.name
        as_current_user = args.as_current_user
        dn = args.dn

        instance = pki.server.instance.PKIInstance(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.grant_database_access(dn, as_current_user=as_current_user)


class SubsystemDBAccessRevokeCLI(pki.cli.CLI):
    '''
    Revoke {subsystem} database access
    '''

    help = '''\
        Usage: pki-server {subsystem}-db-access-revoke [OPTIONS] <DN>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --as-current-user              Run as current user.
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super(SubsystemDBAccessRevokeCLI, self).__init__(
            'revoke',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.name.upper()))

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--as-current-user',
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
        self.parser.add_argument('dn')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

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
        subsystem_name = self.parent.parent.parent.name
        as_current_user = args.as_current_user
        dn = args.dn

        instance = pki.server.instance.PKIInstance(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.revoke_database_access(dn, as_current_user=as_current_user)


class SubsystemDBIndexCLI(pki.cli.CLI):
    '''
    {subsystem} index management commands
    '''

    def __init__(self, parent):
        super(SubsystemDBIndexCLI, self).__init__(
            'index',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.name.upper()))

        self.parent = parent
        self.add_module(SubsystemDBIndexAddCLI(self))
        self.add_module(SubsystemDBIndexRebuildCLI(self))


class SubsystemDBIndexAddCLI(pki.cli.CLI):
    '''
    Add {subsystem} indexes
    '''

    help = '''\
        Usage: pki-server {subsystem}-db-index-add [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super(SubsystemDBIndexAddCLI, self).__init__(
            'add',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.name.upper()))

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
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
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

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
        subsystem_name = self.parent.parent.parent.name

        instance = pki.server.instance.PKIInstance(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.add_indexes()


class SubsystemDBIndexRebuildCLI(pki.cli.CLI):
    '''
    Rebuild {subsystem} indexes
    '''

    help = '''\
        Usage: pki-server {subsystem}-db-index-rebuild [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super(SubsystemDBIndexRebuildCLI, self).__init__(
            'rebuild',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.name.upper()))

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
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
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

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
        subsystem_name = self.parent.parent.parent.name

        instance = pki.server.instance.PKIInstance(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.rebuild_indexes()


class SubsystemDBReplicationCLI(pki.cli.CLI):
    '''
    {subsystem} replication management commands
    '''

    def __init__(self, parent):
        super(SubsystemDBReplicationCLI, self).__init__(
            'repl',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.name.upper()))

        self.parent = parent
        self.add_module(SubsystemDBReplicationEnableCLI(self))
        self.add_module(SubsystemDBReplicationAgreementCLI(self))


class SubsystemDBReplicationEnableCLI(pki.cli.CLI):
    '''
    Enable {subsystem} database replication
    '''

    help = '''\
        Usage: pki-server {subsystem}-db-repl-enable [OPTIONS]

          -i, --instance <instance ID>            Instance ID (default: pki-tomcat)
              --url <URL>                         Database URL
              --bind-dn <DN>                      Database bind DN
              --bind-password <password>          Database bind password
              --replica-bind-dn <DN>              Replica bind DN
              --replica-bind-password <password>  Replica bind password
              --replica-id <ID>                   Replica ID
              --suffix <DN>                       Database suffix
          -v, --verbose                           Run in verbose mode.
              --debug                             Run in debug mode.
              --help                              Show help message.
    '''

    def __init__(self, parent):
        super(SubsystemDBReplicationEnableCLI, self).__init__(
            'enable',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.name.upper()))

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--url')
        self.parser.add_argument('--bind-dn')
        self.parser.add_argument('--bind-password')
        self.parser.add_argument('--replica-bind-dn')
        self.parser.add_argument('--replica-bind-password')
        self.parser.add_argument('--replica-id')
        self.parser.add_argument('--suffix')
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
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

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
        subsystem_name = self.parent.parent.parent.name
        url = urllib.parse.urlparse(args.url)
        bind_dn = args.bind_dn
        bind_password = args.bind_password
        replica_bind_dn = args.replica_bind_dn
        replica_bind_password = args.replica_bind_password
        replica_id = args.replica_id
        suffix = args.suffix

        # user must provide the replica ID is required since
        # in the future the auto-generated replica ID will no
        # longer be supported

        if not replica_id:
            logger.error('Missing replica ID')
            sys.exit(1)

        instance = pki.server.instance.PKIInstance(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        ldap_config = {}

        if url.scheme == 'ldaps':
            ldap_config['ldapconn.secureConn'] = 'true'
        else:
            ldap_config['ldapconn.secureConn'] = 'false'

        ldap_config['ldapconn.host'] = url.hostname
        ldap_config['ldapconn.port'] = str(url.port)

        ldap_config['ldapauth.authtype'] = 'BasicAuth'
        ldap_config['ldapauth.bindDN'] = bind_dn
        ldap_config['ldapauth.bindPassword'] = bind_password

        ldap_config['basedn'] = suffix

        subsystem.enable_replication(
            ldap_config,
            replica_bind_dn,
            replica_bind_password,
            replica_id)


class SubsystemDBReplicationAgreementCLI(pki.cli.CLI):
    '''
    {subsystem} replication agreement management commands
    '''

    def __init__(self, parent):
        super(SubsystemDBReplicationAgreementCLI, self).__init__(
            'agmt',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.name.upper()))

        self.parent = parent
        self.add_module(SubsystemDBReplicationAgreementAddCLI(self))
        self.add_module(SubsystemDBReplicationAgreementInitCLI(self))


class SubsystemDBReplicationAgreementAddCLI(pki.cli.CLI):
    '''
    Add {subsystem} replication agreement
    '''

    help = '''\
        Usage: pki-server {subsystem}-db-repl-agmt-add [OPTIONS] <name>

          -i, --instance <instance ID>            Instance ID (default: pki-tomcat)
              --url <URL>                         Database URL
              --bind-dn <DN>                      Database bind DN
              --bind-password <password>          Database bind password
              --replica-url <URL>                 Replica URL
              --replica-bind-dn <DN>              Replica bind DN
              --replica-bind-password <password>  Replica bind password
              --replication-security <value>      Replication security: SSL, TLS, None
              --suffix <DN>                       Database suffix
          -v, --verbose                           Run in verbose mode.
              --debug                             Run in debug mode.
              --help                              Show help message.
    '''

    def __init__(self, parent):
        super(SubsystemDBReplicationAgreementAddCLI, self).__init__(
            'add',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.parent.name.upper()))

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--url')
        self.parser.add_argument('--bind-dn')
        self.parser.add_argument('--bind-password')
        self.parser.add_argument('--replica-url')
        self.parser.add_argument('--replica-bind-dn')
        self.parser.add_argument('--replica-bind-password')
        self.parser.add_argument('--replication-security')
        self.parser.add_argument('--suffix')
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
        self.parser.add_argument('name')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.parent.name))

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
        subsystem_name = self.parent.parent.parent.parent.name
        url = urllib.parse.urlparse(args.url)
        bind_dn = args.bind_dn
        bind_password = args.bind_password
        replica_url = args.replica_url
        replica_bind_dn = args.replica_bind_dn
        replica_bind_password = args.replica_bind_password
        replication_security = args.replication_security
        suffix = args.suffix
        name = args.name

        instance = pki.server.instance.PKIInstance(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        ldap_config = {}

        if url.scheme == 'ldaps':
            ldap_config['ldapconn.secureConn'] = 'true'
        else:
            ldap_config['ldapconn.secureConn'] = 'false'

        ldap_config['ldapconn.host'] = url.hostname
        ldap_config['ldapconn.port'] = str(url.port)

        ldap_config['ldapauth.authtype'] = 'BasicAuth'
        ldap_config['ldapauth.bindDN'] = bind_dn
        ldap_config['ldapauth.bindPassword'] = bind_password

        ldap_config['basedn'] = suffix

        subsystem.add_replication_agreement(
            name,
            ldap_config,
            replica_url,
            replica_bind_dn,
            replica_bind_password,
            replication_security)


class SubsystemDBReplicationAgreementInitCLI(pki.cli.CLI):
    '''
    Initialize {subsystem} replication agreement
    '''

    help = '''\
        Usage: pki-server {subsystem}-db-repl-agmt-init [OPTIONS] <name>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --url <URL>                    Database URL
              --bind-dn <DN>                 Database bind DN
              --bind-password <password>     Database bind password
              --suffix <DN>                  Database suffix
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super(SubsystemDBReplicationAgreementInitCLI, self).__init__(
            'init',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.parent.name.upper()))

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--url')
        self.parser.add_argument('--bind-dn')
        self.parser.add_argument('--bind-password')
        self.parser.add_argument('--suffix')
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
        self.parser.add_argument('name')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.parent.name))

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
        subsystem_name = self.parent.parent.parent.parent.name
        url = urllib.parse.urlparse(args.url)
        bind_dn = args.bind_dn
        bind_password = args.bind_password
        suffix = args.suffix
        name = args.name

        instance = pki.server.instance.PKIInstance(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        ldap_config = {}

        if url.scheme == 'ldaps':
            ldap_config['ldapconn.secureConn'] = 'true'
        else:
            ldap_config['ldapconn.secureConn'] = 'false'

        ldap_config['ldapconn.host'] = url.hostname
        ldap_config['ldapconn.port'] = str(url.port)

        ldap_config['ldapauth.authtype'] = 'BasicAuth'
        ldap_config['ldapauth.bindDN'] = bind_dn
        ldap_config['ldapauth.bindPassword'] = bind_password

        ldap_config['basedn'] = suffix

        subsystem.init_replication_agreement(
            name,
            ldap_config)


class SubsystemDBVLVCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemDBVLVCLI, self).__init__(
            'vlv', '%s VLV management commands' % parent.parent.name.upper())

        self.parent = parent
        self.add_module(SubsystemDBVLVFindCLI(self))
        self.add_module(SubsystemDBVLVAddCLI(self))
        self.add_module(SubsystemDBVLVDeleteCLI(self))
        self.add_module(SubsystemDBVLVReindexCLI(self))


class SubsystemDBVLVFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemDBVLVFindCLI, self).__init__(
            'find',
            'Find %s VLVs' % parent.parent.parent.name.upper())

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--as-current-user',
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
        print('Usage: pki-server %s-db-vlv-find [OPTIONS]' % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
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
        subsystem_name = self.parent.parent.parent.name
        as_current_user = args.as_current_user

        instance = pki.server.instance.PKIInstance(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.find_vlv(as_current_user=as_current_user)


class SubsystemDBVLVAddCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemDBVLVAddCLI, self).__init__(
            'add',
            'Add %s VLVs' % parent.parent.parent.name.upper())

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--as-current-user',
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
        print('Usage: pki-server %s-db-vlv-add [OPTIONS]' % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
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
        subsystem_name = self.parent.parent.parent.name
        as_current_user = args.as_current_user

        instance = pki.server.instance.PKIInstance(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.add_vlv(as_current_user=as_current_user)


class SubsystemDBVLVDeleteCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemDBVLVDeleteCLI, self).__init__(
            'del',
            'Delete %s VLVs' % parent.parent.parent.name.upper())

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--as-current-user',
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
        print('Usage: pki-server %s-db-vlv-del [OPTIONS]' % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
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
        subsystem_name = self.parent.parent.parent.name
        as_current_user = args.as_current_user

        instance = pki.server.instance.PKIInstance(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.delete_vlv(as_current_user=as_current_user)


class SubsystemDBVLVReindexCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemDBVLVReindexCLI, self).__init__(
            'reindex',
            'Re-index %s VLVs' % parent.parent.parent.name.upper())

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--as-current-user',
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
        print('Usage: pki-server %s-db-vlv-reindex [OPTIONS]' % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
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
        subsystem_name = self.parent.parent.parent.name
        as_current_user = args.as_current_user

        instance = pki.server.instance.PKIInstance(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.reindex_vlv(as_current_user=as_current_user)
