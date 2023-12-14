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

from __future__ import absolute_import
from __future__ import print_function
import getopt
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

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:D:w:v', [
                'instance=', 'bind-dn=', 'bind-password=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        bind_dn = 'cn=Directory Manager'
        bind_password = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-D', '--bind-dn'):
                bind_dn = a

            elif o in ('-w', '--bind-password'):
                bind_password = a

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

    def print_help(self):
        print('Usage: pki-server db-upgrade [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'as-current-user',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        as_current_user = False
        verbose = False
        debug = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--as-current-user':
                as_current_user = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)
                verbose = True

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)
                debug = True

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

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

    def print_help(self):
        print('Usage: pki-server %s-db-config-show [OPTIONS]' % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

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

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

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

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'hostname=', 'port=', 'secure=',
                'auth=',
                'bindDN=', 'bindPWPrompt=',
                'nickname=',
                'database=', 'baseDN=', 'multiSuffix=',
                'maxConns=', 'minConns=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        hostname = None
        port = None
        secure = None
        auth = None
        bindDN = None
        bindPWPrompt = None
        nickname = None
        database = None
        baseDN = None
        multiSuffix = None
        maxConns = None
        minConns = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--hostname':
                hostname = a

            elif o == '--port':
                if not a.isdigit():
                    raise ValueError('Invalid input: %s accepts a number' % o)
                port = a

            elif o == '--secure':
                if a.lower() not in ['true', 'false']:
                    raise ValueError('Invalid input: %s accepts True or False' % o)
                secure = a.lower() == 'true'

            elif o == '--auth':
                if a not in ['BasicAuth', 'SslClientAuth']:
                    raise ValueError('Invalid input: %s' % a)
                auth = a

            elif o == '--bindDN':
                bindDN = a

            elif o == '--bindPWPrompt':
                bindPWPrompt = a

            elif o == '--nickname':
                nickname = a

            elif o == '--database':
                database = a

            elif o == '--baseDN':
                baseDN = a

            elif o == '--multiSuffix':
                if a.lower() not in ['true', 'false']:
                    raise ValueError('Invalid input: %s accepts True or False' % o)
                multiSuffix = a.lower() == 'true'

            elif o == '--maxConns':
                if not a.isdigit():
                    raise ValueError('Invalid input: %s accepts a number' % o)
                maxConns = a

            elif o == '--minConns':
                if not a.isdigit():
                    raise ValueError('Invalid input: %s accepts a number' % o)
                minConns = a

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
            subsystem.config[name % 'ldapconn.host'] = hostname

        if port:
            subsystem.config[name % 'ldapconn.port'] = port

        if secure is not None:
            if secure:
                subsystem.config[name % 'ldapconn.secureConn'] = 'true'
            else:
                subsystem.config[name % 'ldapconn.secureConn'] = 'false'

        if auth:
            subsystem.config[name % 'ldapauth.authtype'] = auth

        if bindDN:
            subsystem.config[name % 'ldapauth.bindDN'] = bindDN

        if bindPWPrompt:
            subsystem.config[name % 'ldapauth.bindPWPrompt'] = bindPWPrompt

        if nickname:
            subsystem.config[name % 'ldapauth.clientCertNickname'] = nickname

        if database:
            subsystem.config[name % 'database'] = database

        if baseDN:
            subsystem.config[name % 'basedn'] = baseDN

        if multiSuffix is not None:
            if multiSuffix:
                subsystem.config[name % 'multipleSuffix.enable'] = 'true'
            else:
                subsystem.config[name % 'multipleSuffix.enable'] = 'false'

        if maxConns:
            subsystem.config[name % 'maxConns'] = maxConns

        if minConns:
            subsystem.config[name % 'minConns'] = minConns

        subsystem.save()

        SubsystemDBCLI.print_config(subsystem)


class SubsystemDBInfoCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('info', 'Display %s database info' % parent.parent.name.upper())

        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-db-info [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'as-current-user',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.name
        as_current_user = False

        cmd = [subsystem_name + '-db-info']

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--as-current-user':
                as_current_user = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)
                cmd.append('--verbose')

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)
                cmd.append('--debug')

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.name))

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
        subsystem_name = self.parent.parent.name

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.name))

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'skip-config', 'skip-schema',
                'skip-base', 'skip-containers',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.name

        skip_config = False
        skip_schema = False
        skip_base = False
        skip_containers = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--skip-config':
                skip_config = True

            elif o == '--skip-schema':
                skip_schema = True

            elif o == '--skip-base':
                skip_base = True

            elif o == '--skip-containers':
                skip_containers = True

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

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'force', 'as-current-user',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.name
        force = False
        as_current_user = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--force':
                force = True

            elif o == '--as-current-user':
                as_current_user = True

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

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'force', 'as-current-user',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.name
        force = False
        as_current_user = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--force':
                force = True

            elif o == '--as-current-user':
                as_current_user = True

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

    def print_help(self):
        print('Usage: pki-server %s-db-upgrade [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'as-current-user',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.name
        as_current_user = False

        cmd = [subsystem_name + '-db-upgrade']

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--as-current-user':
                as_current_user = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)
                cmd.append('--verbose')

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)
                cmd.append('--debug')

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'as-current-user',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name
        as_current_user = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--as-current-user':
                as_current_user = True

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

        if len(args) < 1:
            logger.error('Missing DN')
            self.print_help()
            sys.exit(1)

        dn = args[0]

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'as-current-user',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name
        as_current_user = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--as-current-user':
                as_current_user = True

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

        if len(args) < 1:
            logger.error('Missing DN')
            self.print_help()
            sys.exit(1)

        dn = args[0]

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

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
        subsystem_name = self.parent.parent.parent.name

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

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
        subsystem_name = self.parent.parent.parent.name

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'url=', 'bind-dn=', 'bind-password=',
                'replica-bind-dn=', 'replica-bind-password=',
                'replica-id=', 'suffix=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name
        url = None
        bind_dn = None
        bind_password = None
        replica_bind_dn = None
        replica_bind_password = None
        replica_id = None
        suffix = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--url':
                url = urllib.parse.urlparse(a)

            elif o == '--bind-dn':
                bind_dn = a

            elif o == '--bind-password':
                bind_password = a

            elif o == '--replica-bind-dn':
                replica_bind_dn = a

            elif o == '--replica-bind-password':
                replica_bind_password = a

            elif o == '--replica-id':
                replica_id = a

            elif o == '--suffix':
                suffix = a

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.parent.name))

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'url=', 'bind-dn=', 'bind-password=',
                'replica-url=', 'replica-bind-dn=', 'replica-bind-password=',
                'replication-security=', 'suffix=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.parent.name
        url = None
        bind_dn = None
        bind_password = None
        replica_url = None
        replica_bind_dn = None
        replica_bind_password = None
        replication_security = None
        suffix = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--url':
                url = urllib.parse.urlparse(a)

            elif o == '--bind-dn':
                bind_dn = a

            elif o == '--bind-password':
                bind_password = a

            elif o == '--replica-url':
                replica_url = a

            elif o == '--replica-bind-dn':
                replica_bind_dn = a

            elif o == '--replica-bind-password':
                replica_bind_password = a

            elif o == '--replication-security':
                replication_security = a

            elif o == '--suffix':
                suffix = a

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

        if len(args) < 1:
            logger.error('Missing replication agreement name')
            self.print_help()
            sys.exit(1)

        name = args[0]

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.parent.name))

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'url=', 'bind-dn=', 'bind-password=', 'suffix=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.parent.name
        url = None
        bind_dn = None
        bind_password = None
        suffix = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--url':
                url = urllib.parse.urlparse(a)

            elif o == '--bind-dn':
                bind_dn = a

            elif o == '--bind-password':
                bind_password = a

            elif o == '--suffix':
                suffix = a

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

        if len(args) < 1:
            logger.error('Missing replication agreement name')
            self.print_help()
            sys.exit(1)

        name = args[0]

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

    def print_help(self):
        print('Usage: pki-server %s-db-vlv-find [OPTIONS]' % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'as-current-user',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name
        as_current_user = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--as-current-user':
                as_current_user = True

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

    def print_help(self):
        print('Usage: pki-server %s-db-vlv-add [OPTIONS]' % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'as-current-user',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name
        as_current_user = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--as-current-user':
                as_current_user = True

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

    def print_help(self):
        print('Usage: pki-server %s-db-vlv-del [OPTIONS]' % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'as-current-user',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name
        as_current_user = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--as-current-user':
                as_current_user = True

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

    def print_help(self):
        print('Usage: pki-server %s-db-vlv-reindex [OPTIONS]' % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --as-current-user              Run as current user.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'as-current-user',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name
        as_current_user = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--as-current-user':
                as_current_user = True

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
