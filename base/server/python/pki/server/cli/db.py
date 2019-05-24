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
import ldap
import logging
import nss.nss as nss
import subprocess
import sys
import getpass

import pki.cli


class DBCLI(pki.cli.CLI):

    def __init__(self):
        super(DBCLI, self).__init__(
            'db', 'DB management commands')

        self.add_module(DBUpgrade())
        self.add_module(DBSchemaUpgrade())


class DBSchemaUpgrade(pki.cli.CLI):

    SCHEMA_PATH = '/usr/share/pki/server/conf/schema.ldif'

    def __init__(self):
        super(DBSchemaUpgrade, self).__init__(
            'schema-upgrade', 'Upgrade PKI database schema')

    def usage(self):
        print('Usage: pki-server db-schema-upgrade [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).')
        print('  -w, --bind-password <password>     Password to connect to DB.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(
                argv, 'i:D:w:v', ['instance=', 'bind-dn=', 'bind-password=',
                                  'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
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
                self.set_verbose(True)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.usage()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print("ERROR: Invalid instance %s." % instance_name)
            sys.exit(1)
        instance.load()

        if not instance.subsystems:
            print("ERROR: No subsystem in instance %s." % instance_name)
            sys.exit(1)

        if not bind_password:
            bind_password = getpass.getpass(prompt='Enter password: ')

        try:
            self.update_schema(instance.subsystems[0], bind_dn, bind_password)

        except subprocess.CalledProcessError as e:
            print("ERROR: " + e.output)
            sys.exit(e.returncode)

        self.print_message('Upgrade complete')

    def update_schema(self, subsystem, bind_dn, bind_password):
        # TODO(alee) re-implement this using open_database
        host = subsystem.config['internaldb.ldapconn.host']
        port = subsystem.config['internaldb.ldapconn.port']
        secure = subsystem.config['internaldb.ldapconn.secureConn']
        cmd = ['ldapmodify',
               '-c',
               '-D', bind_dn,
               '-w', bind_password,
               '-h', host,
               '-p', port,
               '-f', self.SCHEMA_PATH
               ]

        if secure.lower() == "true":
            cmd.append('-Z')

        subprocess.check_output(cmd, stderr=subprocess.STDOUT)


class DBUpgrade(pki.cli.CLI):
    def __init__(self):
        super(DBUpgrade, self).__init__(
            'upgrade', 'Upgrade PKI server database')

    def usage(self):
        print('Usage: pki-server db-upgrade [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(
                argv, 'i:v', ['instance=', 'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.usage()
                sys.exit(1)

        nss.nss_init_nodb()

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print("ERROR: Invalid instance %s." % instance_name)
            sys.exit(1)
        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            print('ERROR: No CA subsystem in instance %s.' % instance_name)
            sys.exit(1)

        base_dn = subsystem.config['internaldb.basedn']
        conn = subsystem.open_database()

        try:
            repo_dn = 'ou=certificateRepository,ou=ca,%s' % base_dn
            if self.verbose:
                print('Searching certificates records with missing issuerName in %s' % repo_dn)

            entries = conn.ldap.search_s(
                repo_dn,
                ldap.SCOPE_ONELEVEL,
                '(&(objectclass=certificaterecord)(|(!(issuername=*))(issuername=)))',
                None)

            for entry in entries:
                self.add_issuer_name(conn, entry)

        finally:
            conn.close()

        self.print_message('Upgrade complete')

    def add_issuer_name(self, conn, entry):
        dn, attrs = entry

        if self.verbose:
            print('Fixing certificate record %s' % dn)

        attr_cert = attrs.get('userCertificate;binary')
        if not attr_cert:
            return  # shouldn't happen, but nothing we can do if it does

        cert = nss.Certificate(bytearray(attr_cert[0]))
        issuer_name = str(cert.issuer)

        try:
            conn.ldap.modify_s(dn, [(ldap.MOD_REPLACE, 'issuerName', issuer_name)])
        except ldap.LDAPError as e:
            print(
                'Failed to add issuerName to certificate {}: {}'
                .format(attrs.get('cn', ['<unknown>'])[0], e))


class SubsystemDBCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemDBCLI, self).__init__(
            'db',
            '%s database management commands' % parent.name.upper())

        self.parent = parent
        self.add_module(SubsystemDBConfigCLI(self))
        self.add_module(SubsystemDBInfoCLI(self))

    @staticmethod
    def print_config(subsystem):

        name = 'internaldb.%s'

        hostname = subsystem.config.get(name % 'ldapconn.host', None)
        print('  Hostname: %s' % hostname)

        port = subsystem.config.get(name % 'ldapconn.port', None)
        print('  Port: %s' % port)

        secure = subsystem.config.get(name % 'ldapconn.secureConn', None)
        print('  Secure: %s' % secure)

        auth = subsystem.config.get(name % 'ldapauth.authtype', None)
        print('  Authentication: %s' % auth)

        if auth == 'BasicAuth':
            bindDN = subsystem.config.get(name % 'ldapauth.bindDN', None)
            print('  Bind DN: %s' % bindDN)

            bindPWPrompt = subsystem.config.get(name % 'ldapauth.bindPWPrompt', None)
            print('  Bind Password Prompt: %s' % bindPWPrompt)

        if auth == 'SslClientAuth':
            nickname = subsystem.config.get(name % 'ldapauth.clientCertNickname', None)
            print('  Client Certificate: %s' % nickname)

        database = subsystem.config.get(name % 'database', None)
        print('  Database: %s' % database)

        baseDN = subsystem.config.get(name % 'basedn', None)
        print('  Base DN: %s' % baseDN)

        multipleSuffix = subsystem.config.get(name % 'multipleSuffix.enable', None)
        print('  Multiple suffix: %s' % multipleSuffix)

        maxConns = subsystem.config.get(name % 'maxConns', None)
        print('  Maximum connections: %s' % maxConns)

        minConns = subsystem.config.get(name % 'minConns', None)
        print('  Minimum connections: %s' % minConns)


class SubsystemDBConfigCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemDBConfigCLI, self).__init__(
            'config',
            '%s database configuration management commands' % parent.parent.name.upper())

        self.parent = parent
        self.add_module(SubsystemDBConfigShowCLI(self))
        self.add_module(SubsystemDBConfigModifyCLI(self))


class SubsystemDBConfigShowCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemDBConfigShowCLI, self).__init__(
            'show',
            'Display %s database configuration' % parent.parent.parent.name.upper())

        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-db-config-show [OPTIONS]' % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            print('ERROR: No %s subsystem in instance %s.'
                  % (subsystem_name.upper(), instance_name))
            sys.exit(1)

        SubsystemDBCLI.print_config(subsystem)


class SubsystemDBConfigModifyCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(SubsystemDBConfigModifyCLI, self).__init__(
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
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
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

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            print('ERROR: No %s subsystem in instance %s.'
                  % (subsystem_name.upper(), instance_name))
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
        super(SubsystemDBInfoCLI, self).__init__(
            'info',
            'Display %s database info' % parent.parent.name.upper())

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
            print('ERROR: %s' % e)
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
                print('ERROR: unknown option %s' % o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            print('ERROR: No %s subsystem in instance %s.'
                  % (subsystem_name.upper(), instance_name))
            sys.exit(1)

        subsystem.run(cmd, as_current_user=as_current_user)
