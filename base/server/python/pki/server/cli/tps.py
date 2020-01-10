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

from __future__ import absolute_import
from __future__ import print_function

import getopt
import io
import ldap
import ldap.modlist
import ldif
import logging
import os
import shutil
import sys
import tempfile
import time

import pki.cli
import pki.server.cli.audit
import pki.server.cli.config
import pki.server.cli.db
import pki.server.instance

logger = logging.getLogger(__name__)

TPS_VLV_PATH = '/usr/share/pki/tps/conf/vlv.ldif'
TPS_VLV_TASKS_PATH = '/usr/share/pki/tps/conf/vlvtasks.ldif'


class TPSCLI(pki.cli.CLI):

    def __init__(self):
        super(TPSCLI, self).__init__(
            'tps', 'TPS management commands')

        self.add_module(pki.server.cli.audit.AuditCLI(self))
        self.add_module(TPSCloneCLI())
        self.add_module(pki.server.cli.config.SubsystemConfigCLI(self))
        self.add_module(TPSDBCLI(self))


class TPSCloneCLI(pki.cli.CLI):

    def __init__(self):
        super(TPSCloneCLI, self).__init__(
            'clone', 'TPS clone management commands')

        self.add_module(TPSClonePrepareCLI())


class TPSClonePrepareCLI(pki.cli.CLI):

    def __init__(self):
        super(TPSClonePrepareCLI, self).__init__(
            'prepare', 'Prepare TPS clone')

    def print_help(self):
        print('Usage: pki-server tps-clone-prepare [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --pkcs12-file <path>           PKCS #12 file to store certificates and keys.')
        print('      --pkcs12-password <password>   Password for the PKCS #12 file.')
        print('      --pkcs12-password-file <path>  File containing the PKCS #12 password.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'pkcs12-file=', 'pkcs12-password=', 'pkcs12-password-file=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        pkcs12_file = None
        pkcs12_password = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--pkcs12-file':
                pkcs12_file = a

            elif o == '--pkcs12-password':
                pkcs12_password = a.encode()

            elif o == '--pkcs12-password-file':
                with io.open(a, 'rb') as f:
                    pkcs12_password = f.read()

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

        if not pkcs12_file:
            logger.error('Missing PKCS #12 file')
            self.print_help()
            sys.exit(1)

        if not pkcs12_password:
            logger.error('Missing PKCS #12 password')
            self.print_help()
            sys.exit(1)

        instance = pki.server.instance.PKIInstance(instance_name)
        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)
        instance.load()

        subsystem = instance.get_subsystem('tps')
        if not subsystem:
            logger.error('No TPS subsystem in instance %s.', instance_name)
            sys.exit(1)

        tmpdir = tempfile.mkdtemp()

        try:
            pkcs12_password_file = os.path.join(tmpdir, 'pkcs12_password.txt')
            with open(pkcs12_password_file, 'wb') as f:
                f.write(pkcs12_password)

            subsystem.export_system_cert(
                'subsystem', pkcs12_file, pkcs12_password_file)
            subsystem.export_system_cert(
                'audit_signing', pkcs12_file, pkcs12_password_file, append=True)
            instance.export_external_certs(
                pkcs12_file, pkcs12_password_file, append=True)

        finally:
            shutil.rmtree(tmpdir)


class TPSDBCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(TPSDBCLI, self).__init__(
            'db', 'TPS database management commands')

        self.parent = parent
        self.add_module(pki.server.cli.db.SubsystemDBConfigCLI(self))
        self.add_module(pki.server.cli.db.SubsystemDBInfoCLI(self))
        self.add_module(pki.server.cli.db.SubsystemDBEmptyCLI(self))
        self.add_module(pki.server.cli.db.SubsystemDBRemoveCLI(self))
        self.add_module(pki.server.cli.db.SubsystemDBUpgradeCLI(self))
        self.add_module(TPSDBVLVCLI())


class TPSDBVLVCLI(pki.cli.CLI):

    def __init__(self):
        super(TPSDBVLVCLI, self).__init__(
            'vlv', 'TPS VLV management commands')

        self.add_module(TPSDBVLVFindCLI())
        self.add_module(TPSDBVLVAddCLI())
        self.add_module(TPSDBVLVDeleteCLI())
        self.add_module(TPSDBVLVReindexCLI())


class TPSDBVLVFindCLI(pki.cli.CLI):

    def __init__(self):
        super(TPSDBVLVFindCLI, self).__init__(
            'find', 'Find TPS VLVs')

    def print_help(self):
        print('Usage: pki-server tps-db-vlv-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).')
        print('  -w, --bind-password <password>     Password to connect to database.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(
                argv,
                'i:D:w:x:g:v',
                ['instance=', 'bind-dn=', 'bind-password=', 'generate-ldif=',
                 'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        bind_dn = None
        bind_password = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-D', '--bind-dn'):
                bind_dn = a

            elif o in ('-w', '--bind-password'):
                bind_password = a

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

        instance = pki.server.instance.PKIInstance(instance_name)
        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)
        instance.load()

        subsystem = instance.get_subsystem('tps')
        if not subsystem:
            logger.error('No TPS subsystem in instance %s.', instance_name)
            sys.exit(1)

        self.find_vlv(subsystem, bind_dn, bind_password)

    def find_vlv(self, subsystem, bind_dn, bind_password):

        conn = subsystem.open_database(bind_dn=bind_dn,
                                       bind_password=bind_password)

        try:
            database = subsystem.config['internaldb.database']
            base_dn = 'cn=' + database + ',cn=ldbm database, cn=plugins, cn=config'

            logger.info('Searching %s', base_dn)

            entries = conn.ldap.search_s(
                base_dn,
                ldap.SCOPE_SUBTREE,
                '(|(objectClass=vlvSearch)(objectClass=vlvIndex))')

            self.print_message('%d entries found' % len(entries))

            if not entries:
                return

            first = True
            for entry in entries:
                dn = entry[0]
                attrs = entry[1]

                if first:
                    first = False
                else:
                    print()

                print('  dn: %s' % dn)
                for key, values in attrs.items():
                    for value in values:
                        print('  %s: %s' % (key, value))

        finally:
            conn.close()


class TPSDBVLVAddCLI(pki.cli.CLI):

    def __init__(self):
        super(TPSDBVLVAddCLI, self).__init__(
            'add', 'Add TPS VLVs')

    def print_help(self):
        print('Usage: pki-server tps-db-vlv-add [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).')
        print('  -w, --bind-password <password>     Password to connect to database.')
        print('  -g, --generate-ldif <outfile>      Generate LDIF of required changes.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(
                argv,
                'i:D:w:x:g:v',
                ['instance=', 'bind-dn=', 'bind-password=', 'generate-ldif=',
                 'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        bind_dn = 'cn=Directory Manager'
        bind_password = None
        out_file = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-D', '--bind-dn'):
                bind_dn = a

            elif o in ('-w', '--bind-password'):
                bind_password = a

            elif o in ('-g', '--generate-ldif'):
                out_file = a

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

        instance = pki.server.instance.PKIInstance(instance_name)
        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)
        instance.load()

        subsystem = instance.get_subsystem('tps')
        if not subsystem:
            logger.error('No TPS subsystem in instance %s.', instance_name)
            sys.exit(1)

        if out_file:
            self.generate_ldif(subsystem, out_file)
            return

        self.add_vlv(subsystem, bind_dn, bind_password)

    def generate_ldif(self, subsystem, out_file):
        subsystem.customize_file(TPS_VLV_PATH, out_file)
        self.print_message('Output: %s' % out_file)

    def add_vlv(self, subsystem, bind_dn, bind_password):

        input_file = tempfile.NamedTemporaryFile(delete=False)

        try:
            subsystem.customize_file(TPS_VLV_PATH, input_file.name)

            conn = subsystem.open_database(bind_dn=bind_dn,
                                           bind_password=bind_password)

            try:
                parser = ldif.LDIFRecordList(open(input_file.name, 'rb'))
                parser.parse()

                for dn, entry in parser.all_records:

                    logger.info('Adding %s', dn)

                    add_modlist = ldap.modlist.addModlist(entry)
                    conn.ldap.add_s(dn, add_modlist)

            finally:
                conn.close()

        finally:
            os.unlink(input_file.name)

        self.print_message('VLVs added')


class TPSDBVLVDeleteCLI(pki.cli.CLI):

    def __init__(self):
        super(TPSDBVLVDeleteCLI, self).__init__(
            'del', 'Delete TPS VLVs')

    def print_help(self):
        print('Usage: pki-server tps-db-vlv-del [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).')
        print('  -w, --bind-password <password>     Password to connect to DB.')
        print('  -g, --generate-ldif <outfile>      Generate LDIF of required changes.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(
                argv,
                'i:D:w:x:g:v',
                ['instance=', 'bind-dn=', 'bind-password=', 'generate-ldif=',
                 'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        bind_dn = None
        bind_password = None
        out_file = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-D', '--bind-dn'):
                bind_dn = a

            elif o in ('-w', '--bind-password'):
                bind_password = a

            elif o in ('-g', '--generate-ldif'):
                out_file = a

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

        instance = pki.server.instance.PKIInstance(instance_name)
        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)
        instance.load()

        subsystem = instance.get_subsystem('tps')
        if not subsystem:
            logger.error('No TPS subsystem in instance %s.', instance_name)
            sys.exit(1)

        if out_file:
            self.generate_ldif(subsystem, out_file)
            return

        self.delete_vlv(subsystem, bind_dn, bind_password)

    def generate_ldif(self, subsystem, out_file):

        tmp_file = tempfile.NamedTemporaryFile(delete=False)

        try:
            subsystem.customize_file(TPS_VLV_PATH, tmp_file.name)

            parser = ldif.LDIFRecordList(open(tmp_file.name, 'rb'))
            parser.parse()

            with open(out_file, 'w') as outfile:

                writer = ldif.LDIFWriter(outfile)

                for dn, _ in reversed(parser.all_records):
                    entry = {'changetype': ['delete']}
                    writer.unparse(dn, entry)

            self.print_message('Output: %s' % out_file)

        finally:
            os.unlink(tmp_file.name)

    def delete_vlv(self, subsystem, bind_dn, bind_password):

        conn = subsystem.open_database(bind_dn=bind_dn,
                                       bind_password=bind_password)
        try:
            database = subsystem.config['internaldb.database']
            base_dn = 'cn=' + database + ',cn=ldbm database, cn=plugins, cn=config'

            logger.info('Searching %s', base_dn)

            entries = conn.ldap.search_s(
                base_dn,
                ldap.SCOPE_SUBTREE,
                '(|(objectClass=vlvSearch)(objectClass=vlvIndex))')

            if not entries:
                self.print_message('VLVs not found')
                return

            for entry in reversed(entries):
                dn = entry[0]

                logger.info('Deleting %s', dn)

                conn.ldap.delete_s(dn)

        finally:
            conn.close()

        self.print_message('VLVs deleted')


class TPSDBVLVReindexCLI(pki.cli.CLI):

    def __init__(self):
        super(TPSDBVLVReindexCLI, self).__init__(
            'reindex', 'Re-index TPS VLVs')

    def print_help(self):
        print('Usage: pki-server tps-db-vlv-reindex [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).')
        print('  -w, --bind-password <password>     Password to connect to database.')
        print('  -g, --generate-ldif <outfile>      Generate LDIF of required changes.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(
                argv,
                'i:D:w:x:g:v',
                ['instance=', 'bind-dn=', 'bind-password=', 'generate-ldif=',
                 'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        bind_dn = 'cn=Directory Manager'
        bind_password = None
        out_file = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-D', '--bind-dn'):
                bind_dn = a

            elif o in ('-w', '--bind-password'):
                bind_password = a

            elif o in ('-g', '--generate-ldif'):
                out_file = a

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

        instance = pki.server.instance.PKIInstance(instance_name)
        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)
        instance.load()

        subsystem = instance.get_subsystem('tps')
        if not subsystem:
            logger.error('No TPS subsystem in instance %s.', instance_name)
            sys.exit(1)

        if out_file:
            self.generate_ldif(subsystem, out_file)
            return

        self.reindex_vlv(subsystem, bind_dn, bind_password)

    def generate_ldif(self, subsystem, out_file):
        subsystem.customize_file(TPS_VLV_TASKS_PATH, out_file)
        self.print_message('Output: %s' % out_file)

    def reindex_vlv(self, subsystem, bind_dn, bind_password):

        input_file = tempfile.NamedTemporaryFile(delete=False)
        subsystem.customize_file(TPS_VLV_TASKS_PATH, input_file.name)

        conn = subsystem.open_database(bind_dn=bind_dn,
                                       bind_password=bind_password)

        try:
            parser = ldif.LDIFRecordList(open(input_file.name, 'rb'))
            parser.parse()

            for dn, entry in parser.all_records:

                logger.info('Adding %s', dn)

                add_modlist = ldap.modlist.addModlist(entry)
                conn.ldap.add_s(dn, add_modlist)

                while True:
                    time.sleep(1)

                    try:
                        logger.info('Checking %s', dn)

                        conn.ldap.search_s(dn, ldap.SCOPE_BASE)
                    except ldap.NO_SUCH_OBJECT:
                        break

        finally:
            os.unlink(input_file.name)
            conn.close()

        self.print_message('Reindex complete')
