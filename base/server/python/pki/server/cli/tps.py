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
import pki.server.cli.group
import pki.server.cli.user
import pki.server.instance

logger = logging.getLogger(__name__)

TPS_VLV_TASKS_PATH = '/usr/share/pki/tps/conf/vlvtasks.ldif'


class TPSCLI(pki.cli.CLI):

    def __init__(self):
        super(TPSCLI, self).__init__(
            'tps', 'TPS management commands')

        self.add_module(pki.server.cli.audit.AuditCLI(self))
        self.add_module(TPSCloneCLI())
        self.add_module(pki.server.cli.config.SubsystemConfigCLI(self))
        self.add_module(TPSDBCLI(self))
        self.add_module(pki.server.cli.group.GroupCLI(self))
        self.add_module(pki.server.cli.user.UserCLI(self))


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
        print('      --no-key                       Do not include private key.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'pkcs12-file=', 'pkcs12-password=', 'pkcs12-password-file=',
                'no-key',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        pkcs12_file = None
        pkcs12_password = None
        no_key = False

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

            elif o == '--no-key':
                no_key = True

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

        instance = pki.server.instance.PKIServerFactory.create(instance_name)
        if not instance.exists():
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
                'subsystem', pkcs12_file, pkcs12_password_file, no_key=no_key)
            subsystem.export_system_cert(
                'audit_signing', pkcs12_file, pkcs12_password_file, no_key=no_key, append=True)
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
        self.add_module(TPSDBVLVCLI(self))


class TPSDBVLVCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(TPSDBVLVCLI, self).__init__(
            'vlv', 'TPS VLV management commands')

        self.parent = parent
        self.add_module(pki.server.cli.db.SubsystemDBVLVFindCLI(self))
        self.add_module(pki.server.cli.db.SubsystemDBVLVAddCLI(self))
        self.add_module(pki.server.cli.db.SubsystemDBVLVDeleteCLI(self))
        self.add_module(TPSDBVLVReindexCLI())


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
        if not instance.exists():
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
