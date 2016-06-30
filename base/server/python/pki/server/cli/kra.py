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
import os
import shutil
import sys
import tempfile
import time

import pki.cli


KRA_VLVS = ['allKeys', 'kraAll',
            'kraArchival', 'kraRecovery',
            'kraCanceled', 'kraCanceledEnrollment', 'kraCanceledRecovery',
            'kraRejected', 'kraRejectedEnrollment', 'kraRejectedRecovery',
            'kraComplete', 'kraCompleteEnrollment', 'kraCompleteRecovery']
KRA_VLV_PATH = '/usr/share/pki/kra/conf/vlv.ldif'
KRA_VLV_TASKS_PATH = '/usr/share/pki/kra/conf/vlvtasks.ldif'


class KRACLI(pki.cli.CLI):

    def __init__(self):
        super(KRACLI, self).__init__(
            'kra', 'KRA management commands')

        self.add_module(KRACloneCLI())
        self.add_module(KRADBCLI())


class KRACloneCLI(pki.cli.CLI):

    def __init__(self):
        super(KRACloneCLI, self).__init__(
            'clone', 'KRA clone management commands')

        self.add_module(KRAClonePrepareCLI())


class KRAClonePrepareCLI(pki.cli.CLI):

    def __init__(self):
        super(KRAClonePrepareCLI, self).__init__(
            'prepare', 'Prepare KRA clone')

    def print_help(self):
        print('Usage: pki-server kra-clone-prepare [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --pkcs12-file <path>           PKCS #12 file to store certificates and keys.')
        print('      --pkcs12-password <password>   Password for the PKCS #12 file.')
        print('      --pkcs12-password-file <path>  File containing the PKCS #12 password.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, args):

        try:
            opts, _ = getopt.gnu_getopt(args, 'i:v', [
                'instance=', 'pkcs12-file=', 'pkcs12-password=', 'pkcs12-password-file=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
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
                pkcs12_password = a

            elif o == '--pkcs12-password-file':
                with io.open(a, 'rb') as f:
                    pkcs12_password = f.read()

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        if not pkcs12_file:
            print('ERROR: Missing PKCS #12 file')
            self.print_help()
            sys.exit(1)

        if not pkcs12_password:
            print('ERROR: Missing PKCS #12 password')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)
        instance.load()

        subsystem = instance.get_subsystem('kra')
        if not subsystem:
            print('ERROR: No KRA subsystem in instance %s.' % instance_name)
            sys.exit(1)

        tmpdir = tempfile.mkdtemp()

        try:
            pkcs12_password_file = os.path.join(tmpdir, 'pkcs12_password.txt')
            with open(pkcs12_password_file, 'w') as f:
                f.write(pkcs12_password)

            subsystem.export_system_cert(
                'subsystem', pkcs12_file, pkcs12_password_file, new_file=True)
            subsystem.export_system_cert(
                'transport', pkcs12_file, pkcs12_password_file)
            subsystem.export_system_cert(
                'storage', pkcs12_file, pkcs12_password_file)
            subsystem.export_system_cert(
                'audit_signing', pkcs12_file, pkcs12_password_file)

            instance.export_external_certs(pkcs12_file, pkcs12_password_file)

        finally:
            shutil.rmtree(tmpdir)


class KRADBCLI(pki.cli.CLI):

    def __init__(self):
        super(KRADBCLI, self).__init__(
            'db', 'KRA database management commands')

        self.add_module(KRADBVLVCLI())


class KRADBVLVCLI(pki.cli.CLI):

    def __init__(self):
        super(KRADBVLVCLI, self).__init__(
            'vlv', 'KRA VLV management commands')

        self.add_module(KRADBVLVFindCLI())
        self.add_module(KRADBVLVAddCLI())
        self.add_module(KRADBVLVDeleteCLI())
        self.add_module(KRADBVLVReindexCLI())


class KRADBVLVFindCLI(pki.cli.CLI):

    def __init__(self):
        super(KRADBVLVFindCLI, self).__init__(
            'find', 'Find KRA VLVs')

    def print_help(self):
        print('Usage: pki-server kra-db-vlv-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).')
        print('  -w, --bind-password <password>     Password to connect to database.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, args):
        try:
            opts, _ = getopt.gnu_getopt(
                args,
                'i:D:w:x:g:v',
                ['instance=', 'bind-dn=', 'bind-password=', 'generate-ldif=',
                 'verbose', 'help']
            )

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
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

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

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

        subsystem = instance.get_subsystem('kra')
        if not subsystem:
            print('ERROR: No KRA subsystem in instance %s.' % instance_name)
            sys.exit(1)

        self.find_vlv(subsystem, bind_dn, bind_password)

    def find_vlv(self, subsystem, bind_dn, bind_password):

        conn = subsystem.open_database(bind_dn=bind_dn,
                                       bind_password=bind_password)

        try:
            database = subsystem.config['internaldb.database']
            base_dn = 'cn=' + database + ',cn=ldbm database, cn=plugins, cn=config'

            if self.verbose:
                print('Searching %s' % base_dn)

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


class KRADBVLVAddCLI(pki.cli.CLI):

    def __init__(self):
        super(KRADBVLVAddCLI, self).__init__(
            'add', 'Add KRA VLVs')
        self.out_file = None

    def print_help(self):
        print('Usage: pki-server kra-db-vlv-add [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).')
        print('  -w, --bind-password <password>     Password to connect to database.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('  -g, --generate-ldif <outfile>      Generate LDIF of required changes.')
        print('      --help                         Show help message.')
        print()

    def execute(self, args):
        try:
            opts, _ = getopt.gnu_getopt(
                args,
                'i:D:w:x:g:v',
                ['instance=', 'bind-dn=', 'bind-password=', 'generate-ldif=',
                 'verbose', 'help']
            )

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
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

            elif o in ('-g', '--generate-ldif'):
                self.out_file = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

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
        self.add_vlv(instance, bind_dn, bind_password)

    def add_vlv(self, instance, bind_dn, bind_password):
        subsystem = instance.get_subsystem('kra')
        if not subsystem:
            print('No KRA subsystem available.')
            return

        if self.out_file:
            subsystem.customize_file(KRA_VLV_PATH, self.out_file)
            print('KRA VLVs written to ' + self.out_file)
            return

        ldif_file = tempfile.NamedTemporaryFile(delete=False)
        subsystem.customize_file(KRA_VLV_PATH, ldif_file.name)

        conn = subsystem.open_database(bind_dn=bind_dn,
                                       bind_password=bind_password)

        try:
            parser = ldif.LDIFRecordList(open(ldif_file.name, "rb"))
            parser.parse()
            for dn, entry in parser.all_records:
                add_modlist = ldap.modlist.addModlist(entry)
                conn.ldap.add_s(dn, add_modlist)
        finally:
            os.unlink(ldif_file.name)
            conn.close()

        print('KRA VLVs added to the database for ' + instance.name)


class KRADBVLVDeleteCLI(pki.cli.CLI):

    def __init__(self):
        super(KRADBVLVDeleteCLI, self).__init__(
            'del', 'Delete KRA VLVs')
        self.out_file = None

    def print_help(self):
        print('Usage: pki-server kra-db-vlv-del [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).')
        print('  -w, --bind-password <password>     Password to connect to database.')
        print('  -g, --generate-ldif <outfile>      Generate LDIF of required changes.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, args):
        try:
            opts, _ = getopt.gnu_getopt(
                args,
                'i:D:w:x:g:v',
                ['instance=', 'bind-dn=', 'bind-password=', 'generate-ldif=',
                 'verbose', 'help']
            )

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
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

            elif o in ('-g', '--generate-ldif'):
                self.out_file = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

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
        self.delete_vlv(instance, bind_dn, bind_password)

    def delete_vlv(self, instance, bind_dn, bind_password):
        subsystem = instance.get_subsystem('kra')
        if not subsystem:
            if self.verbose:
                print('modify_kra_vlv: No KRA subsystem available.  '
                      'Skipping ...')
                return
        database = subsystem.config['internaldb.database']

        if self.out_file:
            with open(self.out_file, "w") as f:
                for vlv in KRA_VLVS:
                    dn = ("cn=" + vlv + '-' + instance.name +
                          ',cn=' + database +
                          ',cn=ldbm database, cn=plugins, cn=config')
                    index_dn = ("cn=" + vlv + '-' + instance.name +
                                "Index," + dn)
                    f.write('dn: ' + index_dn + '\n')
                    f.write('changetype: delete' + '\n')
                    f.write('\n')
                    f.write('dn: ' + dn + '\n')
                    f.write('changetype: delete' + '\n')
                    f.write('\n')
            print('KRA VLV changes written to ' + self.out_file)
            return

        conn = subsystem.open_database(bind_dn=bind_dn,
                                       bind_password=bind_password)
        try:
            for vlv in KRA_VLVS:
                dn = ("cn=" + vlv + '-' + instance.name + ',cn=' + database +
                      ',cn=ldbm database, cn=plugins, cn=config')
                index_dn = "cn=" + vlv + '-' + instance.name + "Index," + dn

                try:
                    conn.ldap.delete_s(index_dn)
                except ldap.NO_SUCH_OBJECT:
                    pass

                try:
                    conn.ldap.delete_s(dn)
                except ldap.NO_SUCH_OBJECT:
                    pass

        finally:
            conn.close()

        print('KRA VLVs deleted from the database for ' + instance.name)


class KRADBVLVReindexCLI(pki.cli.CLI):

    def __init__(self):
        super(KRADBVLVReindexCLI, self).__init__(
            'reindex', 'Re-index KRA VLVs')
        self.out_file = None

    def print_help(self):
        print('Usage: pki-server kra-db-vlv-reindex [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -D, --bind-dn <Bind DN>            Connect DN (default: cn=Directory Manager).')
        print('  -w, --bind-password <password>     Password to connect to database.')
        print('  -g, --generate-ldif <outfile>      Generate LDIF of required changes.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, args):
        try:
            opts, _ = getopt.gnu_getopt(
                args,
                'i:D:w:x:g:v',
                ['instance=', 'bind-dn=', 'bind-password=', 'generate-ldif=',
                 'verbose', 'help']
            )

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
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

            elif o in ('-g', '--generate-ldif'):
                self.out_file = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

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
        self.reindex_vlv(instance, bind_dn, bind_password)

    def reindex_vlv(self, instance, bind_dn, bind_password):
        subsystem = instance.get_subsystem('kra')
        if not subsystem:
            if self.verbose:
                print('reindex_vlv: No KRA subsystem available.  '
                      'Skipping ...')
                return

        if self.out_file:
            subsystem.customize_file(KRA_VLV_TASKS_PATH, self.out_file)
            print('KRA VLV reindex task written to ' + self.out_file)
            return

        ldif_file = tempfile.NamedTemporaryFile(delete=False)
        subsystem.customize_file(KRA_VLV_TASKS_PATH, ldif_file.name)

        conn = subsystem.open_database(bind_dn=bind_dn,
                                       bind_password=bind_password)

        print('Initiating KRA VLV reindex for ' + instance.name)

        try:
            parser = ldif.LDIFRecordList(open(ldif_file.name, "rb"))
            parser.parse()

            for dn, entry in parser.all_records:

                if self.verbose:
                    print('Adding %s' % dn)

                add_modlist = ldap.modlist.addModlist(entry)
                conn.ldap.add_s(dn, add_modlist)

                while True:
                    time.sleep(1)

                    try:
                        if self.verbose:
                            print('Checking %s' % dn)

                        conn.ldap.search_s(dn, ldap.SCOPE_BASE)
                    except ldap.NO_SUCH_OBJECT:
                        break

        finally:
            os.unlink(ldif_file.name)
            conn.close()

        print('KRA VLV reindex completed for ' + instance.name)
