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
import nss.nss as nss
import sys

import pki.cli


class DBCLI(pki.cli.CLI):

    def __init__(self):
        super(DBCLI, self).__init__(
            'db', 'DB management commands')

        self.add_module(DBUpgrade())


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

    def execute(self, args):
        try:
            opts, _ = getopt.gnu_getopt(
                args, 'i:v', ['instance=', 'verbose', 'help'])

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
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.usage()
                sys.exit(1)

        nss.nss_init_nodb()

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            print('ERROR: missing subsystem ca')
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
                '(&(objectclass=certificateRecord)(!(issuerName=*)))',
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
            conn.ldap.modify_s(dn, [(ldap.MOD_ADD, 'issuerName', issuer_name)])
        except ldap.LDAPError as e:
            print(
                'Failed to add issuerName to certificate {}: {}'
                .format(attrs.get('cn', ['<unknown>'])[0], e))
