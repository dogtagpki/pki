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
import os
import shutil
import sys
import tempfile

import pki.cli


class TPSCLI(pki.cli.CLI):

    def __init__(self):
        super(TPSCLI, self).__init__(
            'tps', 'TPS management commands')

        self.add_module(TPSCloneCLI())


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
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --pkcs12-file               PKCS #12 file to store certificates and keys.')
        print('      --pkcs12-password           Password for the PKCS #12 file.')
        print('      --pkcs12-password-file      File containing the PKCS #12 password.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
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
        instance.load()

        subsystem = instance.get_subsystem('tps')

        tmpdir = tempfile.mkdtemp()

        try:
            pkcs12_password_file = os.path.join(tmpdir, 'pkcs12_password.txt')
            with open(pkcs12_password_file, 'w') as f:
                f.write(pkcs12_password)

            subsystem.export_system_cert(
                'subsystem', pkcs12_file, pkcs12_password_file, new_file=True)
            subsystem.export_system_cert(
                'signing', pkcs12_file, pkcs12_password_file)
            subsystem.export_system_cert(
                'audit_signing', pkcs12_file, pkcs12_password_file)

        finally:
            shutil.rmtree(tmpdir)
