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
# Copyright (C) 2015 Red Hat, Inc.
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


class CACLI(pki.cli.CLI):

    def __init__(self):
        super(CACLI, self).__init__(
            'ca', 'CA management commands')

        self.add_module(CACertCLI())
        self.add_module(CACloneCLI())


class CACertCLI(pki.cli.CLI):

    def __init__(self):
        super(CACertCLI, self).__init__(
            'cert', 'CA certificates management commands')

        self.add_module(CACertChainCLI())
        self.add_module(CACertRequestCLI())


class CACertChainCLI(pki.cli.CLI):

    def __init__(self):
        super(CACertChainCLI, self).__init__(
            'chain', 'CA certificate chain management commands')

        self.add_module(CACertChainExportCLI())


class CACertChainExportCLI(pki.cli.CLI):

    def __init__(self):
        super(CACertChainExportCLI, self).__init__(
            'export', 'Export certificate chain')

    def print_help(self):
        print('Usage: pki-server ca-cert-chain-export [OPTIONS]')
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

        subsystem = instance.get_subsystem('ca')

        tmpdir = tempfile.mkdtemp()

        try:
            pkcs12_password_file = os.path.join(tmpdir, 'pkcs12_password.txt')
            with open(pkcs12_password_file, 'w') as f:
                f.write(pkcs12_password)

            subsystem.export_cert_chain(pkcs12_file, pkcs12_password_file)

        finally:
            shutil.rmtree(tmpdir)


class CACertRequestCLI(pki.cli.CLI):

    def __init__(self):
        super(CACertRequestCLI, self).__init__(
            'request', 'CA certificate requests management commands')

        self.add_module(CACertRequestFindCLI())
        self.add_module(CACertRequestShowCLI())

    @staticmethod
    def print_request(request, details=False):
        print('  Request ID: %s' % request['id'])
        print('  Type: %s' % request['type'])
        print('  Status: %s' % request['status'])

        if details:
            print('  Request: %s' % request['request'])


class CACertRequestFindCLI(pki.cli.CLI):

    def __init__(self):
        super(CACertRequestFindCLI, self).__init__(
            'find', 'Find CA certificate requests')

    def usage(self):
        print('Usage: pki-server ca-cert-request-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --cert                      Issued certificate.')
        print('      --cert-file                 File containing issued certificate.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, args):

        try:
            opts, _ = getopt.gnu_getopt(args, 'i:v', [
                'instance=', 'cert=', 'cert-file=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        cert = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--cert':
                cert = a

            elif o == '--cert-file':
                with io.open(a, 'rb') as f:
                    cert = f.read()

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.usage()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        subsystem = instance.get_subsystem('ca')
        results = subsystem.find_cert_requests(cert=cert)

        self.print_message('%s entries matched' % len(results))

        first = True
        for request in results:
            if first:
                first = False
            else:
                print()

            CACertRequestCLI.print_request(request)


class CACertRequestShowCLI(pki.cli.CLI):

    def __init__(self):
        super(CACertRequestShowCLI, self).__init__(
            'show', 'Show CA certificate request')

    def usage(self):
        print('Usage: pki-server ca-cert-request-show <request ID> [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, args):

        try:
            opts, args = getopt.gnu_getopt(args, 'i:v', [
                'instance=', 'output-file=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        if len(args) != 1:
            print('ERROR: missing request ID')
            self.usage()
            sys.exit(1)

        request_id = args[0]
        instance_name = 'pki-tomcat'
        output_file = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--output-file':
                output_file = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.usage()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        subsystem = instance.get_subsystem('ca')
        request = subsystem.get_cert_requests(request_id)

        if output_file:
            with io.open(output_file, 'wb') as f:
                f.write(request['request'])

        else:
            CACertRequestCLI.print_request(request, details=True)


class CACloneCLI(pki.cli.CLI):

    def __init__(self):
        super(CACloneCLI, self).__init__(
            'clone', 'CA clone management commands')

        self.add_module(CAClonePrepareCLI())


class CAClonePrepareCLI(pki.cli.CLI):

    def __init__(self):
        super(CAClonePrepareCLI, self).__init__(
            'prepare', 'Prepare CA clone')

    def print_help(self):
        print('Usage: pki-server ca-clone-prepare [OPTIONS]')
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

        subsystem = instance.get_subsystem('ca')

        tmpdir = tempfile.mkdtemp()

        try:
            pkcs12_password_file = os.path.join(tmpdir, 'pkcs12_password.txt')
            with open(pkcs12_password_file, 'w') as f:
                f.write(pkcs12_password)

            subsystem.export_system_cert(
                'subsystem', pkcs12_file, pkcs12_password_file, new_file=True)
            subsystem.export_system_cert('signing', pkcs12_file, pkcs12_password_file)
            subsystem.export_system_cert('ocsp_signing', pkcs12_file, pkcs12_password_file)
            subsystem.export_system_cert('audit_signing', pkcs12_file, pkcs12_password_file)

        finally:
            shutil.rmtree(tmpdir)
