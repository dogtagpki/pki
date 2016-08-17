# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#     Abhijeet Kasurde <akasurde@redhat.com>
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
import base64
import getopt
import getpass
import nss.nss as nss
import os
import string
import subprocess
import sys
from tempfile import mkstemp

import pki.cli
import pki.nssdb
import pki.server


class SubsystemCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemCLI, self).__init__('subsystem',
                                           'Subsystem management commands')

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
        super(SubsystemFindCLI, self).__init__('find', 'Find subsystems')

    def usage(self):
        print('Usage: pki-server subsystem-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, args):

        try:
            opts, _ = getopt.gnu_getopt(args, 'i:v', [
                'instance=',
                'verbose', 'help'])

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

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        self.print_message('%s entries matched' % len(instance.subsystems))

        first = True
        for subsystem in instance.subsystems:
            if first:
                first = False
            else:
                print()

            SubsystemCLI.print_subsystem(subsystem)


class SubsystemShowCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemShowCLI, self).__init__('show', 'Show subsystem')

    def usage(self):
        print('Usage: pki-server subsystem-show [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

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

        if len(args) != 1:
            print('ERROR: missing subsystem ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            print('ERROR: No %s subsystem in instance '
                  '%s.' % (subsystem_name, instance_name))
            sys.exit(1)

        SubsystemCLI.print_subsystem(subsystem)


class SubsystemEnableCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemEnableCLI, self).__init__('enable', 'Enable subsystem')

    def usage(self):
        print('Usage: pki-server subsystem-enable [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

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

        if len(args) != 1:
            print('ERROR: missing subsystem ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            print('ERROR: No %s subsystem in instance '
                  '%s.' % (subsystem_name, instance_name))
            sys.exit(1)

        if subsystem.is_enabled():
            self.print_message('Subsystem "%s" is already '
                               'enabled' % subsystem_name)
        else:
            subsystem.enable()
            self.print_message('Enabled "%s" subsystem' % subsystem_name)

        SubsystemCLI.print_subsystem(subsystem)


class SubsystemDisableCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemDisableCLI, self).__init__(
            'disable',
            'Disable subsystem')

    def usage(self):
        print('Usage: pki-server subsystem-disable [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

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

        if len(args) != 1:
            print('ERROR: missing subsystem ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            print('ERROR: No %s subsystem in instance '
                  '%s.' % (subsystem_name, instance_name))
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
        super(SubsystemCertCLI, self).__init__(
            'cert', 'Subsystem certificate management commands')

        self.add_module(SubsystemCertFindCLI())
        self.add_module(SubsystemCertShowCLI())
        self.add_module(SubsystemCertExportCLI())
        self.add_module(SubsystemCertUpdateCLI())
        self.add_module(SubsystemCertValidateCLI())

    @staticmethod
    def print_subsystem_cert(cert, show_all=False):
        print('  Cert ID: %s' % cert['id'])
        print('  Nickname: %s' % cert['nickname'])
        print('  Token: %s' % cert['token'])

        if show_all:
            print('  Certificate: %s' % cert['data'])
            print('  Request: %s' % cert['request'])


class SubsystemCertFindCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemCertFindCLI, self).__init__(
            'find', 'Find subsystem certificates')

    def print_help(self):
        print('Usage: pki-server subsystem-cert-find [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --show-all                  Show all attributes.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'show-all',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        show_all = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--show-all':
                show_all = True

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        if len(args) != 1:
            print('ERROR: missing subsystem ID')
            self.print_help()
            sys.exit(1)

        subsystem_name = args[0]

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            print('ERROR: No %s subsystem in instance '
                  '%s.' % (subsystem_name, instance_name))
            sys.exit(1)
        results = subsystem.find_system_certs()

        self.print_message('%s entries matched' % len(results))

        first = True
        for cert in results:
            if first:
                first = False
            else:
                print()

            SubsystemCertCLI.print_subsystem_cert(cert, show_all)


class SubsystemCertShowCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemCertShowCLI, self).__init__(
            'show', 'Show subsystem certificate')

    def usage(self):
        print('Usage: pki-server subsystem-cert-show [OPTIONS] <subsystem ID> <cert ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --show-all                  Show all attributes.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'show-all',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        show_all = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--show-all':
                show_all = True

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.usage()
                sys.exit(1)

        if len(args) < 1:
            print('ERROR: missing subsystem ID')
            self.usage()
            sys.exit(1)

        if len(args) < 2:
            print('ERROR: missing cert ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]
        cert_id = args[1]

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            print('ERROR: No %s subsystem in instance '
                  '%s.' % (subsystem_name, instance_name))
            sys.exit(1)
        cert = subsystem.get_subsystem_cert(cert_id)

        SubsystemCertCLI.print_subsystem_cert(cert, show_all)


class SubsystemCertExportCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemCertExportCLI, self).__init__(
            'export', 'Export subsystem certificate')

    def print_help(self):  # flake8: noqa
        print('Usage: pki-server subsystem-cert-export [OPTIONS] <subsystem ID> [cert ID]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --cert-file <path>             Output file to store the exported certificate in PEM format.')
        print('      --csr-file <path>              Output file to store the exported CSR in PEM format.')
        print('      --pkcs12-file <path>           Output file to store the exported certificate and key in PKCS #12 format.')
        print('      --pkcs12-password <password>   Password for the PKCS #12 file.')
        print('      --pkcs12-password-file <path>  Input file containing the password for the PKCS #12 file.')
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
            print('ERROR: ' + str(e))
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
        debug = False

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

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--debug':
                debug = True

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            print('ERROR: missing subsystem ID')
            self.print_help()
            sys.exit(1)

        subsystem_name = args[0]

        if not (cert_file or csr_file or pkcs12_file):
            print('ERROR: missing output file')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            print('ERROR: No %s subsystem in instance '
                  '%s.' % (subsystem_name, instance_name))
            sys.exit(1)
        subsystem_cert = None

        if len(args) >= 2:
            cert_id = args[1]
            subsystem_cert = subsystem.get_subsystem_cert(cert_id)

        if (cert_file or csr_file) and not subsystem_cert:
            print('ERROR: missing cert ID')
            self.print_help()
            sys.exit(1)

        if cert_file:
            cert_data = subsystem_cert.get('data', None)
            if cert_data is None:
                print("ERROR: Unable to find certificate data for %s" % cert_id)
                sys.exit(1)

            cert_data = pki.nssdb.convert_cert(cert_data, 'base64', 'pem')
            with open(cert_file, 'w') as f:
                f.write(cert_data)

        if csr_file:
            cert_request = subsystem_cert.get('request', None)
            if cert_request is None:
                print("ERROR: Unable to find certificate request for %s" % cert_id)
                sys.exit(1)

            csr_data = pki.nssdb.convert_csr(cert_request, 'base64', 'pem')
            with open(csr_file, 'w') as f:
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
                    include_chain=include_chain,
                    debug=debug)

            finally:
                nssdb.close()


class SubsystemCertUpdateCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemCertUpdateCLI, self).__init__(
            'update', 'Update subsystem certificate')

    def usage(self):
        print('Usage: pki-server subsystem-cert-update [OPTIONS] <subsystem ID> <cert ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

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

        if len(args) < 1:
            print('ERROR: missing subsystem ID')
            self.usage()
            sys.exit(1)

        if len(args) < 2:
            print('ERROR: missing cert ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]
        cert_id = args[1]

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            print('ERROR: No %s subsystem in instance '
                  '%s.' % (subsystem_name, instance_name))
            sys.exit(1)
        subsystem_cert = subsystem.get_subsystem_cert(cert_id)

        # get cert data from NSS database
        nss.nss_init(instance.nssdb_dir)
        nss_cert = nss.find_cert_from_nickname(subsystem_cert['nickname'])
        data = base64.b64encode(nss_cert.der_data)
        del nss_cert
        nss.nss_shutdown()
        subsystem_cert['data'] = data

        # format cert data for LDAP database
        lines = [data[i:i + 64] for i in range(0, len(data), 64)]
        data = string.join(lines, '\r\n') + '\r\n'

        # get cert request from local CA
        # TODO: add support for remote CA
        ca = instance.get_subsystem('ca')
        if not ca:
            print('ERROR: No CA subsystem in instance %s.' % instance_name)
            sys.exit(1)
        results = ca.find_cert_requests(cert=data)
        cert_request = results[-1]
        request = cert_request['request']

        # format cert request for CS.cfg
        lines = request.splitlines()
        if lines[0] == '-----BEGIN CERTIFICATE REQUEST-----':
            lines = lines[1:]
        if lines[-1] == '-----END CERTIFICATE REQUEST-----':
            lines = lines[:-1]
        request = string.join(lines, '')
        subsystem_cert['request'] = request

        # store cert data and request in CS.cfg
        subsystem.update_subsystem_cert(subsystem_cert)
        subsystem.save()

        self.print_message('Updated "%s" subsystem certificate' % cert_id)


class SubsystemCertValidateCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemCertValidateCLI, self).__init__(
            'validate', 'Validate subsystem certificates')

    def usage(self):
        print('Usage: pki-server subsystem-cert-validate [OPTIONS] <subsystem ID> [<cert_id>]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

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
                self.print_message('ERROR: unknown option ' + o)
                self.usage()
                sys.exit(1)

        if len(args) < 1:
            print('ERROR: missing subsystem ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]

        if len(args) >= 2:
            cert_id = args[1]
        else:
            cert_id = None

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            print('ERROR: No %s subsystem in instance '
                  '%s.' % (subsystem_name, instance_name))
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

            certs_valid &= self.validate_certificate(instance, cert)

        if certs_valid:
            self.print_message("Validation succeeded")
            sys.exit(0)
        else:
            self.print_message("Validation failed")
            sys.exit(1)

    def validate_certificate(self, instance, cert):

        if self.verbose:
            print(cert)

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
            print('  Status: ERROR: missing token name')
            return False

        print('  Token: %s' % token)

        if token and token.lower() in ['internal', 'internal key storage token']:
            token = None

        # get token password and store in temporary file
        passwd = instance.get_token_password(token)

        pwfile_handle, pwfile_path = mkstemp()
        os.write(pwfile_handle, passwd)
        os.close(pwfile_handle)

        try:
            cmd = ['pki',
                   '-d', instance.nssdb_dir,
                   '-C', pwfile_path]

            if token:
                cmd.extend(['--token', token])

            cmd.extend(['client-cert-validate',
                        nickname,
                        '--certusage', usage
                       ])

            subprocess.check_output(cmd, stderr=subprocess.STDOUT)
            print('  Status: VALID')

            return True

        except subprocess.CalledProcessError as e:
            if e.returncode == 1:
                print('  Status: INVALID')
            else:
                print('  Status: ERROR: %s' % e.output)
            return False

        finally:
            os.unlink(pwfile_path)
