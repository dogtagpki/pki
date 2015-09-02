#!/usr/bin/python
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
import base64
import getopt
import nss.nss as nss
import string
import sys

import pki.cli
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
            opts, _ = getopt.getopt(args, 'i:v', [
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
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.usage()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        self.print_message('%s entries matched' % len(instance.subsystems))

        first = True
        for subsystem in instance.subsystems:
            if first:
                first = False
            else:
                print

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
            opts, args = getopt.getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        if len(args) != 1:
            print('ERROR: missing subsystem ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]
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

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

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
            opts, args = getopt.getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        if len(args) != 1:
            print('ERROR: missing subsystem ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]
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

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        subsystem.enable()

        self.print_message('Enabled "%s" subsystem' % subsystem_name)

        SubsystemCLI.print_subsystem(subsystem)


class SubsystemDisableCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemDisableCLI, self).__init__('disable', 'Disable subsystem')

    def usage(self):
        print('Usage: pki-server subsystem-disable [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        if len(args) != 1:
            print('ERROR: missing subsystem ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]
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

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        subsystem.disable()

        self.print_message('Disabled "%s" subsystem' % subsystem_name)

        SubsystemCLI.print_subsystem(subsystem)


class SubsystemCertCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemCertCLI, self).__init__(
            'cert', 'Subsystem certificate management commands')

        self.add_module(SubsystemCertFindCLI())
        self.add_module(SubsystemCertShowCLI())
        self.add_module(SubsystemCertUpdateCLI())

    @staticmethod
    def print_subsystem_cert(cert):
        print('  Cert ID: %s' % cert['id'])
        print('  Nickname: %s' % cert['nickname'])
        print('  Token: %s' % cert['token'])
        print('  Certificate: %s' % cert['data'])
        print('  Request: %s' % cert['request'])


class SubsystemCertFindCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemCertFindCLI, self).__init__(
            'find', 'Find subsystem certificates')

    def usage(self):
        print('Usage: pki-server subsystem-cert-find [OPTIONS] <subsystem ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        if len(args) != 1:
            print('ERROR: missing subsystem ID')
            self.usage()
            sys.exit(1)

        subsystem_name = args[0]
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

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        results = subsystem.find_subsystem_certs()

        self.print_message('%s entries matched' % len(results))

        first = True
        for cert in results:
            if first:
                first = False
            else:
                print()

            SubsystemCertCLI.print_subsystem_cert(cert)


class SubsystemCertShowCLI(pki.cli.CLI):

    def __init__(self):
        super(SubsystemCertShowCLI, self).__init__(
            'show', 'Show subsystem certificate')

    def usage(self):
        print('Usage: pki-server subsystem-cert-show [OPTIONS] <subsystem ID> <cert ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
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

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        subsystem_cert = subsystem.get_subsystem_cert(cert_id)

        SubsystemCertCLI.print_subsystem_cert(subsystem_cert)


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
            opts, args = getopt.getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
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

        instance = pki.server.PKIInstance(instance_name)
        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)
        subsystem_cert = subsystem.get_subsystem_cert(cert_id)

        # get cert data from NSS database
        nss.nss_init(instance.nssdb_dir)
        nss_cert = nss.find_cert_from_nickname(subsystem_cert['nickname'])
        data = base64.b64encode(nss_cert.der_data)
        del nss_cert
        nss.nss_shutdown()
        subsystem_cert['data'] = data

        # format cert data for LDAP database
        lines = [data[i:i+64] for i in range(0, len(data), 64)]
        data = string.join(lines, '\r\n') + '\r\n'

        # get cert request from local CA
        # TODO: add support for remote CA
        ca = instance.get_subsystem('ca')
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

        SubsystemCertCLI.print_subsystem_cert(subsystem_cert)
