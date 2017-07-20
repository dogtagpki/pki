# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
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
# Copyright (C) 2015-2017 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function

import getopt
import sys

import pki.cli
import pki.server as server
import pki.cert


class CertCLI(pki.cli.CLI):
    def __init__(self):
        super(CertCLI, self).__init__('cert',
                                      'System certificate management commands')
        self.add_module(CertFindCLI())
        self.add_module(CertUpdateCLI())

    @staticmethod
    def print_system_cert(cert, show_all=False):
        print('  Cert ID: %s' % cert['id'])
        print('  Nickname: %s' % cert['nickname'])
        print('  Token: %s' % cert['token'])

        if show_all:
            print('  Certificate: %s' % cert['data'])
            print('  Request: %s' % cert['request'])


class CertFindCLI(pki.cli.CLI):

    def __init__(self):
        super(CertFindCLI, self).__init__(
            'find', 'Find system certificates.')

    def print_help(self):
        print('Usage: pki-server cert-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --show-all                  Show all attributes.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
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

        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()
        results = []

        for subsystem_name in instance.subsystems:
            subsystem = instance.get_subsystem(subsystem_name.name)
            # Store the subsystem's system certificate
            sub_system_certs = subsystem.find_system_certs()
            # Iterate on all subsystem's system certificate to prepend subsystem name to the ID
            for subsystem_cert in sub_system_certs:
                if subsystem_cert['id'] != 'sslserver' and subsystem_cert['id'] != 'subsystem':
                    subsystem_cert['id'] = subsystem_name.name + '_' + subsystem_cert['id']
                # Append only unique certificates to other subsystem certificate list
                if subsystem_cert not in results:
                    results.append(subsystem_cert)

        self.print_message('%s entries matched' % len(results))

        first = True
        for cert in results:
            if first:
                first = False
            else:
                print()

            CertCLI.print_system_cert(cert, show_all)


class CertUpdateCLI(pki.cli.CLI):
    def __init__(self):
        super(CertUpdateCLI, self).__init__(
            'update', 'Update system certificate')

    def usage(self):
        print('Usage: pki-server cert-update [OPTIONS] <cert ID>')
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
            print('ERROR: missing cert ID')
            self.usage()
            sys.exit(1)

        cert_id = args[0]

        instance = server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        # If the cert is instance specific, get it from ca
        subsystem_name = 'ca'

        if cert_id != 'sslserver' and cert_id != 'subsystem':
            # To avoid ambiguity where cert ID can contain more than 1 _, we limit to one split
            temp_cert_identify = cert_id.split('_', 1)
            subsystem_name = temp_cert_identify[0]
            cert_id = temp_cert_identify[1]

        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            print('ERROR: No %s subsystem in instance '
                  '%s.' % (subsystem_name, instance_name))
            sys.exit(1)
        subsystem_cert = subsystem.get_subsystem_cert(cert_id)

        if self.verbose:
            print('Retrieving certificate %s from %s' %
                  (subsystem_cert['nickname'], subsystem_cert['token']))

        token = subsystem_cert['token']
        nssdb = instance.open_nssdb(token)

        # Get the cert data from NSS DB
        data = nssdb.get_cert(
            nickname=subsystem_cert['nickname'],
            output_format='base64')
        subsystem_cert['data'] = data

        # format cert data for LDAP database
        lines = [data[i:i + 64] for i in range(0, len(data), 64)]
        data = '\r\n'.join(lines) + '\r\n'

        # Get the cert request from LDAP database
        if self.verbose:
            print('Retrieving certificate request from CA database')

        # TODO: add support for remote CA
        ca = instance.get_subsystem('ca')
        if not ca:
            print('ERROR: No CA subsystem in instance %s.' % instance_name)
            sys.exit(1)

        results = ca.find_cert_requests(cert=data)

        if results:
            cert_request = results[-1]
            request = cert_request['request']

            # format cert request for CS.cfg
            lines = request.splitlines()
            if lines[0] == '-----BEGIN CERTIFICATE REQUEST-----':
                lines = lines[1:]
            if lines[-1] == '-----END CERTIFICATE REQUEST-----':
                lines = lines[:-1]
            request = ''.join(lines)
            subsystem_cert['request'] = request

        else:
            print('WARNING: Certificate request not found')

        # store cert data and request in CS.cfg
        if cert_id == 'sslserver' or cert_id == 'subsystem':
            # Update for all subsystems
            for subsystem in instance.subsystems:
                subsystem.update_subsystem_cert(subsystem_cert)
        else:
            subsystem.update_subsystem_cert(subsystem_cert)

        subsystem.save()

        self.print_message('Updated "%s" system certificate' % cert_id)
