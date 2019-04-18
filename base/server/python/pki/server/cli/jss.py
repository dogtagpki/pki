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
# Copyright (C) 2019 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function
import getopt
import logging
import os
import sys

import pki.cli


class JSSCLI(pki.cli.CLI):

    def __init__(self):
        super(JSSCLI, self).__init__(
            'jss', 'JSS management commands')

        self.add_module(JSSEnableCLI())
        self.add_module(JSSDisableCLI())


class JSSEnableCLI(pki.cli.CLI):

    def __init__(self):
        super(JSSEnableCLI, self).__init__(
            'enable', 'Enable JSS in PKI server')

    def print_help(self):
        print('Usage: pki-server jss-enable [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            print("ERROR: Invalid instance: %s" % instance_name)
            sys.exit(1)

        jss_config = instance.load_jss_config()

        jss_config['certdbDir'] = instance.nssdb_dir
        jss_config['passwordFile'] = instance.password_conf

        instance.store_jss_config(jss_config)

        server_config = instance.get_server_config()

        listener = server_config.create_listener('org.dogtagpki.tomcat.JSSListener')

        jss_conf = os.path.join(instance.conf_dir, 'jss.conf')
        listener.set('configFile', jss_conf)

        server_config.save()


class JSSDisableCLI(pki.cli.CLI):

    def __init__(self):
        super(JSSDisableCLI, self).__init__(
            'disable', 'Disable JSS in PKI server')

    def print_help(self):
        print('Usage: pki-server jss-disable [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            print("ERROR: Invalid instance: %s" % instance_name)
            sys.exit(1)

        server_config = instance.get_server_config()
        server_config.remove_listener('org.dogtagpki.tomcat.JSSListener')
        server_config.save()
