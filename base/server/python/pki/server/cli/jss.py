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

        self.add_module(JSSInstallCLI())
        self.add_module(JSSUninstallCLI())

        self.add_module(JSSEnableCLI())
        self.add_module(JSSDisableCLI())


class JSSInstallCLI(pki.cli.CLI):

    def __init__(self):
        super(JSSInstallCLI, self).__init__(
            'install', 'Install JSS library in PKI server')

    def print_help(self):
        print('Usage: pki-server jss-install [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --force                        Force installation.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'force',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        force = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--force':
                force = True

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

        instance.symlink(
            '/usr/share/java/commons-lang.jar',
            os.path.join(instance.lib_dir, 'commons-lang.jar'),
            force)

        instance.symlink(
            '/usr/share/java/commons-codec.jar',
            os.path.join(instance.lib_dir, 'commons-codec.jar'),
            force)

        instance.symlink(
            '/usr/share/java/slf4j/slf4j-api.jar',
            os.path.join(instance.lib_dir, 'slf4j-api.jar'),
            force)

        instance.symlink(
            '/usr/share/java/slf4j/slf4j-jdk14.jar',
            os.path.join(instance.lib_dir, 'slf4j-jdk14.jar'),
            force)

        instance.symlink(
            '/usr/share/java/jaxb-api.jar',
            os.path.join(instance.lib_dir, 'jaxb-api.jar'),
            force)

        instance.symlink(
            '/usr/lib/java/jss4.jar',
            os.path.join(instance.lib_dir, 'jss4.jar'),
            force)

        instance.symlink(
            '/usr/share/java/tomcatjss.jar',
            os.path.join(instance.lib_dir, 'tomcatjss.jar'),
            force)


class JSSUninstallCLI(pki.cli.CLI):

    def __init__(self):
        super(JSSUninstallCLI, self).__init__(
            'uninstall', 'Uninstall JSS library in PKI server')

    def print_help(self):
        print('Usage: pki-server jss-uninstall [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --force                        Force uninstallation.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'force',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        force = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--force':
                force = True

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

        pki.util.unlink(os.path.join(instance.lib_dir, 'tomcatjss.jar'), force)
        pki.util.unlink(os.path.join(instance.lib_dir, 'jss4.jar'), force)
        pki.util.unlink(os.path.join(instance.lib_dir, 'jaxb-api.jar'), force)
        pki.util.unlink(os.path.join(instance.lib_dir, 'slf4j-jdk14.jar'), force)
        pki.util.unlink(os.path.join(instance.lib_dir, 'slf4j-api.jar'), force)
        pki.util.unlink(os.path.join(instance.lib_dir, 'commons-codec.jar'), force)
        pki.util.unlink(os.path.join(instance.lib_dir, 'commons-lang.jar'), force)


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
