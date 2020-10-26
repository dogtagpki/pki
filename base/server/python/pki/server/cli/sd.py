#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
from __future__ import print_function
import getopt
import logging
import sys

import pki.cli
import pki.server
import pki.server.instance

logger = logging.getLogger(__name__)


class SDCLI(pki.cli.CLI):

    def __init__(self):
        super(SDCLI, self).__init__(
            'sd', 'Security domain management commands')

        self.add_module(SDHostCLI())


class SDHostCLI(pki.cli.CLI):

    def __init__(self):
        super(SDHostCLI, self).__init__(
            'host', 'Security domain host management commands')

        self.add_module(SDHostAddCLI())


class SDHostAddCLI(pki.cli.CLI):

    def __init__(self):
        super(SDHostAddCLI, self).__init__(
            'add', 'Add security domain host')

    def print_help(self):
        print('Usage: pki-server sd-host-add [OPTIONS] <host ID>')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --hostname <hostname>          Hostname')
        print('      --unsecure-port <port>         Unsecure port (default: 8080)')
        print('      --secure-port <port>           Secure port (default: 8443)')
        print('      --domain-manager               Domain manager')
        print('      --clone                        Clone')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'hostname=', 'unsecure-port=', 'secure-port=',
                'domain-manager', 'clone',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        hostname = None
        unsecure_port = '8080'
        secure_port = '8443'
        domain_manager = False
        clone = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--hostname':
                hostname = a

            elif o == '--unsecure-port':
                unsecure_port = a

            elif o == '--secure-port':
                secure_port = a

            elif o == '--domain-manager':
                domain_manager = True

            elif o == '--clone':
                clone = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing host ID')
            self.print_help()
            sys.exit(1)

        host_id = args[0]

        if not hostname:
            logger.error('Missing hostname')
            self.print_help()
            sys.exit(1)

        instance = pki.server.instance.PKIInstance(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem('ca')
        if not subsystem:
            logger.error('No CA subsystem in instance %s', instance_name)
            sys.exit(1)

        subsystem.add_security_domain_host(
            host_id,
            hostname,
            unsecure_port=unsecure_port,
            secure_port=secure_port,
            domain_manager=domain_manager,
            clone=clone)
