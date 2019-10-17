# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

from __future__ import absolute_import
from __future__ import print_function
import getopt
import logging
import os
import sys

import pki.cli
import pki.server

logger = logging.getLogger(__name__)


class ACMECLI(pki.cli.CLI):

    def __init__(self):
        super(ACMECLI, self).__init__(
            'acme', 'ACME management commands')

        self.add_module(ACMEDeployCLI())
        self.add_module(ACMEUndeployCLI())


class ACMEDeployCLI(pki.cli.CLI):

    def __init__(self):
        super(ACMEDeployCLI, self).__init__(
            'deploy', 'Deploy ACME subsystem')

    def print_help(self):
        print('Usage: pki-server acme-deploy [OPTIONS] [name]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        name = 'acme'
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
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        descriptor = os.path.join(pki.server.PKIServer.SHARE_DIR,
                                  'acme/conf/Catalina/localhost/acme.xml')
        doc_base = os.path.join(pki.server.PKIServer.SHARE_DIR,
                                'acme/webapps/acme')

        logging.info('Deploying %s webapp', name)
        instance.deploy_webapp(name, descriptor, doc_base)


class ACMEUndeployCLI(pki.cli.CLI):

    def __init__(self):
        super(ACMEUndeployCLI, self).__init__(
            'undeploy', 'Undeploy ACME subsystem')

    def print_help(self):
        print('Usage: pki-server acme-undeploy [OPTIONS] [name]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        name = 'acme'
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
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        logging.info('Undeploying %s webapp', name)
        instance.undeploy_webapp(name)
