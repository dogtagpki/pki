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

        self.add_module(ACMECreateCLI())
        self.add_module(ACMERemoveCLI())
        self.add_module(ACMEDeployCLI())
        self.add_module(ACMEUndeployCLI())


class ACMECreateCLI(pki.cli.CLI):

    def __init__(self):
        super(ACMECreateCLI, self).__init__(
            'create', 'Create ACME subsystem')

    def print_help(self):
        print('Usage: pki-server acme-create [OPTIONS] [name]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --force                        Force creation.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'database=', 'backend=',
                'force',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        name = 'acme'
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
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        acme_conf_dir = os.path.join(instance.conf_dir, name)
        logging.info('Creating %s', acme_conf_dir)
        instance.makedirs(acme_conf_dir, force=force)

        acme_share_dir = os.path.join(pki.server.PKIServer.SHARE_DIR, 'acme')

        metadata_template = os.path.join(acme_share_dir, 'conf', 'metadata.json')
        metadata_conf = os.path.join(acme_conf_dir, 'metadata.json')
        logging.info('Creating %s', metadata_conf)
        instance.copy(metadata_template, metadata_conf, force=force)

        database_template = os.path.join(acme_share_dir, 'conf', 'database.json')
        database_conf = os.path.join(acme_conf_dir, 'database.json')
        logging.info('Creating %s', database_conf)
        instance.copy(database_template, database_conf, force=force)

        validators_template = os.path.join(acme_share_dir, 'conf', 'validators.json')
        validators_conf = os.path.join(acme_conf_dir, 'validators.json')
        logging.info('Creating %s', validators_conf)
        instance.copy(validators_template, validators_conf, force=force)

        backend_template = os.path.join(acme_share_dir, 'conf', 'backend.json')
        backend_conf = os.path.join(acme_conf_dir, 'backend.json')
        logging.info('Creating %s', backend_conf)
        instance.copy(backend_template, backend_conf, force=force)


class ACMERemoveCLI(pki.cli.CLI):

    def __init__(self):
        super(ACMERemoveCLI, self).__init__(
            'remove', 'Remove ACME subsystem')

    def print_help(self):
        print('Usage: pki-server acme-remove [OPTIONS] [name]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --force                        Force removal.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'force',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        name = 'acme'
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
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            name = args[0]

        instance = pki.server.instance.PKIServerFactory.create(instance_name)

        if not instance.is_valid():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        acme_conf_dir = os.path.join(instance.conf_dir, name)
        logging.info('Removing %s', acme_conf_dir)
        pki.util.rmtree(acme_conf_dir, force=force)


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
