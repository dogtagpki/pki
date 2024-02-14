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
import inspect
import logging
import sys
import textwrap

import pki.cli
import pki.server

logger = logging.getLogger(__name__)


class WebappCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('webapp', 'Webapp management commands')

        self.add_module(WebappFindCLI())
        self.add_module(WebappShowCLI())
        self.add_module(WebappDeployCLI())
        self.add_module(WebappUndeployCLI())

    @staticmethod
    def print_webapp(webapp):

        print('  Webapp ID: %s' % webapp['id'])
        print('  Path: %s' % webapp['path'])

        if 'version' in webapp:
            print('  Version: %s' % webapp['version'])

        print('  Descriptor: %s' % webapp['descriptor'])
        print('  Document Base: %s' % webapp['docBase'])


class WebappFindCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('find', 'Find webapps')

    def print_help(self):
        print('Usage: pki-server webapp-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
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
                print('ERROR: Unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        if len(args) > 0:
            instance_name = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        webapps = instance.get_webapps()
        first = True

        for webapp in webapps:
            if first:
                first = False
            else:
                print()

            WebappCLI.print_webapp(webapp)


class WebappShowCLI(pki.cli.CLI):
    '''
    Show webapp
    '''

    help = '''\
        Usage: pki-server webapp-show [OPTIONS] <webapp ID>

          -i, --instance <instance ID>    Instance ID (default: pki-tomcat).
          -v, --verbose                   Run in verbose mode.
              --debug                     Run in debug mode.
              --help                      Show help message.
    '''  # noqa: E501

    def __init__(self):
        super().__init__('show', inspect.cleandoc(self.__class__.__doc__))

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
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
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing webapp ID')
            self.print_help()
            sys.exit(1)

        webapp_id = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        webapp = instance.get_webapp(webapp_id)

        if not webapp:
            logger.error('No such webapp: %s', webapp_id)
            sys.exit(1)

        WebappCLI.print_webapp(webapp)


class WebappDeployCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('deploy', 'Deploy webapp')

    def print_help(self):
        print('Usage: pki-server webapp-deploy [OPTIONS] <webapp ID>')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --descriptor <path>         Path to webapp descriptor')
        print('      --doc-base <path>           Document base')
        print('      --wait                      Wait until started.')
        print('      --max-wait <seconds>        Maximum wait time (default: 60)')
        print('      --timeout <seconds>         Connection timeout')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'wait', 'max-wait=', 'timeout=',
                'descriptor=', 'doc-base=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        descriptor = None
        doc_base = None
        wait = False
        max_wait = 60
        timeout = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--descriptor':
                descriptor = a

            elif o == '--doc-base':
                doc_base = a

            elif o == '--wait':
                wait = True

            elif o == '--max-wait':
                max_wait = int(a)

            elif o == '--timeout':
                timeout = int(a)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: Unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            raise Exception('Missing Webapp ID')

        instance = pki.server.PKIServerFactory.create(instance_name)

        webapp_id = args[0]

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.deploy_webapp(
            webapp_id,
            descriptor,
            doc_base,
            wait=wait,
            max_wait=max_wait,
            timeout=timeout)


class WebappUndeployCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('undeploy', 'Undeploy webapp')

    def print_help(self):
        print('Usage: pki-server webapp-undeploy [OPTIONS] [<webapp ID>]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --wait                      Wait until stopped.')
        print('      --max-wait <seconds>        Maximum wait time (default: 60)')
        print('      --timeout <seconds>         Connection timeout')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'wait', 'max-wait=', 'timeout=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: %s' % e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        wait = False
        max_wait = 60
        timeout = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--wait':
                wait = True

            elif o == '--max-wait':
                max_wait = int(a)

            elif o == '--timeout':
                timeout = int(a)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: Unknown option: %s' % o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            raise Exception('Missing Webapp ID')

        webapp_id = args[0]

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.undeploy_webapp(
            webapp_id,
            wait=wait,
            max_wait=max_wait,
            timeout=timeout)
