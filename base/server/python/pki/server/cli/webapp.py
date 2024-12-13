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

import argparse
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

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')

    def print_help(self):
        print('Usage: pki-server webapp-find [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance

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

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')
        self.parser.add_argument('webapp_id')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help))

    def execute(self, argv):

        args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        webapp_id = args.webapp_id

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

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--descriptor')
        self.parser.add_argument('--doc-base')
        self.parser.add_argument(
            '--wait',
            action='store_true')
        self.parser.add_argument(
            '--max-wait',
            type=int,
            default=60)
        self.parser.add_argument(
            '--timeout',
            type=int)
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')
        self.parser.add_argument('webapp_id')

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

        args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        descriptor = args.descriptor
        doc_base = args.doc_base
        wait = args.wait
        max_wait = args.max_wait
        timeout = args.timeout
        webapp_id = args.webapp_id

        instance = pki.server.PKIServerFactory.create(instance_name)

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

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--wait',
            action='store_true')
        self.parser.add_argument(
            '--max-wait',
            type=int,
            default=60)
        self.parser.add_argument(
            '--timeout',
            type=int)
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')
        self.parser.add_argument('webapp_id')

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

        args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        wait = args.wait
        max_wait = args.max_wait
        timeout = args.timeout
        webapp_id = args.webapp_id

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.undeploy_webapp(
            webapp_id,
            wait=wait,
            max_wait=max_wait,
            timeout=timeout)
