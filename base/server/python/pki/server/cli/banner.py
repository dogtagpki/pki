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
# Copyright (C) 2017 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function

import getopt
import logging
import io
import sys

import pki.cli

logger = logging.getLogger(__name__)


class BannerCLI(pki.cli.CLI):

    def __init__(self):
        super(BannerCLI, self).__init__('banner',
                                        'Banner management commands')

        self.add_module(BannerShowCLI())
        self.add_module(BannerValidateCLI())


class BannerShowCLI(pki.cli.CLI):

    def __init__(self):
        super(BannerShowCLI, self).__init__('show', 'Show banner')

    def usage(self):
        print('Usage: pki-server banner-show [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.usage()
                sys.exit(1)

        instance = pki.server.instance.PKIInstance(instance_name)

        if not instance.is_valid():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        if not instance.banner_installed():
            logger.error('Banner is not installed')
            sys.exit(1)

        print(instance.get_banner())


class BannerValidateCLI(pki.cli.CLI):

    def __init__(self):
        super(BannerValidateCLI, self).__init__('validate', 'Validate banner')

    def usage(self):
        print('Usage: pki-server banner-validate [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --file <path>               Validate specified banner file.')
        print('      --silent                    Run in silent mode.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --debug                     Run in debug mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'file=', 'silent',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        banner_file = None
        silent = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--file':
                banner_file = a

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--silent':
                silent = True

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.usage()
                sys.exit(1)

        try:
            if banner_file:
                # load banner from file
                with io.open(banner_file) as f:
                    banner = f.read().strip()
            else:

                # load banner from instance
                instance = pki.server.instance.PKIInstance(instance_name)

                if not instance.is_valid():
                    logger.error('Invalid instance %s.', instance_name)
                    sys.exit(1)

                instance.load()

                if not instance.banner_installed():
                    if not silent:
                        self.print_message('Banner is not installed')
                    return

                banner = instance.get_banner()

        except UnicodeDecodeError as e:
            if logger.isEnabledFor(logging.DEBUG):
                logger.exception('Banner contains invalid character(s): %s', e)
            else:
                logger.error('Banner contains invalid character(s): %s', e)
            sys.exit(1)

        if not banner:
            logger.error('Banner is empty')
            sys.exit(1)

        if not silent:
            self.print_message('Banner is valid')
