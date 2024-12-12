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

import argparse
import logging
import io
import sys

import pki.cli

logger = logging.getLogger(__name__)


class BannerCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('banner', 'Banner management commands')

        self.add_module(BannerShowCLI())
        self.add_module(BannerValidateCLI())


class BannerShowCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('show', 'Show banner')

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
        print('Usage: pki-server banner-show [OPTIONS]')
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
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        if not instance.banner_installed():
            logger.error('Banner is not installed')
            sys.exit(1)

        print(instance.get_banner())


class BannerValidateCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('validate', 'Validate banner')

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--file')
        self.parser.add_argument(
            '--silent',
            action='store_true')
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

        args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        banner_file = args.file
        silent = args.silent

        try:
            if banner_file:
                # load banner from file
                with io.open(banner_file, encoding='utf-8') as f:
                    banner = f.read().strip()
            else:

                # load banner from instance
                instance = pki.server.PKIServerFactory.create(instance_name)

                if not instance.exists():
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
