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
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#

import argparse
import logging

import pki.cli
import pki.upgrade
import pki.server.upgrade

logger = logging.getLogger(__name__)


class UpgradeCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('upgrade', 'Upgrade PKI server')

    def create_parser(self):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--status',
            action='store_true')
        self.parser.add_argument(
            '--revert',
            action='store_true')
        self.parser.add_argument(
            '--validate',
            action='store_true')
        self.parser.add_argument(
            '-X',
            action='store_true')
        self.parser.add_argument(
            '--remove-tracker',
            action='store_true')
        self.parser.add_argument(
            '--reset-tracker',
            action='store_true')
        self.parser.add_argument('--set-tracker')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '-h',
            '--help',
            action='store_true')
        self.parser.add_argument(
            'instance_name',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server upgrade [OPTIONS] [<instance ID>]')
        print()
        print('  --status                       Show upgrade status only. Do not perform upgrade.')
        print('  --revert                       Revert the last version.')
        print('  --validate                     Validate upgrade status.')
        print()
        print('  -i, --instance <instance>      Upgrade a specific instance only.')
        print()
        print('  -X                             Show advanced options.')
        print('  -v, --verbose                  Run in verbose mode.')
        print('      --debug                    Run in debug mode.')
        print('  -h, --help                     Show this help message.')

    def advancedOptions(self):
        print()
        print('WARNING: These options may render the system unusable.')
        print()
        print('  --remove-tracker               Remove tracker.')
        print('  --reset-tracker                Reset tracker to match package version.')
        print('  --set-tracker <version>        Set tracker to a specific version.')

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return
        elif args.X:
            self.advancedOptions()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        if args.instance_name:
            instance_name = args.instance_name
        else:
            instance_name = args.instance

        status = args.status
        revert = args.revert
        validate = args.validate

        remove_tracker = args.remove_tracker
        reset_tracker = args.reset_tracker

        tracker_version = None
        if args.set_tracker:
            tracker_version = pki.util.Version(args.set_tracker)

        if instance_name:
            instance = pki.server.PKIServerFactory.create(instance_name)

            if not instance.exists():
                raise Exception('Invalid instance: %s' % instance_name)

            instance.load()
            instances = [instance]

        else:
            instances = pki.server.instance.PKIInstance.instances()

        for instance in instances:
            self.upgrade(
                instance,
                status,
                revert,
                validate,
                remove_tracker,
                reset_tracker,
                tracker_version)

    def upgrade(self, instance, status, revert, validate,
                remove_tracker, reset_tracker, tracker_version):

        upgrader = pki.server.upgrade.PKIServerUpgrader(instance=instance)

        if status:
            upgrader.status()

        elif revert:
            upgrader.revert()

        elif validate:
            upgrader.validate()

        elif remove_tracker:
            upgrader.remove_tracker()

        elif reset_tracker:
            upgrader.reset_tracker()

        elif tracker_version is not None:
            upgrader.set_tracker(tracker_version)

        else:
            logger.info('Upgrading PKI server %s', instance)
            upgrader.upgrade()
