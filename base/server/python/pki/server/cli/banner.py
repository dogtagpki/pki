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
import codecs
import getopt
from lxml import etree
import sys
import traceback

import pki.cli


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
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.usage()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)

        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        if not instance.banner_installed():
            print('ERROR: Banner is not installed')
            sys.exit(1)

        banner = instance.get_banner()

        if not banner:
            print('ERROR: Banner is empty')
            sys.exit(1)

        print(banner)


class BannerValidateCLI(pki.cli.CLI):

    def __init__(self):
        super(BannerValidateCLI, self).__init__('validate', 'Validate banner')

    def usage(self):
        print('Usage: pki-server banner-validate [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>    Instance ID (default: pki-tomcat).')
        print('      --file <path>               Validate specified banner file.')
        print('  -v, --verbose                   Run in verbose mode.')
        print('      --help                      Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'file=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.usage()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        banner_file = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--file':
                banner_file = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.usage()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.usage()
                sys.exit(1)

        if banner_file:

            # load banner from file
            banner = codecs.open(banner_file, "UTF-8").read().strip()

        else:

            # load banner from instance
            instance = pki.server.PKIInstance(instance_name)

            if not instance.is_valid():
                print('ERROR: Invalid instance %s.' % instance_name)
                sys.exit(1)

            instance.load()

            if not instance.banner_installed():
                self.print_message('Banner is not installed')
                return

            banner = instance.get_banner()

        if not banner:
            print('ERROR: Banner is empty')
            sys.exit(1)

        xml_banner = "<banner>" + banner + "</banner>"

        try:
            parser = etree.XMLParser()
            etree.fromstring(xml_banner, parser)

            self.print_message('Banner is valid')

        except etree.XMLSyntaxError as e:
            if self.verbose:
                traceback.print_exc()
            print('ERROR: Banner contains invalid character')
            sys.exit(1)
