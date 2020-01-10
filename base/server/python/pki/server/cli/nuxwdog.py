# Authors:
#     Ade Lee <alee@redhat.com>
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
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function

import fileinput
import getopt
import logging
import os
import re
import subprocess
import sys

import pki.server
from lxml import etree

import pki.cli
import pki.server.instance

logger = logging.getLogger(__name__)


class NuxwdogCLI(pki.cli.CLI):

    def __init__(self):
        super(NuxwdogCLI, self).__init__(
            'nuxwdog',
            'Nuxwdog related commands')
        self.add_module(NuxwdogEnableCLI())
        self.add_module(NuxwdogDisableCLI())


class NuxwdogEnableCLI(pki.cli.CLI):

    def __init__(self):
        self.parser = etree.XMLParser(remove_blank_text=True)
        self.nuxwdog_listener_class = (
            'com.netscape.cms.tomcat.PKIListener'
        )
        self.nuxwdog_pwstore_class = (
            'com.netscape.cms.tomcat.NuxwdogPasswordStore'
        )
        super(NuxwdogEnableCLI, self).__init__(
            'enable',
            'Enable nuxwdog')

    def print_help(self):
        print('Usage: pki-server nuxwdog-enable [OPTIONS]')
        print()
        print('  -v, --verbose                Run in verbose mode.')
        print('      --debug                  Run in debug mode.')
        print('      --help                   Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        for o, _ in opts:
            if o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        instances = pki.server.instance.PKIInstance.instances()

        for instance in instances:
            self.enable_nuxwdog(instance)

        self.print_message('Nuxwdog enabled for system.')

    def enable_nuxwdog(self, instance):

        # modify sysconfig file
        self.enable_nuxwdog_sysconfig_file(instance)

        # modify server.xml
        server_xml = os.path.join(instance.conf_dir, 'server.xml')
        self.enable_nuxwdog_server_xml(server_xml, instance)

        # change systemd links
        self.change_systemd_links(instance)

        # modify CS.cfg
        self.modify_password_class_in_cs_cfg(instance)

    def enable_nuxwdog_sysconfig_file(self, instance):
        sysconfig_file = os.path.join('/etc/sysconfig', instance.name)

        got_use_nuxwdog = False

        for line in fileinput.input(sysconfig_file, inplace=1):

            match = re.search("^USE_NUXWDOG=.*", line)
            if match:
                line = "USE_NUXWDOG=\"true\"\n"
                got_use_nuxwdog = True

            print(line, end='')

        if not got_use_nuxwdog:
            with open(sysconfig_file, 'a') as f:
                f.write("USE_NUXWDOG=\"true\"\n")

        os.chown(sysconfig_file, instance.uid, instance.gid)

    def get_conf_file(self, instance):
        # return the path to the first instance
        subsystem = instance.subsystems[0]
        return os.path.join(subsystem.conf_dir, 'CS.cfg')

    def enable_nuxwdog_server_xml(self, filename, instance):
        logger.info('Enabling nuxwdog in %s', filename)

        conf_file = self.get_conf_file(instance)

        document = etree.parse(filename, self.parser)

        server = document.getroot()

        global_naming_resources = None

        nuxwdog_listener = etree.Element('Listener')
        nuxwdog_listener.set('className', self.nuxwdog_listener_class)

        children = list(server)
        for child in children:

            if child.tag == 'Listener':
                class_name = child.get('className')
                if class_name == self.nuxwdog_listener_class:
                    nuxwdog_listener = None
            elif child.tag == 'GlobalNamingResources':
                global_naming_resources = child

        # add before GlobalResourcesLifecycleListener if exists
        if global_naming_resources is not None:
            index = list(server).index(global_naming_resources) - 1
        else:
            index = 0

        if nuxwdog_listener is not None:
            server.insert(index, nuxwdog_listener)

        connectors = server.findall('Service/Connector')
        for connector in connectors:
            if connector.get('secure') == 'true':
                connector.set('passwordClass', self.nuxwdog_pwstore_class)
                connector.set('passwordFile', conf_file)

        with open(filename, 'wb') as f:
            # xml as UTF-8 encoded bytes
            document.write(f, pretty_print=True, encoding='utf-8')

        os.chown(filename, instance.uid, instance.gid)

    def change_systemd_links(self, instance):
        old_systemd_unit_file = 'pki-tomcatd@' + instance.name + '.service'
        old_systemd_link = os.path.join(
            '/etc/systemd/system/pki-tomcatd.target.wants',
            old_systemd_unit_file)

        new_systemd_unit_file = 'pki-tomcatd-nuxwdog@%s.service' % instance.name
        new_systemd_link = os.path.join(
            '/etc/systemd/system/pki-tomcatd-nuxwdog.target.wants',
            new_systemd_unit_file)
        new_systemd_source = '/lib/systemd/system/pki-tomcatd-nuxwdog@.service'

        if os.path.exists(old_systemd_link):
            os.unlink(old_systemd_link)

        if os.path.exists(new_systemd_link):
            os.unlink(new_systemd_link)
        os.symlink(new_systemd_source, new_systemd_link)

        subprocess.check_call(['systemctl', 'daemon-reload'])

    def modify_password_class_in_cs_cfg(self, instance):
        pclass = "com.netscape.cmsutil.password.NuxwdogPasswordStore"

        for subsystem in instance.subsystems:
            cs_cfg = os.path.join(subsystem.conf_dir, 'CS.cfg')
            for line in fileinput.input(cs_cfg, inplace=1):
                match = re.search("^passwordClass=(.*)", line)
                if match:
                    line = "passwordClass=" + pclass + "\n"
                print(line, end='')
            os.chown(cs_cfg, instance.uid, instance.gid)


class NuxwdogDisableCLI(pki.cli.CLI):

    def __init__(self):
        self.parser = etree.XMLParser(remove_blank_text=True)
        self.nuxwdog_listener_class = (
            'com.netscape.cms.tomcat.PKIListener'
        )
        self.plain_pwstore_class = (
            'org.apache.tomcat.util.net.jss.PlainPasswordFile'
        )
        super(NuxwdogDisableCLI, self).__init__(
            'disable',
            'Disable nuxwdog')

    def print_help(self):
        print('Usage: pki-server nuxwdog-disable [OPTIONS]')
        print()
        print('  -v, --verbose                Run in verbose mode.')
        print('      --debug                  Run in debug mode.')
        print('      --help                   Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        for o, _ in opts:
            if o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        instances = pki.server.instance.PKIInstance.instances()

        for instance in instances:
            self.disable_nuxwdog(instance)

        self.print_message('Nuxwdog disabled for system.')

    def disable_nuxwdog(self, instance):
        self.disable_nuxwdog_sysconfig_file(instance)

        server_xml = os.path.join(instance.conf_dir, 'server.xml')
        self.disable_nuxwdog_server_xml(server_xml, instance)

        self.change_systemd_links(instance)

        self.modify_password_class_in_cs_cfg(instance)

    def disable_nuxwdog_sysconfig_file(self, instance):
        sysconfig_file = os.path.join('/etc/sysconfig', instance.name)

        for line in fileinput.input(sysconfig_file, inplace=1):

            match = re.search("^USE_NUXWDOG=.*", line)
            if match:
                line = "USE_NUXWDOG=\"false\"\n"

            print(line, end='')

        os.chown(sysconfig_file, instance.uid, instance.gid)

    def disable_nuxwdog_server_xml(self, filename, instance):
        logger.info('Disabling nuxwdog in %s', filename)

        pw_conf = os.path.join(instance.conf_dir, 'password.conf')

        document = etree.parse(filename, self.parser)

        server = document.getroot()

        connectors = server.findall('Service/Connector')
        for connector in connectors:
            if connector.get('secure') == 'true':
                connector.set('passwordClass', self.plain_pwstore_class)
                connector.set('passwordFile', pw_conf)

        with open(filename, 'wb') as f:
            # xml as UTF-8 encoded bytes
            document.write(f, pretty_print=True, encoding='utf-8')

        os.chown(filename, instance.uid, instance.gid)

    def change_systemd_links(self, instance):
        old_systemd_unit_file = 'pki-tomcatd-nuxwdog@%s.service' % instance.name
        old_systemd_link = os.path.join(
            '/etc/systemd/system/pki-tomcatd-nuxwdog.target.wants',
            old_systemd_unit_file)

        new_systemd_unit_file = 'pki-tomcatd@' + instance.name + '.service'
        new_systemd_link = os.path.join(
            '/etc/systemd/system/pki-tomcatd.target.wants',
            new_systemd_unit_file)
        new_systemd_source = '/lib/systemd/system/pki-tomcatd@.service'

        if os.path.exists(old_systemd_link):
            os.unlink(old_systemd_link)

        if os.path.exists(new_systemd_link):
            os.unlink(new_systemd_link)
        os.symlink(new_systemd_source, new_systemd_link)

        subprocess.check_call(['systemctl', 'daemon-reload'])

    def modify_password_class_in_cs_cfg(self, instance):
        pclass = "com.netscape.cmsutil.password.PlainPasswordFile"

        for subsystem in instance.subsystems:
            cs_cfg = os.path.join(subsystem.conf_dir, 'CS.cfg')
            for line in fileinput.input(cs_cfg, inplace=1):
                match = re.search("^passwordClass=(.*)", line)
                if match:
                    line = "passwordClass=" + pclass + "\n"
                print(line, end='')
                os.chown(cs_cfg, instance.uid, instance.gid)
