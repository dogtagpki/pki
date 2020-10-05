#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Common functions for pkispawn
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   The following functions are defined:
#   Enabling nuxwdog
#   pkidestroy when nuxwdog enabled
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Roshni Pattath <rpattath@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2016 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import logging
import sys
import re

log = logging.getLogger()
logging.basicConfig(stream=sys.stdout, level=logging.INFO)


class NuxwdogOperations(object):
    def __init__(self, ansible_module, **kwargs):
        self.subsystem_type = kwargs.get('subsystem_type', 'CA')
        self.subsystem_name = kwargs.get('subsystem_name', 'pki-tomcat')
        self.pki_user = kwargs.get('pki_user', 'pkiuser')
        self.ansible_module = ansible_module
        self.password = {}
        self.password_conf = kwargs.get('password_conf', '/var/lib/pki/{}/conf/password.conf')
        password_conf = self.password_conf.format(self.subsystem_name)
        file_stat = ansible_module.stat(path=password_conf)
        for result1 in file_stat.values():
            if result1['stat']['exists']:
                output = ansible_module.shell("cat {}".format(password_conf))
                for result in output.values():
                    [self.password.update({i.split("=")[0]: i.split("=")[1]})
                     for i in result['stdout'].split("\n")]
            else:
                output = ansible_module.shell("cat /tmp/{}-password.conf".format(self.subsystem_type))
                for result in output.values():
                    [self.password.update({i.split("=")[0]: i.split("=")[1]})
                     for i in result['stdout'].split("\n")]

    def _validate_nuxwdog_non_pkiuser(self):
        """
        The method validates that nuxwdog is enabled for non pkiuser owned instances
        The test steps applicable for test_bug_1523410_1534030_non_pkiuser_owned_instances tests.
        """

        output = self.ansible_module.shell("grep {} /var/lib/pki/{}/conf/nuxwdog.conf".format(self.pki_user,
                                                                                              self.subsystem_name))
        for result in output.values():
            assert self.pki_user in result['stdout']

    def enable_nuxwdog(self):
        """
        This method enable the nuxwdog for pki instance.
        """
        stop_subsysem = 'systemctl stop pki-tomcatd@{}'.format(self.subsystem_name)
        enable_nuxwdog = 'pki-server instance-nuxwdog-enable {}'.format(self.subsystem_name)

        stop_sub_out = self.ansible_module.shell(stop_subsysem)
        for result in stop_sub_out.values():
            assert result['rc'] == 0
            log.info("Stopped subsystem {}".format(self.subsystem_name))

        nuxwdog_enable_out = self.ansible_module.shell(enable_nuxwdog)
        for result in nuxwdog_enable_out.values():
            assert result['rc'] == 0
            assert "Nuxwdog enabled for instance {}".format(self.subsystem_name) in result['stdout']
            log.info("Nuxwdog enabled for instance {}".format(self.subsystem_name))

        if self.pki_user != 'pkiuser':
            self._validate_nuxwdog_non_pkiuser()

        self.ansible_module.shell("mv /var/lib/pki/{}/conf/password.conf "
                                  "/tmp/{}-password.conf".format(self.subsystem_name, self.subsystem_type))

        if 'TPS' != self.subsystem_type.upper():
            enabled = self.ansible_module.expect(
                command='systemctl start pki-tomcatd-nuxwdog@{}'.format(self.subsystem_name),
                responses={'\[{}\] Please provide the password for internal: '.format(self.subsystem_name):
                               self.password['internal'],
                           '\[{}\] Please provide the password for internaldb: '.format(self.subsystem_name):
                               self.password['internaldb'],
                           '\[{}\] Please provide the password for replicationdb:'.format(self.subsystem_name):
                               self.password['replicationdb']})
            for result in enabled.values():
                assert result['rc'] == 0
                log.info("Instance {} successfully started with nuxwdog".format(self.subsystem_name))

        else:
            enabled = self.ansible_module.expect(
                command='systemctl start pki-tomcatd-nuxwdog@{}'.format(self.subsystem_name),
                responses={
                    '\[{}\] Please provide the password for internal: '.format(self.subsystem_name):
                        self.password['internal'],
                    '\[{}\] Please provide the password for internaldb: '.format(self.subsystem_name):
                        self.password['internaldb']})
            for result in enabled.values():
                assert result['rc'] == 0
                log.info("Instance {} successfully started with nuxwdog".format(self.subsystem_name))

    def disable_nuxwdog(self):
        """
        This method disable the nuxwdog for pki instance.
        """
        stop_subsysem = 'systemctl stop pki-tomcatd-nuxwdog@{}'.format(self.subsystem_name)
        disable_nuxwdog = 'pki-server instance-nuxwdog-disable {}'.format(self.subsystem_name)

        stop_sub_out = self.ansible_module.shell(stop_subsysem)
        for result in stop_sub_out.values():
            assert result['rc'] == 0
            log.info("Stopped subsystem {}".format(self.subsystem_name))

        nuxwdog_disable_out = self.ansible_module.shell(disable_nuxwdog)
        for result in nuxwdog_disable_out.values():
            assert result['rc'] == 0
            assert "Nuxwdog disabled for instance {}".format(self.subsystem_name) in result['stdout']
            log.info("Nuxwdog disabled for instance {}".format(self.subsystem_name))

        self.ansible_module.shell("mv /tmp/{}-password.conf /var/lib/pki/{}/conf/password.conf "
                                  .format(self.subsystem_type, self.subsystem_name))

        self.ansible_module.shell("chown {}:{} /var/lib/pki/{}/conf/password.conf "
                                  .format(self.pki_user, self.pki_user, self.subsystem_name))
        start_subsystem = 'systemctl start pki-tomcatd@{}'.format(self.subsystem_name)
        start_sub_out = self.ansible_module.shell(start_subsystem)
        for result in start_sub_out.values():
            assert result['rc'] == 0
            log.info("Started subsystem {}".format(self.subsystem_name))

    def pkidestroy_nuxwdog(self):
        output = self.ansible_module.expect(
            command='pkidestroy -s {} -i {}'.format(self.subsystem_type, self.subsystem_name),
            responses={"Password for token internal: ": self.password['internal']})
        for result in output.values():
            assert "Uninstallation complete." in result['stdout']
            log.info("Subsystem {} uninstalled successfully".format(self.subsystem_name))

    def pkiserver_nuxwdog(self):
        """
        This method validates the pki-server status command for nuxwdog enabled instance
        """
        output = self.ansible_module.shell('pki-server status {}'.format(self.subsystem_name))
        for result in output.values():
            assert re.search("Instance ID:\s+{}".format(self.subsystem_name), result['stdout'])
            assert re.search("Active:\s+True", result['stdout'])
            assert re.search("Enabled:\s+True", result['stdout'])
            # Todo : RHEL 8.4 https://bugzilla.redhat.com/show_bug.cgi?id=1732981#c10
            #  https://github.com/dogtagpki/pki/pull/515
            # assert re.search("Nuxwdog Enabled:\s+True", result['stdout'])
        log.info("pki-server status command success")
