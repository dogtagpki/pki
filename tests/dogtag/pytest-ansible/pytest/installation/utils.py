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
import os
import random
import re
import ConfigParser

class NuxwdogOperations(object):
    def __init__(self, **kwargs):
        self.subsystem_type = kwargs.get('subsystem_type', 'CA')
        self.subsystem_name = kwargs.get('subsystem_name', 'pki-tomcat')
        self.pki_user = kwargs.get('pki_user', 'pkiuser')

    def enable_nuxwdog(self, ansible_module):

        ansible_module.shell("systemctl stop pki-tomcatd@%s" % self.subsystem_name)
        ansible_module.shell("pki-server instance-nuxwdog-enable %s" % self.subsystem_name)
        output = ansible_module.shell("cat /var/lib/pki/%s/conf/nuxwdog.conf | grep %s" % (self.subsystem_name, self.pki_user))
        for result in output.values():
          assert "%s" % self.pki_user in result['stdout']
        ansible_module.shell("mv /var/lib/pki/%s/conf/password.conf /tmp/%s-password.conf" % (self.subsystem_name, self.subsystem_type))
        password = {}
        output = ansible_module.shell("cat /tmp/%s-password.conf" % self.subsystem_type)
        for result in output.values():
            [password.update({i.split("=")[0]: i.split("=")[1]}) for i in result['stdout'].split("\n")]
        if 'TPS' not in self.subsystem_type:
            ansible_module.expect(command='systemctl start pki-tomcatd-nuxwdog@%s' % self.subsystem_name, responses={
                '\[%s\] Please provide the password for internal:' % self.subsystem_name: '%s' % password['internal'],
                '\[%s\] Please provide the password for internaldb:' % self.subsystem_name: '%s' % password['internaldb'],
                '\[%s\] Please provide the password for replicationdb:' % self.subsystem_name: '%s' % password['replicationdb']})
        else:
            ansible_module.expect(command='systemctl start pki-tomcatd-nuxwdog@%s' % self.subsystem_name, responses={
                '\[%s\] Please provide the password for internal:' % self.subsystem_name: '%s' % password['internal'],
                '\[%s\] Please provide the password for internaldb:' % self.subsystem_name: '%s' % password['internaldb']})

    def pkidestroy_nuxwdog(self, ansible_module):
        output = ansible_module.shell('cat /tmp/%s-password.conf | grep internal= | cut -d \'=\' -f 2'
                                      % self.subsystem_type)
        for result in output.values():
            internal = result['stdout']
        output = ansible_module.expect(command='pkidestroy -s %s -i %s' % (self.subsystem_type, self.subsystem_name),
                                       responses={"Password for token internal:": "%s" % internal})
        for result in output.values():
            assert "Uninstallation complete." in result['stdout']


class Config:

    def default(self,conf,**kwargs):
            if kwargs.keys() is not None:
                config = ConfigParser.RawConfigParser()
                config.optionxform = str
                for key in kwargs.keys():
                    config.set('DEFAULT', key, kwargs[key])
                with open(conf, 'w') as f:
                    config.write(f)

    def subsystem(self, conf, subsystem,**kwargs):
            if kwargs.keys() is not None:
                config = ConfigParser.RawConfigParser()
                config.optionxform = str
                config.add_section('{}'.format(subsystem))

                for key in kwargs.keys():
                    config.set('{}'.format(subsystem), key, kwargs[key])
                with open(conf, 'a') as f:
                    config.write(f)

