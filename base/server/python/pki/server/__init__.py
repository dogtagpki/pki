#!/usr/bin/python
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

from lxml import etree
import grp
import os
import pwd
import re
import subprocess

import pki

INSTANCE_BASE_DIR = '/var/lib/pki'
REGISTRY_DIR = '/etc/sysconfig/pki'
SUBSYSTEM_TYPES = ['ca', 'kra', 'ocsp', 'tks', 'tps']


class PKIServer(object):

    @classmethod
    def instances(cls):

        instances = []

        if not os.path.exists(os.path.join(REGISTRY_DIR, 'tomcat')):
            return instances

        for instance_name in os.listdir(pki.server.INSTANCE_BASE_DIR):
            instance = pki.server.PKIInstance(instance_name)
            instance.load()
            instances.append(instance)

        return instances

class PKISubsystem(object):

    def __init__(self, instance, subsystem_name):

        self.instance = instance
        self.name = subsystem_name
        self.type = instance.type

        if self.type >= 10:
            self.base_dir = os.path.join(self.instance.base_dir, self.name)
            self.conf_dir = os.path.join(self.base_dir, 'conf')
        else:
            self.base_dir = instance.base_dir
            self.conf_dir = os.path.join(self.base_dir, 'conf')

        self.context_xml_template = os.path.join(
            pki.SHARE_DIR, self.name, 'conf', 'Catalina', 'localhost', self.name + '.xml')

        self.context_xml = os.path.join(
            instance.conf_dir, 'Catalina', 'localhost', self.name + '.xml')

        self.doc_base = os.path.join(self.base_dir, 'webapps', self.name)

    def is_valid(self):
        return os.path.exists(self.conf_dir)

    def validate(self):
        if not self.is_valid():
            raise pki.PKIException(
                'Invalid subsystem: ' + self.__repr__(),
                None, self.instance)

    def is_enabled(self):
        return self.instance.is_deployed(self.name)

    def enable(self):
        self.instance.deploy(self.name, self.context_xml_template, self.doc_base)

    def disable(self):
        self.instance.undeploy(self.name)

    def __repr__(self):
        return str(self.instance) + '/' + self.name


class PKIInstance(object):

    def __init__(self, name, instanceType=10):

        self.name = name
        self.type = instanceType

        if self.type >= 10:
            self.base_dir = os.path.join(INSTANCE_BASE_DIR, name)
            self.conf_dir = os.path.join(self.base_dir, 'conf')
        else:
            self.base_dir = os.path.join(pki.BASE_DIR, name)
            self.conf_dir = os.path.join(self.base_dir, 'conf')

        self.registry_dir = os.path.join(pki.server.REGISTRY_DIR, 'tomcat', self.name)
        self.registry_file = os.path.join(self.registry_dir, self.name)

        self.service_name = 'pki-tomcatd@%s.service' % self.name

        self.user = None
        self.group = None

        self.subsystems = []

    def is_valid(self):
        return os.path.exists(self.conf_dir)

    def validate(self):
        if not self.is_valid():
            raise pki.PKIException(
                'Invalid instance: ' + self.__repr__(), None)

    def start(self):
        subprocess.check_call(['systemctl', 'start', self.service_name])

    def stop(self):
        subprocess.check_call(['systemctl', 'stop', self.service_name])

    def is_active(self):
        rc = subprocess.call(['systemctl', '--quiet', 'is-active', self.service_name])
        return rc == 0

    def load(self):
        with open(self.registry_file, 'r') as registry:
            lines = registry.readlines()

        for line in lines:

            m = re.search('^PKI_USER=(.*)$', line)
            if m:
                self.user = m.group(1)

            m = re.search('^PKI_GROUP=(.*)$', line)
            if m:
                self.group = m.group(1)

        for subsystem_name in os.listdir(self.registry_dir):
            if subsystem_name in pki.server.SUBSYSTEM_TYPES:
                subsystem = PKISubsystem(self, subsystem_name)
                self.subsystems.append(subsystem)

    def is_deployed(self, webapp_name):
        context_xml = os.path.join(
            self.conf_dir, 'Catalina', 'localhost', webapp_name + '.xml')
        return os.path.exists(context_xml)

    def deploy(self, webapp_name, descriptor, doc_base=None):
        """
        Deploy a web application into a Tomcat instance.

        This method will copy the specified deployment descriptor into
        <instance>/conf/Catalina/localhost/<name>.xml and point the docBase
        to the specified location. The web application will become available
        under "/<name>" URL path.

        See also: http://tomcat.apache.org/tomcat-7.0-doc/config/context.html

        :param webapp_name: Web application name.
        :type webapp_name: str
        :param descriptor: Path to deployment descriptor (context.xml).
        :type descriptor: str
        :param doc_base: Path to web application content.
        :type doc_base: str
        """

        context_xml = os.path.join(
            self.conf_dir, 'Catalina', 'localhost', webapp_name + '.xml')

        # read deployment descriptor
        parser = etree.XMLParser(remove_blank_text=True)
        document = etree.parse(descriptor, parser)

        if doc_base:
            # customize docBase
            context = document.getroot()
            context.set('docBase', doc_base)

        # write deployment descriptor
        with open(context_xml, 'w') as f:
            f.write(etree.tostring(document, pretty_print=True))

        # find uid and gid
        uid = pwd.getpwnam(self.user).pw_uid
        gid = grp.getgrnam(self.group).gr_gid

        # set deployment descriptor ownership and permission
        os.chown(context_xml, uid, gid)
        os.chmod(context_xml, 00660)

    def undeploy(self, webapp_name):
        context_xml = os.path.join(
            self.conf_dir, 'Catalina', 'localhost', webapp_name + '.xml')
        os.remove(context_xml)

    def __repr__(self):
        if self.type == 9:
            return "Dogtag 9 " + self.name
        return self.name


class PKIServerException(pki.PKIException):

    def __init__(self, message, exception=None,
                 instance=None, subsystem=None):

        pki.PKIException.__init__(self, message, exception)

        self.instance = instance
        self.subsystem = subsystem
