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

from __future__ import absolute_import
from lxml import etree
import getpass
import grp
import io
import ldap
import operator
import os
import pwd
import re
import shutil
import subprocess
import tempfile

import pki
import pki.nss

INSTANCE_BASE_DIR = '/var/lib/pki'
REGISTRY_DIR = '/etc/sysconfig/pki'
SUBSYSTEM_TYPES = ['ca', 'kra', 'ocsp', 'tks', 'tps']
SUBSYSTEM_CLASSES = {}


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
        else:
            self.base_dir = instance.base_dir

        self.conf_dir = os.path.join(self.base_dir, 'conf')
        self.cs_conf = os.path.join(self.conf_dir, 'CS.cfg')

        self.context_xml_template = os.path.join(
            pki.SHARE_DIR,
            self.name,
            'conf',
            'Catalina',
            'localhost',
            self.name + '.xml')

        self.context_xml = os.path.join(
            instance.conf_dir, 'Catalina', 'localhost', self.name + '.xml')

        self.config = {}
        self.type = None
        self.prefix = None

        # custom subsystem location
        self.doc_base = os.path.join(self.base_dir, 'webapps', self.name)

    def load(self):
        self.config.clear()

        lines = open(self.cs_conf).read().splitlines()

        for line in lines:
            parts = line.split('=', 1)
            name = parts[0]
            value = parts[1]
            self.config[name] = value

        self.type = self.config['cs.type']
        self.prefix = self.type.lower()

    def find_subsystem_certs(self):
        certs = []

        cert_ids = self.config['%s.cert.list' % self.name].split(',')
        for cert_id in cert_ids:
            cert = self.create_subsystem_cert_object(cert_id)
            certs.append(cert)

        return certs

    def get_subsystem_cert(self, cert_id):
        return self.create_subsystem_cert_object(cert_id)

    def create_subsystem_cert_object(self, cert_id):
        cert = {}
        cert['id'] = cert_id
        cert['nickname'] = self.config.get(
            '%s.%s.nickname' % (self.name, cert_id), None)
        cert['token'] = self.config.get(
            '%s.%s.tokenname' % (self.name, cert_id), None)
        cert['data'] = self.config.get(
            '%s.%s.cert' % (self.name, cert_id), None)
        cert['request'] = self.config.get(
            '%s.%s.certreq' % (self.name, cert_id), None)
        return cert

    def update_subsystem_cert(self, cert):
        cert_id = cert['id']
        self.config['%s.%s.nickname' % (self.name, cert_id)] = (
            cert.get('nickname', None))
        self.config['%s.%s.tokenname' % (self.name, cert_id)] = (
            cert.get('token', None))
        self.config['%s.%s.cert' % (self.name, cert_id)] = (
            cert.get('data', None))
        self.config['%s.%s.certreq' % (self.name, cert_id)] = (
            cert.get('request', None))

    def save(self):
        sorted_config = sorted(self.config.items(), key=operator.itemgetter(0))
        with io.open(self.cs_conf, 'wb') as f:
            for (key, value) in sorted_config:
                f.write('%s=%s\n' % (key, value))

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
        if os.path.exists(self.doc_base):
            # deploy custom subsystem if exists
            doc_base = self.doc_base

        else:
            # otherwise deploy default subsystem directly from
            # /usr/share/pki/<subsystem>/webapps/<subsystem>
            doc_base = None

        self.instance.deploy(self.name, self.context_xml_template, doc_base)

    def disable(self):
        self.instance.undeploy(self.name)

    def open_database(self, name='internaldb'):

        # TODO: add LDAPI support
        hostname = self.config['%s.ldapconn.host' % name]
        port = self.config['%s.ldapconn.port' % name]
        secure = self.config['%s.ldapconn.secureConn' % name]

        if secure == 'true':
            url = 'ldaps://%s:%s' % (hostname, port)

        elif secure == 'false':
            url = 'ldap://%s:%s' % (hostname, port)

        else:
            raise Exception(
                'Invalid parameter value in %s.ldapconn.secureConn: %s' %
                (name, secure))

        connection = PKIDatabaseConnection(url)

        connection.set_security_database(self.instance.nssdb_dir)

        auth_type = self.config['%s.ldapauth.authtype' % name]
        if auth_type == 'BasicAuth':
            connection.set_credentials(
                bind_dn=self.config['%s.ldapauth.bindDN' % name],
                bind_password=self.instance.get_password(name)
            )

        elif auth_type == 'SslClientAuth':
            connection.set_credentials(
                client_cert_nickname=self.config[
                    '%s.ldapauth.clientCertNickname' % name],
                nssdb_password=self.instance.get_password('internal')
            )

        else:
            raise Exception(
                'Invalid parameter value in %s.ldapauth.authtype: %s' %
                (name, auth_type))

        connection.open()

        return connection

    def __repr__(self):
        return str(self.instance) + '/' + self.name


class PKIInstance(object):

    def __init__(self, name, instanceType=10):  # nopep8

        self.name = name
        self.type = instanceType

        if self.type >= 10:
            self.base_dir = os.path.join(INSTANCE_BASE_DIR, name)
        else:
            self.base_dir = os.path.join(pki.BASE_DIR, name)

        self.conf_dir = os.path.join(self.base_dir, 'conf')
        self.password_conf = os.path.join(self.conf_dir, 'password.conf')

        self.nssdb_dir = os.path.join(self.base_dir, 'alias')
        self.lib_dir = os.path.join(self.base_dir, 'lib')

        self.registry_dir = os.path.join(
            pki.server.REGISTRY_DIR,
            'tomcat',
            self.name)
        self.registry_file = os.path.join(self.registry_dir, self.name)

        self.service_name = 'pki-tomcatd@%s.service' % self.name

        self.user = None
        self.group = None

        self.uid = None
        self.gid = None

        self.passwords = {}

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
        rc = subprocess.call(
            ['systemctl', '--quiet', 'is-active', self.service_name])
        return rc == 0

    def load(self):
        # load UID and GID
        with open(self.registry_file, 'r') as registry:
            lines = registry.readlines()

        for line in lines:

            m = re.search('^PKI_USER=(.*)$', line)
            if m:
                self.user = m.group(1)
                self.uid = pwd.getpwnam(self.user).pw_uid

            m = re.search('^PKI_GROUP=(.*)$', line)
            if m:
                self.group = m.group(1)
                self.gid = grp.getgrnam(self.group).gr_gid

        # load passwords
        self.passwords.clear()
        lines = open(self.password_conf).read().splitlines()

        for line in lines:
            parts = line.split('=', 1)
            name = parts[0]
            value = parts[1]
            self.passwords[name] = value

        # load subsystems
        for subsystem_name in os.listdir(self.registry_dir):
            if subsystem_name in SUBSYSTEM_TYPES:
                if subsystem_name in SUBSYSTEM_CLASSES:
                    subsystem = SUBSYSTEM_CLASSES[subsystem_name](self)
                else:
                    subsystem = PKISubsystem(self, subsystem_name)
                subsystem.load()
                self.subsystems.append(subsystem)

    def get_password(self, name):
        if name in self.passwords:
            return self.passwords[name]

        password = getpass.getpass(prompt='Enter password for %s: ' % name)
        self.passwords[name] = password

        return password

    def open_nssdb(self, token='internal'):
        return pki.nss.NSSDatabase(
            directory=self.nssdb_dir,
            token=token,
            password=self.get_password(token))

    def get_subsystem(self, name):
        for subsystem in self.subsystems:
            if name == subsystem.name:
                return subsystem
        return None

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
        with open(context_xml, 'wb') as f:
            # xml as UTF-8 encoded bytes
            document.write(f, pretty_print=True, encoding='utf-8')

        # set deployment descriptor ownership and permission
        os.chown(context_xml, self.uid, self.gid)
        os.chmod(context_xml, 0o0660)

    def undeploy(self, webapp_name):
        context_xml = os.path.join(
            self.conf_dir, 'Catalina', 'localhost', webapp_name + '.xml')
        os.remove(context_xml)

    def __repr__(self):
        if self.type == 9:
            return "Dogtag 9 " + self.name
        return self.name


class PKIDatabaseConnection(object):

    def __init__(self, url='ldap://localhost:389'):

        self.url = url

        self.nssdb_dir = None

        self.bind_dn = None
        self.bind_password = None

        self.client_cert_nickname = None
        self.nssdb_password = None

        self.temp_dir = None
        self.ldap = None

    def set_security_database(self, nssdb_dir=None):
        self.nssdb_dir = nssdb_dir

    def set_credentials(self, bind_dn=None, bind_password=None,
                        client_cert_nickname=None, nssdb_password=None):
        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.client_cert_nickname = client_cert_nickname
        self.nssdb_password = nssdb_password

    def open(self):

        self.temp_dir = tempfile.mkdtemp()

        if self.nssdb_dir:

            ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, self.nssdb_dir)

        if self.client_cert_nickname:

            password_file = os.path.join(self.temp_dir, 'password.txt')
            with open(password_file, 'w') as f:
                f.write(self.nssdb_password)

            ldap.set_option(ldap.OPT_X_TLS_CERTFILE, self.client_cert_nickname)
            ldap.set_option(ldap.OPT_X_TLS_KEYFILE, password_file)

        self.ldap = ldap.initialize(self.url)

        if self.bind_dn and self.bind_password:
            self.ldap.simple_bind_s(self.bind_dn, self.bind_password)

    def close(self):

        if self.ldap:
            self.ldap.unbind_s()

        if self.temp_dir:
            shutil.rmtree(self.temp_dir)


class PKIServerException(pki.PKIException):

    def __init__(self, message, exception=None,
                 instance=None, subsystem=None):

        pki.PKIException.__init__(self, message, exception)

        self.instance = instance
        self.subsystem = subsystem


class Tomcat(object):

    @classmethod
    def get_major_version(self):

        # run "tomcat version"
        output = subprocess.check_output(['/usr/sbin/tomcat', 'version'])

        # find "Server version: Apache Tomcat/<major version>.<minor version>"
        match = re.search(r'^Server version:[^/]*/(\d+).*$', output, re.MULTILINE)

        if not match:
            raise Exception('Unable to determine Tomcat version')

        # return major version
        return match.group(1)
