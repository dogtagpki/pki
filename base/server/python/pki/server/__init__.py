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
import functools
import getpass
import grp
import io
import ldap
import ldap.filter
import operator
import os
import pwd
import re
import shutil
import subprocess
import tempfile

import pki
import pki.nssdb
import pki.util

INSTANCE_BASE_DIR = '/var/lib/pki'
CONFIG_BASE_DIR = '/etc/pki'
LOG_BASE_DIR = '/var/log/pki'
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


@functools.total_ordering
class PKISubsystem(object):

    def __init__(self, instance, subsystem_name):

        self.instance = instance
        self.name = subsystem_name  # e.g. ca, kra

        if instance.type >= 10:
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
        self.type = None    # e.g. CA, KRA
        self.prefix = None  # e.g. ca, kra

        # custom subsystem location
        self.doc_base = os.path.join(self.base_dir, 'webapps', self.name)

    def __eq__(self, other):
        if not isinstance(other, PKISubsystem):
            return NotImplemented
        return (self.name == other.name and
                self.instance == other.instance and
                self.type == other.type)

    def __ne__(self, other):
        if not isinstance(other, PKISubsystem):
            return NotImplemented
        return not self.__eq__(other)

    def __lt__(self, other):
        if not isinstance(other, PKISubsystem):
            return NotImplemented
        self_type = self.type if self.type is not None else ''
        other_type = other.type if other.type is not None else ''
        return (self.name < other.name or
                self.instance < other.instance or
                self_type < other_type)

    def __hash__(self):
        return hash((self.name, self.instance, self.type))

    def load(self):
        self.config.clear()

        lines = open(self.cs_conf).read().splitlines()

        for index, line in enumerate(lines):
            if not line or line.startswith('#'):
                continue
            parts = line.split('=', 1)
            if len(parts) < 2:
                raise Exception('Missing delimiter in %s line %d' % (self.cs_conf, index + 1))
            name = parts[0]
            value = parts[1]
            self.config[name] = value

        self.type = self.config['cs.type']
        self.prefix = self.type.lower()

    def find_system_certs(self):
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
        cert['certusage'] = self.config.get(
            '%s.cert.%s.certusage' % (self.name, cert_id), None)
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

    def export_system_cert(
            self,
            cert_id,
            pkcs12_file,
            pkcs12_password_file,
            new_file=False):

        cert = self.get_subsystem_cert(cert_id)
        nickname = cert['nickname']
        token = cert['token']

        if token and token.lower() in ['internal', 'internal key storage token']:
            token = None

        nssdb_password = self.instance.get_token_password(token)

        tmpdir = tempfile.mkdtemp()

        try:
            nssdb_password_file = os.path.join(tmpdir, 'password.txt')
            with open(nssdb_password_file, 'w') as f:
                f.write(nssdb_password)

            # add the certificate, key, and chain
            cmd = [
                'pki',
                '-d', self.instance.nssdb_dir,
                '-C', nssdb_password_file
            ]

            if token:
                cmd.extend(['--token', token])

            cmd.extend([
                'pkcs12-cert-add',
                '--pkcs12-file', pkcs12_file,
                '--pkcs12-password-file', pkcs12_password_file,
            ])

            if new_file:
                cmd.extend(['--new-file'])

            cmd.extend([
                nickname
            ])

            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)

    def export_cert_chain(
            self,
            pkcs12_file,
            pkcs12_password_file):

        # use subsystem certificate to get certificate chain
        cert = self.get_subsystem_cert('subsystem')
        nickname = cert['nickname']
        token = cert['token']

        if token and token.lower() in ['internal', 'internal key storage token']:
            token = None

        nssdb_password = self.instance.get_token_password(token)

        tmpdir = tempfile.mkdtemp()

        try:
            nssdb_password_file = os.path.join(tmpdir, 'password.txt')
            with open(nssdb_password_file, 'w') as f:
                f.write(nssdb_password)

            # export the certificate, key, and chain
            cmd = [
                'pki',
                '-d', self.instance.nssdb_dir,
                '-C', nssdb_password_file
            ]

            if token:
                cmd.extend(['--token', token])

            cmd.extend([
                'pkcs12-export',
                '--pkcs12-file', pkcs12_file,
                '--pkcs12-password-file', pkcs12_password_file,
                nickname
            ])

            subprocess.check_call(cmd)

            # remove the certificate and key, but keep the chain
            cmd = [
                'pki',
                '-d', self.instance.nssdb_dir,
                '-C', nssdb_password_file
            ]

            if token:
                cmd.extend(['--token', token])

            cmd.extend([
                'pkcs12-cert-del',
                '--pkcs12-file', pkcs12_file,
                '--pkcs12-password-file', pkcs12_password_file,
                nickname
            ])

            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)

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

    def open_database(self, name='internaldb', bind_dn=None,
                      bind_password=None):

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
        if (bind_dn is not None and bind_password is not None):
            # connect using the provided credentials
            connection.set_credentials(
                bind_dn=bind_dn,
                bind_password=bind_password
            )
        elif auth_type == 'BasicAuth':
            connection.set_credentials(
                bind_dn=self.config['%s.ldapauth.bindDN' % name],
                bind_password=self.instance.get_password(name)
            )

        elif auth_type == 'SslClientAuth':
            connection.set_credentials(
                client_cert_nickname=self.config[
                    '%s.ldapauth.clientCertNickname' % name],
                # TODO: remove hard-coded token name
                nssdb_password=self.instance.get_token_password('internal')
            )

        else:
            raise Exception(
                'Invalid parameter value in %s.ldapauth.authtype: %s' %
                (name, auth_type))

        connection.open()

        return connection

    def customize_file(self, input_file, output_file):
        params = {
            '{instanceId}': self.instance.name,
            '{database}': self.config['internaldb.database'],
            '{rootSuffix}': self.config['internaldb.basedn']
        }

        pki.util.customize_file(input_file, output_file, params)

    def __repr__(self):
        return str(self.instance) + '/' + self.name


class CASubsystem(PKISubsystem):

    def __init__(self, instance):
        super(CASubsystem, self).__init__(instance, 'ca')

    def find_cert_requests(self, cert=None):

        base_dn = self.config['internaldb.basedn']

        if cert:
            escaped_value = ldap.filter.escape_filter_chars(cert)
            search_filter = '(extdata-req--005fissued--005fcert=%s)' % escaped_value

        else:
            search_filter = '(objectClass=*)'

        con = self.open_database()

        entries = con.ldap.search_s(
            'ou=ca,ou=requests,%s' % base_dn,
            ldap.SCOPE_ONELEVEL,
            search_filter,
            None)

        con.close()

        requests = []
        for entry in entries:
            requests.append(self.create_request_object(entry))

        return requests

    def get_cert_requests(self, request_id):

        base_dn = self.config['internaldb.basedn']

        con = self.open_database()

        entries = con.ldap.search_s(
            'cn=%s,ou=ca,ou=requests,%s' % (request_id, base_dn),
            ldap.SCOPE_BASE,
            '(objectClass=*)',
            None)

        con.close()

        entry = entries[0]
        return self.create_request_object(entry)

    def create_request_object(self, entry):

        attrs = entry[1]

        request = {}
        request['id'] = attrs['cn'][0]
        request['type'] = attrs['requestType'][0]
        request['status'] = attrs['requestState'][0]
        request['request'] = attrs['extdata-cert--005frequest'][0]

        return request


# register CASubsystem
SUBSYSTEM_CLASSES['ca'] = CASubsystem


class ExternalCert(object):

    def __init__(self, nickname=None, token=None):
        self.nickname = nickname
        self.token = token


@functools.total_ordering
class PKIInstance(object):

    def __init__(self, name, instanceType=10):  # nopep8

        self.name = name
        self.type = instanceType

        if self.type >= 10:
            self.base_dir = os.path.join(INSTANCE_BASE_DIR, name)
        else:
            self.base_dir = os.path.join(pki.BASE_DIR, name)

        self.conf_dir = os.path.join(CONFIG_BASE_DIR, name)
        self.log_dir = os.path.join(LOG_BASE_DIR, name)

        self.password_conf = os.path.join(self.conf_dir, 'password.conf')
        self.external_certs_conf = os.path.join(
            self.conf_dir, 'external_certs.conf')
        self.external_certs = []

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

    def __eq__(self, other):
        if not isinstance(other, PKIInstance):
            return NotImplemented
        return (self.name == other.name and
                self.type == other.type)

    def __ne__(self, other):
        if not isinstance(other, PKIInstance):
            return NotImplemented
        return not self.__eq__(other)

    def __lt__(self, other):
        if not isinstance(other, PKIInstance):
            return NotImplemented
        return (self.name < other.name or
                self.type < other.type)

    def __hash__(self):
        return hash((self.name, self.type))

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
        if os.path.exists(self.registry_file):

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
        if os.path.exists(self.password_conf):

            lines = open(self.password_conf).read().splitlines()

            for index, line in enumerate(lines):
                if not line or line.startswith('#'):
                    continue
                parts = line.split('=', 1)
                if len(parts) < 2:
                    raise Exception('Missing delimiter in %s line %d' %
                                    (self.password_conf, index + 1))
                name = parts[0]
                value = parts[1]
                self.passwords[name] = value

        self.load_external_certs(self.external_certs_conf)

        # load subsystems
        if os.path.exists(self.registry_dir):
            for subsystem_name in os.listdir(self.registry_dir):
                if subsystem_name in SUBSYSTEM_TYPES:
                    if subsystem_name in SUBSYSTEM_CLASSES:
                        subsystem = SUBSYSTEM_CLASSES[subsystem_name](self)
                    else:
                        subsystem = PKISubsystem(self, subsystem_name)
                    subsystem.load()
                    self.subsystems.append(subsystem)

    def load_external_certs(self, conf_file):
        self.external_certs = PKIInstance.read_external_certs(conf_file)

    @staticmethod
    def read_external_certs(conf_file):
        external_certs = []
        # load external certs data
        if os.path.exists(conf_file) and os.stat(conf_file).st_size > 0:
            tmp_certs = {}
            lines = open(conf_file).read().splitlines()
            for line in lines:
                m = re.search('(\\d+)\\.(\\w+)=(.*)', line)
                if not m:
                    raise pki.PKIException('Error parsing %s' % conf_file)
                indx = m.group(1)
                attr = m.group(2)
                value = m.group(3)
                if indx not in tmp_certs:
                    tmp_certs[indx] = ExternalCert()

                setattr(tmp_certs[indx], attr, value)
            external_certs = tmp_certs.values()
        return external_certs

    def get_password(self, name):

        # find password (e.g. internaldb, replicationdb) in password.conf
        if name in self.passwords:
            return self.passwords[name]

        # prompt for password if not found
        password = getpass.getpass(prompt='Enter password for %s: ' % name)
        self.passwords[name] = password

        return password

    def get_token_password(self, token='internal'):

        # determine the password name for the token
        if not token or token.lower() in ['internal', 'internal key storage token']:
            name = 'internal'

        else:
            name = 'hardware-%s' % token

        # find password in password.conf
        if name in self.passwords:
            return self.passwords[name]

        # prompt for password if not found
        password = getpass.getpass(prompt='Enter password for %s: ' % token)
        self.passwords[name] = password

        return password

    def open_nssdb(self, token='internal'):
        return pki.nssdb.NSSDatabase(
            directory=self.nssdb_dir,
            token=token,
            password=self.get_token_password(token))

    def external_cert_exists(self, nickname, token):
        for cert in self.external_certs:
            if cert.nickname == nickname and cert.token == token:
                return True
        return False

    def add_external_cert(self, nickname, token):
        if self.external_cert_exists(nickname, token):
            return
        self.external_certs.append(ExternalCert(nickname, token))
        self.save_external_cert_data()

    def delete_external_cert(self, nickname, token):
        for cert in self.external_certs:
            if cert.nickname == nickname and cert.token == token:
                self.external_certs.remove(cert)
        self.save_external_cert_data()

    def save_external_cert_data(self):
        with io.open(self.external_certs_conf, 'wb') as f:
            indx = 0
            for cert in self.external_certs:
                f.write('%s.nickname=%s\n' % (str(indx), cert.nickname))
                f.write('%s.token=%s\n' % (str(indx), cert.token))
                indx += 1

    def export_external_certs(self, pkcs12_file, pkcs12_password_file,
                              new_file=False):
        for cert in self.external_certs:
            nickname = cert.nickname
            token = cert.token

            if token and token.lower() in ['internal', 'internal key storage token']:
                token = None

            nssdb_password = self.get_token_password(token)

            tmpdir = tempfile.mkdtemp()

            try:
                nssdb_password_file = os.path.join(tmpdir, 'password.txt')
                with open(nssdb_password_file, 'w') as f:
                    f.write(nssdb_password)

                # add the certificate, key, and chain
                cmd = [
                    'pki',
                    '-d', self.nssdb_dir,
                    '-C', nssdb_password_file
                ]

                if token:
                    cmd.extend(['--token', token])

                cmd.extend([
                    'pkcs12-cert-add',
                    '--pkcs12-file', pkcs12_file,
                    '--pkcs12-password-file', pkcs12_password_file,
                ])

                if new_file:
                    cmd.extend(['--new-file'])

                cmd.extend([
                    nickname
                ])

                subprocess.check_call(cmd)

            finally:
                shutil.rmtree(tmpdir)

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
    def get_major_version(cls):

        # run "tomcat version"
        output = subprocess.check_output(['/usr/sbin/tomcat', 'version'])
        output = output.decode('utf-8')

        # find "Server version: Apache Tomcat/<major version>.<minor version>"
        match = re.search(r'^Server version:[^/]*/(\d+).*$', output, re.MULTILINE)

        if not match:
            raise Exception('Unable to determine Tomcat version')

        # return major version
        return match.group(1)
