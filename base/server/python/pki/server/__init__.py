# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
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
# Copyright (C) 2018 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import

import functools
import getpass
import grp
import io
import logging
import os
import pwd
import re
import shutil
import subprocess
import tempfile

import ldap
import ldap.filter
from lxml import etree

import pki
import pki.account
import pki.cert
import pki.client as client
import pki.nssdb
import pki.util
from pki.keyring import Keyring
import pki.server.subsystem

SYSCONFIG_DIR = '/etc/sysconfig'
ETC_SYSTEMD_DIR = '/etc/systemd'
LIB_SYSTEMD_DIR = '/lib/systemd'

SUBSYSTEM_TYPES = ['ca', 'kra', 'ocsp', 'tks', 'tps']

logger = logging.getLogger(__name__)

parser = etree.XMLParser(remove_blank_text=True)


class Tomcat(object):

    BASE_DIR = '/var/lib/tomcats'
    CONF_DIR = '/etc/tomcat'
    LIB_DIR = '/usr/share/java/tomcat'
    SHARE_DIR = '/usr/share/tomcat'
    EXECUTABLE = '/usr/sbin/tomcat'
    UNIT_FILE = '/lib/systemd/system/tomcat@.service'
    TOMCAT_CONF = CONF_DIR + '/tomcat.conf'

    @classmethod
    def get_version(cls):
        # run "tomcat version"
        output = subprocess.check_output([Tomcat.EXECUTABLE, 'version'])
        output = output.decode('utf-8')

        # find "Server version: Apache Tomcat/<version>"
        match = re.search(
            r'^Server version: *.*/(.+)$',
            output,
            re.MULTILINE  # pylint: disable=no-member
        )

        if not match:
            raise Exception('Unable to determine Tomcat version')

        # return version
        return pki.util.Version(match.group(1))


@functools.total_ordering
class PKIServer(object):

    BASE_DIR = '/var/lib/pki'
    CONFIG_DIR = '/etc/pki'
    LOG_DIR = '/var/log/pki'
    SHARE_DIR = '/usr/share/pki'
    REGISTRY_DIR = SYSCONFIG_DIR + '/pki'
    TOMCAT_CONF = SHARE_DIR + '/etc/tomcat.conf'

    def __init__(self,
                 name,
                 instance_type='tomcat',
                 user='tomcat',
                 group='tomcat'):

        self.name = name
        self.type = instance_type
        self.user = user
        self.group = group

        self.config = {}
        self.passwords = {}

    def __repr__(self):
        return self.name

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if not isinstance(other, PKIServer):
            return NotImplemented
        return self.name == other.name

    def __lt__(self, other):
        if not isinstance(other, PKIServer):
            return NotImplemented
        return self.name < other.name

    @property
    def base_dir(self):
        return os.path.join(Tomcat.BASE_DIR, self.name)

    @property
    def bin_dir(self):
        return os.path.join(self.base_dir, 'bin')

    @property
    def conf_dir(self):
        return os.path.join(self.base_dir, 'conf')

    @property
    def lib_dir(self):
        return os.path.join(self.base_dir, 'lib')

    @property
    def common_dir(self):
        return os.path.join(self.base_dir, 'common')

    @property
    def common_lib_dir(self):
        return os.path.join(self.common_dir, 'lib')

    @property
    def log_dir(self):
        return os.path.join(self.base_dir, 'logs')

    @property
    def temp_dir(self):
        return os.path.join(self.base_dir, 'temp')

    @property
    def webapps_dir(self):
        return os.path.join(self.base_dir, 'webapps')

    @property
    def work_dir(self):
        return os.path.join(self.base_dir, 'work')

    @property
    def catalina_policy(self):
        return os.path.join(self.conf_dir, 'catalina.policy')

    @property
    def catalina_properties(self):
        return os.path.join(self.conf_dir, 'catalina.properties')

    @property
    def context_xml(self):
        return os.path.join(self.conf_dir, 'context.xml')

    @property
    def logging_properties(self):
        return os.path.join(self.conf_dir, 'logging.properties')

    @property
    def server_xml(self):
        return os.path.join(self.conf_dir, 'server.xml')

    @property
    def tomcat_conf(self):
        return os.path.join(self.conf_dir, 'tomcat.conf')

    @property
    def web_xml(self):
        return os.path.join(self.conf_dir, 'web.xml')

    @property
    def service_name(self):
        return '%s@%s' % (self.type, self.name)

    @property
    def service_conf(self):
        return os.path.join(SYSCONFIG_DIR, self.service_name)

    @property
    def uid(self):
        return pwd.getpwnam(self.user).pw_uid

    @property
    def gid(self):
        return grp.getgrnam(self.group).gr_gid

    @property
    def password_conf(self):
        return os.path.join(self.conf_dir, 'password.conf')

    @property
    def nssdb_dir(self):
        return os.path.join(self.base_dir, 'alias')

    @property
    def jss_conf(self):
        return os.path.join(self.conf_dir, 'jss.conf')

    def is_valid(self):
        return os.path.exists(self.base_dir)

    def validate(self):
        if not self.is_valid():
            raise pki.PKIException('Invalid instance: ' + self.name, None)

    def is_active(self):
        cmd = ['systemctl', '--quiet', 'is-active', '%s.service' % self.service_name]
        logger.debug('Command: %s', ' '.join(cmd))
        rc = subprocess.call(cmd)
        return rc == 0

    def start(self):
        cmd = ['systemctl', 'start', '%s.service' % self.service_name]
        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.check_call(cmd)

    def stop(self):
        cmd = ['systemctl', 'stop', '%s.service' % self.service_name]
        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.check_call(cmd)

    def restart(self):
        cmd = ['systemctl', 'restart', '%s.service' % self.service_name]
        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.check_call(cmd)

    def enable(self):
        cmd = ['systemctl', 'enable', '%s.service' % self.service_name]
        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.check_call(cmd)

    def disable(self):
        cmd = ['systemctl', 'disable', '%s.service' % self.service_name]
        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.check_call(cmd)

    def run(self, command='start', jdb=False, as_current_user=False):
        p = self.execute(command, jdb=jdb, as_current_user=as_current_user)
        p.wait()

    def execute(self, command, jdb=False, as_current_user=False):

        logger.debug('Environment variables:')
        for name in self.config:
            logger.debug('- %s: %s', name, self.config[name])

        prefix = []

        # by default run PKI server as systemd user
        if not as_current_user:

            current_user = pwd.getpwuid(os.getuid()).pw_name

            # switch to systemd user if different from current user
            if current_user != self.user:
                prefix.extend(['sudo', '-u', self.user])

        java_home = self.config['JAVA_HOME']
        java_opts = self.config['JAVA_OPTS']
        security_manager = self.config['SECURITY_MANAGER']

        classpath = [
            Tomcat.SHARE_DIR + '/bin/bootstrap.jar',
            Tomcat.SHARE_DIR + '/bin/tomcat-juli.jar',
            '/usr/lib/java/commons-daemon.jar'
        ]

        cmd = prefix
        if jdb:
            cmd.extend(['jdb'])
        else:
            cmd.extend([
                java_home + '/bin/java',
                '-agentpath:/usr/lib/abrt-java-connector/libabrt-java-connector.so=abrt=on,'
            ])

        cmd.extend([
            '-classpath', os.pathsep.join(classpath),
            '-Dcatalina.base=' + self.base_dir,
            '-Dcatalina.home=' + Tomcat.SHARE_DIR,
            '-Djava.endorsed.dirs=',
            '-Djava.io.tmpdir=' + self.temp_dir,
            '-Djava.util.logging.config.file=' + self.logging_properties,
            '-Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager'
        ])

        if security_manager == 'true':
            cmd.extend([
                '-Djava.security.manager',
                '-Djava.security.policy==' + self.catalina_policy
            ])

        if java_opts:
            cmd.extend(java_opts.split())

        cmd.extend(['org.apache.catalina.startup.Bootstrap', command])

        logger.debug('Command: %s', ' '.join(cmd))

        return subprocess.Popen(cmd, env=self.config)

    def makedirs(self, path, force=False):
        pki.util.makedirs(
            path, uid=self.uid, gid=self.gid, force=force)

    def symlink(self, source, dest, force=False):
        pki.util.symlink(
            source, dest, uid=self.uid, gid=self.gid, force=force)

    def copy(self, source, dest, force=False):
        pki.util.copy(
            source, dest, uid=self.uid, gid=self.gid, force=force)

    def copyfile(self, source, dest, slots=None, params=None, force=False):
        pki.util.copyfile(
            source, dest, slots=slots, params=params,
            uid=self.uid, gid=self.gid, force=force)

    def create(self, force=False):

        self.makedirs(self.base_dir, force=force)

        bin_dir = os.path.join(Tomcat.SHARE_DIR, 'bin')
        self.symlink(bin_dir, self.bin_dir, force=force)

        self.makedirs(self.conf_dir, force=force)

        catalina_policy = os.path.join(Tomcat.CONF_DIR, 'catalina.policy')
        self.copy(catalina_policy, self.catalina_policy, force=force)

        catalina_properties = os.path.join(
            PKIServer.SHARE_DIR, 'server', 'conf', 'catalina.properties')
        self.symlink(catalina_properties, self.catalina_properties, force=force)

        context_xml = os.path.join(Tomcat.CONF_DIR, 'context.xml')
        self.copy(context_xml, self.context_xml, force=force)

        logging_properties = os.path.join(Tomcat.CONF_DIR, 'logging.properties')
        self.copy(logging_properties, self.logging_properties, force=force)

        server_xml = os.path.join(Tomcat.CONF_DIR, 'server.xml')
        self.copy(server_xml, self.server_xml, force=force)

        self.copy(Tomcat.TOMCAT_CONF, self.tomcat_conf, force=force)

        tomcat_users_xml = os.path.join(Tomcat.CONF_DIR, 'tomcat-users.xml')
        tomcat_users_xml_link = os.path.join(self.conf_dir, 'tomcat-users.xml')
        self.copy(tomcat_users_xml, tomcat_users_xml_link, force=force)

        tomcat_users_xsd = os.path.join(Tomcat.CONF_DIR, 'tomcat-users.xsd')
        tomcat_users_xsd_link = os.path.join(self.conf_dir, 'tomcat-users.xsd')
        self.copy(tomcat_users_xsd, tomcat_users_xsd_link, force=force)

        web_xml = os.path.join(Tomcat.CONF_DIR, 'web.xml')
        self.copy(web_xml, self.web_xml, force=force)

        conf_d_dir = os.path.join(self.conf_dir, 'conf.d')
        self.makedirs(conf_d_dir, force=force)

        lib_dir = os.path.join(PKIServer.SHARE_DIR, 'server', 'lib')
        self.symlink(lib_dir, self.lib_dir, force=force)

        self.makedirs(self.common_dir, force=force)

        common_lib_dir = os.path.join(PKIServer.SHARE_DIR, 'server', 'common', 'lib')
        self.symlink(common_lib_dir, self.common_lib_dir, force=force)

        self.makedirs(self.temp_dir, force=force)
        self.makedirs(self.webapps_dir, force=force)
        self.makedirs(self.work_dir, force=force)
        self.makedirs(self.log_dir, force=force)

        document = etree.parse(self.server_xml, parser)
        server = document.getroot()

        for engine in server.findall('Service/Engine'):
            engine_name = engine.get('name')
            engine_dir = os.path.join(self.conf_dir, engine_name)
            self.makedirs(engine_dir, force=force)

            for host in engine.findall('Host'):
                host_name = host.get('name')
                host_dir = os.path.join(engine_dir, host_name)
                self.makedirs(host_dir, force=force)

        service_conf = os.path.join(SYSCONFIG_DIR, 'tomcat')
        self.copy(service_conf, self.service_conf, force=force)

        with open(self.service_conf, 'a') as f:
            print('CATALINA_BASE="%s"' % self.base_dir, file=f)

    def create_nssdb(self, force=False):

        logger.info('Creating NSS database: %s', self.nssdb_dir)

        self.makedirs(self.nssdb_dir, force=force)

        nssdb = pki.nssdb.NSSDatabase(
            directory=self.nssdb_dir,
            password=self.get_token_password())

        nssdb.create()

        pki.util.chown(self.nssdb_dir, self.uid, self.gid)

    def get_webapps(self):

        webapps = []

        context_dir = os.path.join(
            self.conf_dir,
            'Catalina',
            'localhost')

        for filename in os.listdir(context_dir):

            if not filename.endswith('.xml'):
                continue

            webapp = {}

            webapp_id = filename[:-4]
            webapp['id'] = webapp_id

            parts = webapp_id.split('##')

            name = parts[0]
            if name == 'ROOT':
                webapp['path'] = '/'
            else:
                webapp['path'] = '/' + name.replace('#', '/')

            if len(parts) > 1:
                webapp['version'] = parts[1]

            context_xml = os.path.join(context_dir, filename)
            webapp['descriptor'] = context_xml

            document = etree.parse(context_xml, parser)
            context = document.getroot()

            doc_base = context.get('docBase', None)
            webapp['docBase'] = doc_base

            webapps.append(webapp)

        return sorted(webapps, key=lambda webapp: webapp['id'])

    def deploy_webapp(self, webapp_id, descriptor, doc_base=None):
        """
        Deploy a web application into a Tomcat instance.

        This method will copy the specified deployment descriptor into
        <instance>/conf/Catalina/localhost/<ID>.xml and point the docBase
        to the specified location.

        See also: https://tomcat.apache.org/tomcat-8.5-doc/config/context.html

        :param webapp_id: Web application ID.
        :type webapp_id: str
        :param descriptor: Path to deployment descriptor (context.xml).
        :type descriptor: str
        :param doc_base: Path to web application content.
        :type doc_base: str
        """
        context_xml = os.path.join(
            self.conf_dir,
            'Catalina',
            'localhost',
            webapp_id + '.xml')

        document = etree.parse(descriptor, parser)
        context = document.getroot()

        if doc_base is not None:
            context.set('docBase', doc_base)

        with open(context_xml, 'wb') as f:
            # xml as UTF-8 encoded bytes
            document.write(f, pretty_print=True, encoding='utf-8')

        os.chown(context_xml, self.uid, self.gid)
        os.chmod(context_xml, 0o0660)

    def undeploy_webapp(self, webapp_id, force=False):

        context_xml = os.path.join(
            self.conf_dir,
            'Catalina',
            'localhost',
            webapp_id + '.xml')

        pki.util.remove(context_xml, force=force)

    def remove(self, force=False):

        pki.util.remove(self.service_conf, force=force)
        pki.util.rmtree(self.log_dir, force=force)
        pki.util.rmtree(self.work_dir, force=force)
        pki.util.rmtree(self.webapps_dir, force=force)
        pki.util.rmtree(self.temp_dir, force=force)
        pki.util.unlink(self.common_lib_dir, force=force)
        pki.util.rmtree(self.common_dir, force=force)
        pki.util.unlink(self.lib_dir, force=force)
        pki.util.rmtree(self.conf_dir, force=force)
        pki.util.unlink(self.bin_dir, force=force)
        pki.util.rmtree(self.base_dir, force=force)

    def remove_nssdb(self, force=False):

        pki.util.rmtree(self.nssdb_dir, force=force)

    def load(self):

        logger.info('Loading instance: %s', self.name)

        self.load_config()
        self.load_passwords()

    def load_config(self):

        self.config.clear()

        logger.info('Loading global Tomcat config: %s', Tomcat.TOMCAT_CONF)
        pki.util.load_properties(Tomcat.TOMCAT_CONF, self.config)

        logger.info('Loading PKI Tomcat config: %s', PKIServer.TOMCAT_CONF)
        pki.util.load_properties(PKIServer.TOMCAT_CONF, self.config)

        if os.path.exists(self.tomcat_conf):
            logger.info('Loading instance Tomcat config: %s', self.tomcat_conf)
            pki.util.load_properties(self.tomcat_conf, self.config)

        # strip quotes
        for name, value in self.config.items():
            if value.startswith('"') and value.endswith('"'):
                self.config[name] = value[1:-1]

        self.config['NAME'] = self.name

    def load_passwords(self):

        self.passwords.clear()

        if os.path.exists(self.password_conf):
            logger.info('Loading password config: %s', self.password_conf)
            pki.util.load_properties(self.password_conf, self.passwords)

    def store_passwords(self):

        pki.util.store_properties(self.password_conf, self.passwords)
        pki.util.chown(self.password_conf, self.uid, self.gid)

    def load_jss_config(self):

        jss_config = {}

        if os.path.exists(self.jss_conf):
            logger.info('Loading JSS config: %s', self.jss_conf)
            pki.util.load_properties(self.jss_conf, jss_config)

        return jss_config

    def store_jss_config(self, jss_config):

        pki.util.store_properties(self.jss_conf, jss_config)
        pki.util.chown(self.jss_conf, self.uid, self.gid)

    def get_server_config(self):
        server_config = ServerConfiguration(self.server_xml)
        server_config.load()
        return server_config

    def get_password(self, name):

        # find password (e.g. internaldb, replicationdb) in password.conf
        if name in self.passwords:
            return self.passwords[name]

        # find password in keyring
        try:
            keyring = Keyring()
            key_name = self.name + '/' + name
            password = keyring.get_password(key_name=key_name)
            self.passwords[name] = password
            return password

        except subprocess.CalledProcessError:
            logger.info('Password unavailable in Keyring.')

        # prompt for password if not found
        password = getpass.getpass(prompt='Enter password for %s: ' % name)
        self.passwords[name] = password

        return password

    def get_token_password(self, token=pki.nssdb.INTERNAL_TOKEN_NAME):

        # determine the password name for the token
        if not pki.nssdb.normalize_token(token):
            name = pki.nssdb.INTERNAL_TOKEN_NAME

        else:
            name = 'hardware-%s' % token

        # find password in password.conf
        if name in self.passwords:
            return self.passwords[name]

        # find password in keyring
        try:
            keyring = Keyring()
            key_name = self.name + '/' + name
            password = keyring.get_password(key_name=key_name)
            self.passwords[name] = password
            return password

        except subprocess.CalledProcessError:
            logger.info('Password unavailable in Keyring.')

        # prompt for password if not found
        password = getpass.getpass(prompt='Enter password for %s: ' % token)
        self.passwords[name] = password

        return password

    @classmethod
    def instances(cls):

        instances = []

        if not os.path.exists(os.path.join(PKIServer.REGISTRY_DIR, 'tomcat')):
            return instances

        for instance_name in os.listdir(PKIServer.BASE_DIR):
            instance = pki.server.PKIInstance(instance_name)
            instance.load()
            instances.append(instance)

        return instances

    @staticmethod
    def split_cert_id(cert_id):
        """
        Utility method to return cert_tag and corresponding subsystem details from cert_id

        :param cert_id: Cert ID
        :type cert_id: str
        :returns: (subsystem_name, cert_tag)
        :rtype: (str, str)
        """
        if cert_id == 'sslserver' or cert_id == 'subsystem':
            subsystem_name = None
            cert_tag = cert_id
        else:
            parts = cert_id.split('_', 1)
            subsystem_name = parts[0]
            cert_tag = parts[1]
        return subsystem_name, cert_tag

    @staticmethod
    def setup_password_authentication(username, password, subsystem_name='ca', secure_port='8443'):
        """Return a PKIConnection, logged in using username and password."""
        connection = client.PKIConnection(
            'https', os.environ['HOSTNAME'], secure_port, subsystem_name)
        connection.authenticate(username, password)
        account_client = pki.account.AccountClient(connection)
        account_client.login()
        return connection

    @staticmethod
    def setup_cert_authentication(
            client_nssdb_pass, client_nssdb_pass_file, client_cert,
            client_nssdb, tmpdir, subsystem_name, secure_port='8443'):
        """
        Utility method to set up a secure authenticated connection with a
        subsystem of PKI Server through PKI client

        :param client_nssdb_pass: Client NSS db plain password
        :type client_nssdb_pass: str
        :param client_nssdb_pass_file: File containing client NSS db password
        :type client_nssdb_pass_file: str
        :param client_cert: Client Cert nick name
        :type client_cert: str
        :param client_nssdb: Client NSS db path
        :type client_nssdb: str
        :param tmpdir: Absolute path of temp dir to store p12 and pem files
        :type tmpdir: str
        :param subsystem_name: Name of the subsystem
        :type subsystem_name: str
        :param secure_port: Secure Port Number
        :type secure_port: str
        :return: Authenticated secure connection to PKI server
        """
        temp_auth_p12 = os.path.join(tmpdir, 'auth.p12')
        temp_auth_cert = os.path.join(tmpdir, 'auth.pem')

        if not client_cert:
            raise PKIServerException('Client cert nickname is required.')

        # Create a PKIConnection object that stores the details of subsystem.
        connection = client.PKIConnection('https', os.environ['HOSTNAME'], secure_port,
                                          subsystem_name)

        # Create a p12 file using
        # pk12util -o <p12 file name> -n <cert nick name> -d <NSS db path>
        # -W <pkcs12 password> -K <NSS db pass>
        cmd_generate_pk12 = [
            'pk12util',
            '-o', temp_auth_p12,
            '-n', client_cert,
            '-d', client_nssdb
        ]

        # The pem file used for authentication. Created from a p12 file using the
        # command:
        # openssl pkcs12 -in <p12_file_path> -out /tmp/auth.pem -nodes
        cmd_generate_pem = [
            'openssl',
            'pkcs12',
            '-in', temp_auth_p12,
            '-out', temp_auth_cert,
            '-nodes',

        ]

        if client_nssdb_pass_file:
            # Use the same password file for the generated pk12 file
            cmd_generate_pk12.extend(['-k', client_nssdb_pass_file,
                                      '-w', client_nssdb_pass_file])
            cmd_generate_pem.extend(['-passin', 'file:' + client_nssdb_pass_file])
        else:
            # Use the same password for the generated pk12 file
            cmd_generate_pk12.extend(['-K', client_nssdb_pass,
                                      '-W', client_nssdb_pass])
            cmd_generate_pem.extend(['-passin', 'pass:' + client_nssdb_pass])

        # Generate temp_auth_p12 file
        res_pk12 = subprocess.check_output(cmd_generate_pk12,
                                           stderr=subprocess.STDOUT).decode('utf-8')
        logger.debug('Result of pk12 generation: %s', res_pk12)

        # Use temp_auth_p12 generated in previous step to
        # to generate temp_auth_cert PEM file
        res_pem = subprocess.check_output(cmd_generate_pem,
                                          stderr=subprocess.STDOUT).decode('utf-8')
        logger.debug('Result of pem generation: %s', res_pem)

        # Bind the authentication with the connection object
        connection.set_authentication_cert(temp_auth_cert)

        return connection

    @staticmethod
    def renew_certificate(connection, output, serial):
        """
        Renew cert associated with the provided serial

        :param connection: Secure authenticated connection to PKI Server
        :type connection: PKIConnection
        :param output: Location of the new cert file to be written to
        :type output: str
        :param serial: Serial number of the cert to be renewed
        :type serial: str
        :return: None
        :rtype: None
        """

        # Instantiate the CertClient
        cert_client = pki.cert.CertClient(connection)

        inputs = dict()
        inputs['serial_num'] = serial

        # request: CertRequestInfo object for request generated.
        # cert: CertData object for certificate generated (if any)
        ret = cert_client.enroll_cert(inputs=inputs, profile_id='caManualRenewal')

        request_data = ret[0].request
        cert_data = ret[0].cert

        logger.info('Request ID: %s', request_data.request_id)
        logger.info('Request Status: %s', request_data.request_status)
        logger.debug('request_data: %s', request_data)
        logger.debug('cert_data: %s', cert_data)

        if not cert_data:
            raise PKIServerException('Unable to renew system '
                                     'certificate for serial: %s' % serial)

        # store cert_id for usage later
        cert_serial_number = cert_data.serial_number
        if not cert_serial_number:
            raise PKIServerException('Unable to retrieve serial number of '
                                     'renewed certificate.')

        logger.info('Serial Number: %s', cert_serial_number)
        logger.info('Issuer: %s', cert_data.issuer_dn)
        logger.info('Subject: %s', cert_data.subject_dn)
        logger.debug('Pretty Print:')
        logger.debug(cert_data.pretty_repr)

        new_cert_data = cert_client.get_cert(cert_serial_number=cert_serial_number)
        with open(output, 'w') as f:
            f.write(new_cert_data.encoded)

    @staticmethod
    def load_audit_events(filename):
        '''
        This method loads audit event info from audit-events.properties
        and return it as a map of objects.
        '''

        logger.info('Loading %s', filename)

        with open(filename) as f:
            lines = f.read().splitlines()

        events = {}

        event_pattern = re.compile(r'# Event: (\S+)')
        subsystems_pattern = re.compile(r'# Applicable subsystems: (.*)')
        enabled_pattern = re.compile(r'# Enabled by default: (.*)')

        event = None

        for line in lines:

            logger.debug('Parsing: %s', line)

            event_match = event_pattern.match(line)
            if event_match:

                name = event_match.group(1)
                logger.info('Found event %s', name)

                event = {}
                event['name'] = name
                event['subsystems'] = []
                event['enabled_by_default'] = False

                events[name] = event
                continue

            subsystems_match = subsystems_pattern.match(line)
            if subsystems_match:

                subsystems = subsystems_match.group(1)
                logger.info('Found subsystems %s', subsystems)

                subsystems = subsystems.replace(' ', '').split(',')
                event['subsystems'] = subsystems

            enabled_match = enabled_pattern.match(line)
            if enabled_match:

                enabled = enabled_match.group(1)
                logger.info('Found enabled by default %s', enabled)

                if enabled == 'Yes':
                    event['enabled_by_default'] = True
                else:
                    event['enabled_by_default'] = False

        logger.info('Events:')

        for name, event in events.items():
            logger.info('- %s', name)
            logger.info('  Applicable subsystems: %s', event['subsystems'])
            logger.info('  Enabled by default: %s', event['enabled_by_default'])

        return events


class ExternalCert(object):

    def __init__(self, nickname=None, token=None):
        self.nickname = nickname
        self.token = token


class ServerConfiguration(object):

    def __init__(self, filename):
        self.filename = filename
        self.document = etree.ElementTree()

    def load(self):
        self.document = etree.parse(self.filename, parser)

    def save(self):
        with open(self.filename, 'wb') as f:
            self.document.write(f, pretty_print=True, encoding='utf-8')

    def get_port(self):
        server = self.document.getroot()
        return server.get('port')

    def get_listeners(self):
        server = self.document.getroot()
        return server.findall('Listener')

    def get_listener(self, className):

        listeners = self.get_listeners()

        for listener in listeners:
            c = listener.get('className')
            if c == className:
                return listener

        raise KeyError('Listener not found: %s' % className)

    def create_listener(self, className):

        listener = etree.Element('Listener')
        listener.set('className', className)

        listeners = self.get_listeners()
        last_listener = listeners[-1]

        server = self.document.getroot()
        index = server.index(last_listener) + 1
        server.insert(index, listener)

        return listener

    def remove_listener(self, className):

        listener = self.get_listener(className)
        server = listener.getparent()
        server.remove(listener)

    def get_connectors(self):

        server = self.document.getroot()

        names = set()
        connectors = []
        counter = 0

        service = server.find('Service[@name="Catalina"]')

        for connector in service.findall('Connector'):

            name = connector.get('name')

            if not name:  # connector has no name, generate a temporary name

                while True:  # find unused name
                    counter += 1
                    name = 'Connector%d' % counter
                    if name not in names:
                        break

                connector.set('name', name)

            names.add(name)
            connectors.append(connector)

        return connectors

    def get_connector(self, name):

        connectors = self.get_connectors()

        for connector in connectors:
            n = connector.get('name')
            if n == name:
                return connector

        raise KeyError('Connector not found: %s' % name)

    def create_connector(self, name):

        connector = etree.Element('Connector')
        connector.set('name', name)

        server = self.document.getroot()

        service = server.find('Service[@name="Catalina"]')
        connectors = service.findall('Connector')
        last_connector = connectors[-1]

        index = service.index(last_connector) + 1
        service.insert(index, connector)

        return connector

    def remove_connector(self, name):

        connector = self.get_connector(name)
        service = connector.getparent()
        service.remove(connector)

    def get_sslhosts(self, connector):
        return list(connector.iter('SSLHostConfig'))

    def get_sslhost(self, connector, hostname='_default_'):
        sslhosts = self.get_sslhosts(connector)

        for sslhost in sslhosts:
            h = sslhost.get('hostName', '_default_')
            if h == hostname:
                return sslhost

        raise KeyError('SSL host not found: %s' % hostname)

    def create_sslhost(self, connector, hostname='_default_'):

        sslhost = etree.Element('SSLHostConfig')
        if hostname != '_default_':
            sslhost.set('hostName', hostname)

        connector.append(sslhost)

        return sslhost

    def remove_sslhost(self, connector, hostname):

        sslhost = self.get_sslhost(connector, hostname)
        connector.remove(sslhost)

    def get_sslcerts(self, sslhost):
        return list(sslhost.iter('Certificate'))

    def get_sslcert(self, sslhost, certType='UNDEFINED'):
        sslcerts = self.get_sslcerts(sslhost)

        for sslcert in sslcerts:
            t = sslcert.get('type', 'UNDEFINED')
            if t == certType:
                return sslcert

        raise KeyError('SSL certificate not found: %s' % certType)

    def create_sslcert(self, sslhost, certType):

        sslcert = etree.Element('Certificate')
        if certType != 'UNDEFINED':
            sslcert.set('type', certType)

        sslhost.append(sslcert)

        return sslcert

    def remove_sslcert(self, sslhost, certType):

        sslcert = self.get_sslcert(sslhost, certType)
        sslhost.remove(sslcert)


@functools.total_ordering
class PKIInstance(PKIServer):

    REGISTRY_FILE = PKIServer.SHARE_DIR + '/setup/pkidaemon_registry'
    UNIT_FILE = LIB_SYSTEMD_DIR + '/system/pki-tomcatd@.service'
    TARGET_WANTS = ETC_SYSTEMD_DIR + '/system/pki-tomcatd.target.wants'

    def __init__(self,
                 name,
                 instance_type='pki-tomcatd',
                 user='pkiuser',
                 group='pkiuser',
                 version=10):

        super(PKIInstance, self).__init__(
            name, instance_type, user, group)

        self.version = version

        self.external_certs = []
        self.subsystems = []

    def __eq__(self, other):
        if not isinstance(other, PKIInstance):
            return NotImplemented
        return (self.name == other.name and
                self.version == other.version)

    def __ne__(self, other):
        if not isinstance(other, PKIInstance):
            return NotImplemented
        return not self.__eq__(other)

    def __lt__(self, other):
        if not isinstance(other, PKIInstance):
            return NotImplemented
        return (self.name < other.name or
                self.version < other.version)

    def __hash__(self):
        return hash((self.name, self.version))

    @property
    def base_dir(self):
        if self.version < 10:
            return os.path.join(pki.BASE_DIR, self.name)
        return os.path.join(PKIServer.BASE_DIR, self.name)

    @property
    def conf_dir(self):
        return os.path.join(PKIServer.CONFIG_DIR, self.name)

    @property
    def log_dir(self):
        return os.path.join(PKIServer.LOG_DIR, self.name)

    @property
    def custom_policy(self):
        return os.path.join(self.conf_dir, 'custom.policy')

    @property
    def service_conf(self):
        return os.path.join(SYSCONFIG_DIR, self.name)

    @property
    def server_cert_nick_conf(self):
        return os.path.join(self.conf_dir, 'serverCertNick.conf')

    @property
    def banner_file(self):
        return os.path.join(self.conf_dir, 'banner.txt')

    @property
    def external_certs_conf(self):
        return os.path.join(self.conf_dir, 'external_certs.conf')

    @property
    def registry_dir(self):
        return os.path.join(PKIServer.REGISTRY_DIR, 'tomcat', self.name)

    @property
    def registry_file(self):
        return os.path.join(self.registry_dir, self.name)

    @property
    def unit_file(self):
        return PKIInstance.TARGET_WANTS + '/%s.service' % self.service_name

    def execute(self, command, jdb=False, as_current_user=False):

        if command == 'start':

            prefix = []

            # by default run pkidaemon as systemd user
            if not as_current_user:

                current_user = pwd.getpwuid(os.getuid()).pw_name

                # switch to systemd user if different from current user
                if current_user != self.user:
                    prefix.extend(['sudo', '-u', self.user])

            cmd = prefix + ['/usr/sbin/pki-server', 'upgrade', '--validate', self.name]
            logger.debug('Command: %s', ' '.join(cmd))

            cp = subprocess.run(cmd, env=self.config)
            cp.check_returncode()

            cmd = prefix + ['/usr/bin/pkidaemon', 'start', self.name]
            logger.debug('Command: %s', ' '.join(cmd))

            cp = subprocess.run(cmd, env=self.config)
            cp.check_returncode()

        return super(PKIInstance, self).execute(command, jdb=jdb, as_current_user=as_current_user)

    def create(self, force=False):

        super(PKIInstance, self).create(force=force)

        custom_policy = PKIServer.SHARE_DIR + '/server/conf/custom.policy'
        self.copy(custom_policy, self.custom_policy, force=force)

        conf_dir = os.path.join(self.base_dir, 'conf')
        self.symlink(self.conf_dir, conf_dir, force=force)

        self.makedirs(self.registry_dir, force=force)

        self.copyfile(
            PKIInstance.REGISTRY_FILE,
            self.registry_file,
            params={
                'PKI_WEB_SERVER_TYPE': 'tomcat',
                'PKI_USER': self.user,
                'PKI_GROUP': self.group,
                'PKI_INSTANCE_NAME': self.name,
                'PKI_INSTANCE_PATH': self.base_dir,
                'TOMCAT_PIDFILE': '/var/run/pki/tomcat/' + self.name + '.pid'
            })

        self.symlink(PKIInstance.UNIT_FILE, self.unit_file, force=force)

    def load(self):

        super(PKIInstance, self).load()

        # load UID and GID
        if os.path.exists(self.registry_file):

            logger.info('Loading instance registry: %s', self.registry_file)

            with open(self.registry_file, 'r') as registry:
                lines = registry.readlines()

            for line in lines:
                m = re.search('^PKI_USER=(.*)$', line)
                if m:
                    self.user = m.group(1)

                m = re.search('^PKI_GROUP=(.*)$', line)
                if m:
                    self.group = m.group(1)

        self.load_external_certs(self.external_certs_conf)

        # load subsystems
        if os.path.exists(self.registry_dir):
            for subsystem_name in os.listdir(self.registry_dir):
                if subsystem_name in SUBSYSTEM_TYPES:
                    subsystem = pki.server.subsystem.PKISubsystemFactory.create(
                        self, subsystem_name)
                    subsystem.load()
                    self.subsystems.append(subsystem)

    def load_external_certs(self, conf_file):
        for external_cert in PKIInstance.read_external_certs(conf_file):
            self.external_certs.append(external_cert)

    def remove(self, force=False):

        pki.util.unlink(self.unit_file, force=force)
        pki.util.remove(self.registry_file, force=force)
        pki.util.rmtree(self.registry_dir, force=force)

        conf_dir = os.path.join(self.base_dir, 'conf')
        pki.util.unlink(conf_dir, force=force)

        super(PKIInstance, self).remove(force=force)

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

    def open_nssdb(self, token=pki.nssdb.INTERNAL_TOKEN_NAME):
        return pki.nssdb.NSSDatabase(
            directory=self.nssdb_dir,
            token=token,
            password=self.get_token_password(token),
            internal_password=self.get_token_password(),
            passwords=self.passwords)

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
        with open(self.external_certs_conf, 'w') as f:
            indx = 0
            for cert in self.external_certs:
                f.write('%s.nickname=%s\n' % (str(indx), cert.nickname))
                f.write('%s.token=%s\n' % (str(indx), cert.token))
                indx += 1

    def export_external_certs(self, pkcs12_file, pkcs12_password_file,
                              append=False):
        for cert in self.external_certs:
            nickname = cert.nickname
            token = pki.nssdb.normalize_token(cert.token)

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
                    'pkcs12-cert-import',
                    '--pkcs12-file', pkcs12_file,
                    '--pkcs12-password-file', pkcs12_password_file,
                ])

                if append:
                    cmd.extend(['--append'])

                cmd.extend([
                    nickname
                ])

                logger.debug('Command: %s', ' '.join(cmd))

                subprocess.check_call(cmd)

            finally:
                shutil.rmtree(tmpdir)

    def get_sslserver_cert_nickname(self):
        with open(self.server_cert_nick_conf) as f:
            return f.readline().strip()

    def set_sslserver_cert_nickname(self, nickname, token=None):

        if pki.nssdb.normalize_token(token):
            nickname = token + ':' + nickname

        # update serverCertNick.conf
        with open(self.server_cert_nick_conf, 'w') as f:
            f.write(nickname + '\n')

        os.chown(self.server_cert_nick_conf, self.uid, self.gid)
        os.chmod(self.server_cert_nick_conf, 0o0660)

        # update server.xml
        server_config = self.get_server_config()
        connector = server_config.get_connector('Secure')
        sslhost = server_config.get_sslhost(connector)
        sslcert = server_config.get_sslcert(sslhost)
        sslcert.set('certificateKeyAlias', nickname)
        server_config.save()

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

    def banner_installed(self):
        return os.path.exists(self.banner_file)

    def get_banner(self):
        with io.open(self.banner_file) as f:
            return f.read().strip()

    def __repr__(self):
        if self.version == 9:
            return "Dogtag 9 " + self.name
        return self.name

    def cert_del(self, cert_id, remove_key=False):
        """
        Delete a cert from NSS db

        :param cert_id: Cert ID
        :type cert_id: str
        :param remove_key: Remove associate private key
        :type remove_key: bool
        """

        subsystem_name, cert_tag = PKIServer.split_cert_id(cert_id)

        if not subsystem_name:
            subsystem_name = self.subsystems[0].name

        subsystem = self.get_subsystem(subsystem_name)

        cert = subsystem.get_subsystem_cert(cert_tag)
        nssdb = self.open_nssdb()

        try:
            logger.debug('Removing %s certificate from NSS database from '
                         'subsystem %s in instance %s', cert_tag, subsystem.name, self.name)
            nssdb.remove_cert(
                nickname=cert['nickname'],
                token=cert['token'],
                remove_key=remove_key)
        finally:
            nssdb.close()

    def cert_update_config(self, cert_id, cert):
        """
        Update corresponding subsystem's CS.cfg with the new cert details
        passed.

        **Note:**
        *subsystem* param is ignored when `(cert_id == sslserver ||
        cert_id == subsystem)` since these 2 certs are used by all subsystems

        :param cert_id: Cert ID to update
        :type cert_id: str
        :param cert: Cert details to store in CS.cfg
        :type cert: dict
        :rtype: None
        :raises PKIServerException
        """
        # store cert data and request in CS.cfg
        if cert_id == 'sslserver' or cert_id == 'subsystem':
            # Update for all subsystems
            for subsystem in self.subsystems:
                subsystem.update_subsystem_cert(cert)
                subsystem.save()
        else:
            # Extract subsystem_name from cert_id
            subsystem_name = cert_id.split('_', 1)[0]

            # Load the corresponding subsystem
            subsystem = self.get_subsystem(subsystem_name)

            if subsystem:
                subsystem.update_subsystem_cert(cert)
                subsystem.save()
            else:
                raise PKIServerException('No subsystem can be loaded for %s in '
                                         'instance %s.' % (cert_id, self.name))

    @property
    def cert_folder(self):
        return os.path.join(pki.CONF_DIR, self.name, 'certs')

    def cert_file(self, cert_id):
        """Compute name of certificate under instance cert folder."""
        return os.path.join(self.cert_folder, cert_id + '.crt')

    def nssdb_import_cert(self, cert_id, cert_file=None):
        """
        Add cert from cert_file to NSS db with appropriate trust flags

        :param cert_id: Cert ID
        :type cert_id: str
        :param cert_file: Cert file to be imported into NSS db
        :type cert_file: str
        :return: New cert data loaded into nssdb
        :rtype: dict

        :raises PKIServerException
        """

        subsystem_name, cert_tag = PKIServer.split_cert_id(cert_id)

        if not subsystem_name:
            subsystem_name = self.subsystems[0].name

        subsystem = self.get_subsystem(subsystem_name)

        # audit and CA signing cert require special flags set in NSSDB
        trust_attributes = None
        if subsystem_name == 'ca' and cert_tag == 'signing':
            trust_attributes = 'CT,C,C'
        elif cert_tag == 'audit_signing':
            trust_attributes = ',,P'

        nssdb = self.open_nssdb()

        try:
            # If cert_file is not provided, load the cert from /etc/pki/certs/<cert_id>.crt
            if not cert_file:
                cert_file = self.cert_file(cert_id)

            if not os.path.isfile(cert_file):
                raise PKIServerException('%s does not exist.' % cert_file)

            cert = subsystem.get_subsystem_cert(cert_tag)

            logger.debug('Checking existing %s certificate in NSS database'
                         ' for subsystem: %s, instance: %s',
                         cert_tag, subsystem_name, self.name)

            if nssdb.get_cert(
                    nickname=cert['nickname'],
                    token=cert['token']):
                raise PKIServerException('Certificate already exists: %s in'
                                         'subsystem %s' % (cert_tag, self.name))

            logger.debug('Importing new %s certificate into NSS database'
                         ' for subsys %s, instance %s',
                         cert_tag, subsystem_name, self.name)

            nssdb.add_cert(
                nickname=cert['nickname'],
                token=cert['token'],
                cert_file=cert_file,
                trust_attributes=trust_attributes)

            logger.info('Updating CS.cfg with the new certificate')
            data = nssdb.get_cert(
                nickname=cert['nickname'],
                token=cert['token'],
                output_format='base64')

            # Store the cert data retrieved from NSS db
            cert['data'] = data

            return cert

        finally:
            nssdb.close()

    def cert_import(self, cert_id, cert_file=None):
        """
        Import cert from cert_file into NSS db with appropriate trust flags and update
        all corresponding subsystem's CS.cfg

        :param cert_id: Cert ID
        :type cert_id: str
        :param cert_file: Cert file to be imported into NSS db
        :type cert_file: str
        :return: None
        :rtype: None
        """
        updated_cert = self.nssdb_import_cert(cert_id, cert_file)
        self.cert_update_config(cert_id, updated_cert)

    def cert_create(
            self, cert_id=None,
            username=None, password=None,
            client_cert=None, client_nssdb=None,
            client_nssdb_pass=None, client_nssdb_pass_file=None,
            serial=None, temp_cert=False, renew=False, output=None,
            secure_port='8443'):
        """
        Create a new cert for the cert_id provided

        :param cert_id: New cert's ID
        :type cert_id: str
        :param username: Username (must also supply password)
        :type username: str
        :param password: Password (must also supply username)
        :type password: str
        :param client_cert: Client cert nickname
        :type client_cert: str
        :param client_nssdb: Path to nssdb
        :type client_nssdb: str
        :param client_nssdb_pass: Password to the nssdb
        :type client_nssdb_pass: str
        :param client_nssdb_pass_file: File containing nssdb's password
        :type client_nssdb_pass_file: str
        :param serial: Serial number of the cert to be renewed.  If creating
                       a temporary certificate (temp_cert == True), the serial
                       number will be reused.  If not supplied, the cert_id is
                       used to look it up.
        :type serial: str
        :param temp_cert: Whether new cert is a temporary cert
        :type temp_cert: bool
        :param renew: Whether to place a renewal request to ca
        :type renew: bool
        :param output: Path to which new cert needs to be written to
        :type output: str
        :param secure_port: Secure port number in case of renewing a certificate
        :type secure_port: str
        :return: None
        :rtype: None
        :raises PKIServerException

        Either supply both username and password, or supply
        client_nssdb and client_cert and
        (client_nssdb_pass or client_nssdb_pass_file).

        """
        nssdb = self.open_nssdb()
        tmpdir = tempfile.mkdtemp()
        subsystem = None  # used for system certs

        try:
            if cert_id:
                new_cert_file = output if output else self.cert_file(cert_id)

                subsystem_name, cert_tag = PKIServer.split_cert_id(cert_id)
                if not subsystem_name:
                    subsystem_name = self.subsystems[0].name
                subsystem = self.get_subsystem(subsystem_name)

                if serial is None:
                    # If admin doesn't provide a serial number, set the serial to
                    # the same serial number available in the nssdb
                    serial = subsystem.get_subsystem_cert(cert_tag)["serial_number"]

            else:
                if serial is None:
                    raise PKIServerException("Must provide either 'cert_id' or 'serial'")
                if output is None:
                    raise PKIServerException("Must provide 'output' when renewing by serial")
                if temp_cert:
                    raise PKIServerException("'temp_cert' must be used with 'cert_id'")
                new_cert_file = output

            if not os.path.exists(self.cert_folder):
                os.makedirs(self.cert_folder)

            if temp_cert:
                assert subsystem is not None  # temp_cert only supported with cert_id

                logger.info('Trying to create a new temp cert for %s.', cert_id)

                # Create Temp Cert and write it to new_cert_file
                subsystem.temp_cert_create(nssdb, tmpdir, cert_tag, serial, new_cert_file)

                logger.info('Temp cert for %s is available at %s.', cert_id, new_cert_file)

            else:
                # Create permanent certificate
                if not renew:
                    # TODO: Support rekey
                    raise PKIServerException('Rekey is not supported yet.')

                logger.info('Trying to setup a secure connection to CA subsystem.')
                if username and password:
                    connection = PKIServer.setup_password_authentication(
                        username, password, subsystem_name='ca', secure_port=secure_port)
                else:
                    if not client_cert:
                        raise PKIServerException('Client cert nick name required.')
                    if not client_nssdb_pass and not client_nssdb_pass_file:
                        raise PKIServerException('NSS db password required.')
                    connection = PKIServer.setup_cert_authentication(
                        client_nssdb_pass=client_nssdb_pass,
                        client_cert=client_cert,
                        client_nssdb_pass_file=client_nssdb_pass_file,
                        client_nssdb=client_nssdb,
                        tmpdir=tmpdir,
                        subsystem_name='ca',
                        secure_port=secure_port
                    )
                logger.info('Secure connection with CA is established.')

                logger.info('Placing cert creation request for serial: %s', serial)
                PKIServer.renew_certificate(connection, new_cert_file, serial)
                logger.info('New cert is available at: %s', new_cert_file)

        finally:
            nssdb.close()
            shutil.rmtree(tmpdir)


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


class PKIServerFactory(object):

    @classmethod
    def create(cls, name):
        '''
        This method creates PKIServer object based on the
        optional service type specified in the service name.
        The default type is 'pki-tomcatd'.

        :param name: Server name in this format: [<type>@]<name>[.service]
        '''

        if name.endswith('.service'):
            name = name[0:-8]

        parts = name.split('@')

        if len(parts) == 1:  # no type
            instance_type = 'pki-tomcatd'
            instance_name = name

        else:  # with type
            instance_type = parts[0]
            instance_name = parts[1]

        if instance_type == 'tomcat':
            return PKIServer(instance_name)

        if instance_type == 'pki-tomcatd':
            return PKIInstance(instance_name)

        raise Exception('Unsupported instance type: %s' % instance_type)
