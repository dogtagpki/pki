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
import io
import logging
import os
import pathlib
import pwd
import re
import shutil
import subprocess
import tempfile

from lxml import etree

import pki
import pki.cert
import pki.nssdb
import pki.util
import pki.server

SUBSYSTEM_TYPES = ['ca', 'kra', 'ocsp', 'tks', 'tps']

logger = logging.getLogger(__name__)

parser = etree.XMLParser(remove_blank_text=True)


@functools.total_ordering
class PKIInstance(pki.server.PKIServer):

    REGISTRY_FILE = pki.server.PKIServer.SHARE_DIR + '/setup/pkidaemon_registry'
    UNIT_FILE = pki.server.LIB_SYSTEMD_DIR + '/system/pki-tomcatd@.service'
    TARGET_WANTS = pki.server.ETC_SYSTEMD_DIR + '/system/pki-tomcatd.target.wants'

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

        self.default_root_doc_base = os.path.join(
            pki.SHARE_DIR,
            'server',
            'webapps',
            'ROOT')

        self.root_doc_base = os.path.join(self.webapps_dir, 'ROOT')

        self.default_root_xml = os.path.join(
            pki.SHARE_DIR,
            'server',
            'conf',
            'Catalina',
            'localhost',
            'ROOT.xml')

        self.root_xml = os.path.join(
            self.conf_dir,
            'Catalina',
            'localhost',
            'ROOT.xml')

        self.default_pki_doc_base = os.path.join(
            pki.SHARE_DIR,
            'server',
            'webapps',
            'pki')

        self.pki_doc_base = os.path.join(self.webapps_dir, 'pki')

        self.default_pki_xml = os.path.join(
            pki.SHARE_DIR,
            'server',
            'conf',
            'Catalina',
            'localhost',
            'pki.xml')

        self.pki_xml = os.path.join(
            self.conf_dir,
            'Catalina',
            'localhost',
            'pki.xml')

        self.with_maven_deps = False

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
        return os.path.join(pki.server.PKIServer.BASE_DIR, self.name)

    @property
    def conf_dir(self):
        return os.path.join(pki.server.PKIServer.CONFIG_DIR, self.name)

    @property
    def nssdb_dir(self):
        return os.path.join(self.conf_dir, 'alias')

    @property
    def log_dir(self):
        return os.path.join(pki.server.PKIServer.LOG_DIR, self.name)

    @property
    def service_conf(self):
        return os.path.join(pki.server.SYSCONFIG_DIR, self.name)

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
        return os.path.join(pki.server.PKIServer.REGISTRY_DIR, 'tomcat', self.name)

    @property
    def registry_file(self):
        return os.path.join(self.registry_dir, self.name)

    @property
    def unit_file(self):
        return PKIInstance.TARGET_WANTS + '/%s.service' % self.service_name

    def execute(self, command, jdb=False, as_current_user=False, gdb=False):

        if command == 'start':

            prefix = []

            # by default run pkidaemon as systemd user
            if not as_current_user:

                current_user = pwd.getpwuid(os.getuid()).pw_name

                # switch to systemd user if different from current user
                if current_user != self.user:
                    prefix.extend(['sudo', '-u', self.user])

            cmd = prefix + ['/usr/sbin/pki-server', 'upgrade', '--validate', self.name]

            if logger.isEnabledFor(logging.DEBUG):
                cmd.extend(['--debug'])

            elif logger.isEnabledFor(logging.INFO):
                cmd.extend(['-v'])

            logger.debug('Command: %s', ' '.join(cmd))

            subprocess.run(cmd, env=self.config, check=True)

            cmd = prefix + ['/usr/bin/pkidaemon', 'start', self.name]
            logger.debug('Command: %s', ' '.join(cmd))

            subprocess.run(cmd, env=self.config, check=True)

        return super(PKIInstance, self).execute(command, jdb=jdb,
                                                as_current_user=as_current_user,
                                                gdb=gdb)

    def create(self, force=False):

        super(PKIInstance, self).create(force=force)

        conf_link = os.path.join(self.base_dir, 'conf')
        self.symlink(self.conf_dir, conf_link, force=force)

        logs_link = os.path.join(self.base_dir, 'logs')
        self.symlink(self.log_dir, logs_link, force=force)

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

    def create_libs(self, force=False):

        if not self.with_maven_deps:
            super(PKIInstance, self).create_libs(force=force)
            return

        logger.info('Updating Maven dependencies')

        cmd = [
            'mvn',
            '-f', '/usr/share/pki/pom.xml',
            'dependency:resolve'
        ]

        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.check_call(cmd)

        repo_dir = '%s/.m2/repository' % pathlib.Path.home()

        pom_xml = '/usr/share/pki/pom.xml'
        logger.info('Loading %s', pom_xml)

        document = etree.parse(pom_xml, parser)
        project = document.getroot()

        xmlns = 'http://maven.apache.org/POM/4.0.0'

        groupId = project.findtext('{%s}groupId' % xmlns)
        logger.info('Group: %s', groupId)

        artifactId = project.findtext('{%s}artifactId' % xmlns)
        logger.info('Artifact: %s', artifactId)

        version = project.findtext('{%s}version' % xmlns)
        logger.info('Version: %s', version)

        dependencies = project.findall('{%s}dependencies/{%s}dependency' % (xmlns, xmlns))

        self.makedirs(self.lib_dir, force=force)
        self.makedirs(self.common_dir, force=force)
        self.makedirs(self.common_lib_dir, force=force)

        for dependency in dependencies:

            groupId = dependency.findtext('{%s}groupId' % xmlns)
            artifactId = dependency.findtext('{%s}artifactId' % xmlns)
            version = dependency.findtext('{%s}version' % xmlns)
            fileType = dependency.findtext('{%s}type' % xmlns, default='jar')

            groupDir = groupId.replace('.', '/')
            directory = os.path.join(repo_dir, groupDir, artifactId, version)
            filename = artifactId + '-' + version + '.' + fileType
            source = os.path.join(directory, filename)

            # install Maven libraries in common/lib except slf4j
            if artifactId in ['slf4j-api', 'slf4j-jdk14']:
                dest = os.path.join(self.lib_dir, filename)
            else:
                dest = os.path.join(self.common_lib_dir, filename)

            logger.info('Copying %s to %s', source, dest)
            self.copy(source, dest, force)

        common_lib_dir = os.path.join(pki.server.PKIServer.SHARE_DIR, 'server', 'common', 'lib')

        # install PKI libraries in common/lib
        for filename in [
                'jss4.jar',
                'ldapjdk.jar',
                'pki-cmsutil.jar',
                'pki-nsutil.jar',
                'pki-tomcat.jar',
                'symkey.jar',
                'tomcatjss.jar']:

            source = os.path.join(common_lib_dir, filename)
            dest = os.path.join(self.common_lib_dir, filename)

            logger.info('Linking %s to %s', dest, source)
            self.symlink(source, dest, force=force)

    def create_nssdb(self, force=False):

        super(PKIInstance, self).create_nssdb(force=force)

        nssdb_link = os.path.join(self.base_dir, 'alias')
        logger.info('Creating NSS database link: %s', nssdb_link)

        self.symlink(self.nssdb_dir, nssdb_link, force=force)

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
        for subsystem_name in SUBSYSTEM_TYPES:

            subsystem_dir = os.path.join(self.base_dir, subsystem_name)
            if not os.path.exists(subsystem_dir):
                continue

            subsystem = pki.server.subsystem.PKISubsystemFactory.create(self, subsystem_name)
            subsystem.load()
            self.subsystems.append(subsystem)

    def load_external_certs(self, conf_file):
        for external_cert in PKIInstance.read_external_certs(conf_file):
            self.external_certs.append(external_cert)

    def remove(self, force=False):

        pki.util.unlink(self.unit_file, force=force)
        pki.util.remove(self.registry_file, force=force)
        pki.util.rmtree(self.registry_dir, force=force)

        logs_link = os.path.join(self.base_dir, 'logs')
        pki.util.unlink(logs_link, force=force)

        conf_link = os.path.join(self.base_dir, 'conf')
        pki.util.unlink(conf_link, force=force)

        super(PKIInstance, self).remove(force=force)

    def remove_libs(self, force=False):

        # remove <instance>/common which is always a folder
        pki.util.rmtree(self.common_dir, force=force)

        # remove <instance>/lib which could be a link or a folder
        if os.path.islink(self.lib_dir):
            pki.util.unlink(self.lib_dir, force=force)
        else:
            pki.util.rmtree(self.lib_dir, force=force)

    def remove_nssdb(self, force=False):

        nssdb_link = os.path.join(self.base_dir, 'alias')
        logger.info('Removing NSS database link: %s', nssdb_link)

        pki.util.unlink(nssdb_link, force=force)

        super(PKIInstance, self).remove_nssdb(force=force)

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
                    tmp_certs[indx] = pki.server.ExternalCert()

                setattr(tmp_certs[indx], attr, value)
            external_certs = tmp_certs.values()
        return external_certs

    def external_cert_exists(self, nickname, token):
        for cert in self.external_certs:
            if cert.nickname == nickname and cert.token == token:
                return True
        return False

    def add_external_cert(self, nickname, token):
        if self.external_cert_exists(nickname, token):
            return
        self.external_certs.append(pki.server.ExternalCert(nickname, token))
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

        subsystem_name, cert_tag = pki.server.PKIServer.split_cert_id(cert_id)

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
        :raises pki.server.PKIServerException
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
                raise pki.server.PKIServerException(
                    'No subsystem can be loaded for %s in instance %s.' % (cert_id, self.name))

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

        :raises pki.server.PKIServerException
        """

        subsystem_name, cert_tag = pki.server.PKIServer.split_cert_id(cert_id)

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
                raise pki.server.PKIServerException('%s does not exist.' % cert_file)

            cert = subsystem.get_subsystem_cert(cert_tag)

            logger.debug('Checking existing %s certificate in NSS database'
                         ' for subsystem: %s, instance: %s',
                         cert_tag, subsystem_name, self.name)

            if nssdb.get_cert(
                    nickname=cert['nickname'],
                    token=cert['token']):
                raise pki.server.PKIServerException(
                    'Certificate already exists: %s in subsystem %s' % (cert_tag, self.name))

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
        :raises pki.server.PKIServerException

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

                subsystem_name, cert_tag = pki.server.PKIServer.split_cert_id(cert_id)
                if not subsystem_name:
                    subsystem_name = self.subsystems[0].name
                subsystem = self.get_subsystem(subsystem_name)

                if serial is None:
                    # If admin doesn't provide a serial number, set the serial to
                    # the same serial number available in the nssdb
                    serial = subsystem.get_subsystem_cert(cert_tag)["serial_number"]

            else:
                if serial is None:
                    raise pki.server.PKIServerException(
                        "Must provide either 'cert_id' or 'serial'")
                if output is None:
                    raise pki.server.PKIServerException(
                        "Must provide 'output' when renewing by serial")
                if temp_cert:
                    raise pki.server.PKIServerException(
                        "'temp_cert' must be used with 'cert_id'")
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
                    raise pki.server.PKIServerException('Rekey is not supported yet.')

                logger.info('Trying to setup a secure connection to CA subsystem.')
                if username and password:
                    connection = pki.server.PKIServer.setup_password_authentication(
                        username, password, subsystem_name='ca', secure_port=secure_port)
                else:
                    if not client_cert:
                        raise pki.server.PKIServerException('Client cert nick name required.')
                    if not client_nssdb_pass and not client_nssdb_pass_file:
                        raise pki.server.PKIServerException('NSS db password required.')
                    connection = pki.server.PKIServer.setup_cert_authentication(
                        client_nssdb_pass=client_nssdb_pass,
                        client_cert=client_cert,
                        client_nssdb_pass_file=client_nssdb_pass_file,
                        client_nssdb=client_nssdb,
                        tmpdir=tmpdir,
                        secure_port=secure_port
                    )
                logger.info('Secure connection with CA is established.')

                logger.info('Placing cert creation request for serial: %s', serial)
                pki.server.PKIServer.renew_certificate(connection, new_cert_file, serial)
                logger.info('New cert is available at: %s', new_cert_file)

        finally:
            nssdb.close()
            shutil.rmtree(tmpdir)

    @classmethod
    def instances(cls):

        instances = []

        if not os.path.exists(os.path.join(pki.server.PKIServer.REGISTRY_DIR, 'tomcat')):
            return instances

        for instance_name in os.listdir(pki.server.PKIServer.BASE_DIR):
            instance = PKIInstance(instance_name)
            instance.load()
            instances.append(instance)

        return instances


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
            return pki.server.PKIServer(instance_name)

        if instance_type == 'pki-tomcatd':
            return PKIInstance(instance_name)

        raise Exception('Unsupported instance type: %s' % instance_type)
