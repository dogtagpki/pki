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
import json
import logging
import os
import pwd
import re
import shutil
import socket
import subprocess
import tempfile
import xml.etree.ElementTree as ET

import ldap
import ldap.filter

import pki
import pki.nssdb
import pki.util
import pki.server
import pki.system

SELFTEST_CRITICAL = 'critical'

logger = logging.getLogger(__name__)


@functools.total_ordering
class PKISubsystem(object):

    def __init__(self, instance, subsystem_name):

        self.instance = instance
        self.name = subsystem_name  # e.g. ca, kra

        if instance.version >= 10:
            self.base_dir = os.path.join(self.instance.base_dir, self.name)
        else:
            self.base_dir = instance.base_dir

        self.conf_dir = os.path.join(self.base_dir, 'conf')
        self.cs_conf = os.path.join(self.conf_dir, 'CS.cfg')
        self.registry_conf = os.path.join(self.conf_dir, 'registry.cfg')

        self.config = {}
        self.registry = {}

        self.type = None  # e.g. CA, KRA
        self.prefix = None  # e.g. ca, kra

        self.default_doc_base = os.path.join(
            pki.SHARE_DIR,
            self.name,
            'webapps',
            self.name)

        self.doc_base = os.path.join(instance.webapps_dir, self.name)

        self.default_context_xml = os.path.join(
            pki.SHARE_DIR,
            self.name,
            'conf',
            'Catalina',
            'localhost',
            self.name + '.xml')

        self.context_xml = os.path.join(
            instance.conf_dir,
            'Catalina',
            'localhost',
            self.name + '.xml')

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

        if os.path.exists(self.cs_conf):
            logger.info('Loading subsystem config: %s', self.cs_conf)
            pki.util.load_properties(self.cs_conf, self.config)

            self.type = self.config['cs.type']
            self.prefix = self.type.lower()

        self.registry.clear()

        if os.path.exists(self.registry_conf):
            logger.info('Loading subsystem registry: %s', self.registry_conf)
            pki.util.load_properties(self.registry_conf, self.registry)

    def find_system_certs(self):

        cert_ids = self.config['%s.cert.list' % self.name].split(',')

        for cert_id in cert_ids:
            yield self.get_subsystem_cert(cert_id)

    def get_cert_infos(self):

        cert_ids = self.config['%s.cert.list' % self.name].split(',')

        certs = []

        for cert_id in cert_ids:
            cert = self.get_cert_info(cert_id)
            certs.append(cert)

        return certs

    def get_subsystem_cert(self, cert_id):

        cert = self.get_cert_info(cert_id)
        if not cert['nickname']:
            return cert

        cert_info = self.get_nssdb_cert_info(cert_id)
        if cert_info:
            cert.update(cert_info)

        return cert

    def get_cert_info(self, cert_id):

        logger.info('Getting %s cert info from CS.cfg', cert_id)

        nickname = self.config.get('%s.%s.nickname' % (self.name, cert_id))
        token = self.config.get('%s.%s.tokenname' % (self.name, cert_id))

        cert = {}
        cert['id'] = cert_id
        cert['nickname'] = nickname
        cert['token'] = token
        cert['data'] = self.config.get(
            '%s.%s.cert' % (self.name, cert_id), None)
        cert['request'] = self.config.get(
            '%s.%s.certreq' % (self.name, cert_id), None)
        cert['certusage'] = self.config.get(
            '%s.cert.%s.certusage' % (self.name, cert_id), None)

        return cert

    def get_nssdb_cert_info(self, cert_id):

        logger.info('Getting %s cert info from NSS database', cert_id)

        nickname = self.config.get('%s.%s.nickname' % (self.name, cert_id))
        token = self.config.get('%s.%s.tokenname' % (self.name, cert_id))

        nssdb = self.instance.open_nssdb()
        try:
            return nssdb.get_cert_info(nickname, token=token)
        finally:
            nssdb.close()

    def update_subsystem_cert(self, cert):
        cert_id = cert['id']
        self.config['%s.%s.nickname' % (self.name, cert_id)] = cert.get('nickname')
        self.config['%s.%s.tokenname' % (self.name, cert_id)] = cert.get('token')
        self.config['%s.%s.cert' % (self.name, cert_id)] = cert.get('data')
        self.config['%s.%s.certreq' % (self.name, cert_id)] = cert.get('request')

    def validate_system_cert(self, cert_id=None):

        cmd = ['pki-server', 'subsystem-cert-validate',
               '-i', self.instance.name,
               self.name]

        if cert_id:
            cmd.append(cert_id)

        logger.debug('Command: %s', ' '.join(cmd))

        subprocess.check_output(
            cmd,
            stderr=subprocess.STDOUT)

    def export_system_cert(
            self,
            cert_id,
            pkcs12_file,
            pkcs12_password_file,
            no_key=False,
            append=False):

        cert = self.get_subsystem_cert(cert_id)
        nickname = cert['nickname']
        token = pki.nssdb.normalize_token(cert['token'])

        if token:
            nickname = token + ':' + nickname

        tmpdir = tempfile.mkdtemp()

        try:
            # add the certificate, key, and chain
            cmd = [
                'pki',
                '-d', self.instance.nssdb_dir,
                '-f', self.instance.password_conf
            ]

            cmd.extend([
                'pkcs12-cert-import',
                '--pkcs12-file', pkcs12_file,
                '--pkcs12-password-file', pkcs12_password_file,
            ])

            if no_key:
                cmd.extend(['--no-key'])

            if append:
                cmd.extend(['--append'])

            if logger.isEnabledFor(logging.DEBUG):
                cmd.append('--debug')

            elif logger.isEnabledFor(logging.INFO):
                cmd.append('-v')

            cmd.extend([
                nickname
            ])

            logger.debug('Command: %s', ' '.join(cmd))

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
        token = pki.nssdb.normalize_token(cert['token'])

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

            logger.debug('Command: %s', ' '.join(cmd))

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

            logger.debug('Command: %s', ' '.join(cmd))

            subprocess.check_call(cmd)

        finally:
            shutil.rmtree(tmpdir)

    def save(self):

        logger.info('Storing subsystem config: %s', self.cs_conf)
        self.instance.store_properties(self.cs_conf, self.config)

        logger.info('Storing registry config: %s', self.registry_conf)
        self.instance.store_properties(self.registry_conf, self.registry)

    def is_valid(self):
        return os.path.exists(self.conf_dir)

    def validate(self):
        if not self.is_valid():
            raise pki.PKIException(
                'Invalid subsystem: ' + self.__repr__(),
                None, self.instance)

    def is_enabled(self):
        return self.instance.is_deployed(self.name)

    def is_ready(self, secure_connection=True, timeout=None):

        server_config = self.instance.get_server_config()

        if secure_connection:
            protocol = 'https'
            port = server_config.get_secure_port()

        else:
            protocol = 'http'
            port = server_config.get_unsecure_port()

        connection = pki.client.PKIConnection(
            protocol=protocol,
            hostname=socket.getfqdn(),
            port=port,
            accept='application/xml',
            trust_env=False)

        client = pki.system.SystemStatusClient(connection, subsystem=self.name)
        response = client.get_status(timeout=timeout)

        root = ET.fromstring(response)
        status = root.findtext('Status')

        logger.info('Subsystem status: %s', status)
        return status == 'running'

    def enable(self):
        if os.path.exists(self.doc_base):
            # deploy custom subsystem if exists
            doc_base = self.doc_base

        else:
            # otherwise deploy default subsystem directly from
            # /usr/share/pki/<subsystem>/webapps/<subsystem>
            doc_base = None

        self.instance.deploy_webapp(self.name, self.default_context_xml, doc_base)

    def disable(self):
        self.instance.undeploy_webapp(self.name)

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

        connection = pki.server.PKIDatabaseConnection(url)

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
                nssdb_password=self.instance.get_token_password(
                    pki.nssdb.INTERNAL_TOKEN_NAME)
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

    def enable_audit_event(self, event_name):

        if not event_name:
            raise ValueError("Please specify the Event name")

        if event_name not in self.get_audit_events():
            raise pki.server.PKIServerException('Invalid audit event: %s' % event_name)

        value = self.config['log.instance.SignedAudit.events']
        events = set(value.replace(' ', '').split(','))

        if event_name in events:
            return False

        events.add(event_name)
        event_list = ','.join(sorted(events))
        self.config['log.instance.SignedAudit.events'] = event_list

        return True

    def update_audit_event_filter(self, event_name, event_filter):

        if not event_name:
            raise ValueError("Please specify the Event name")

        if event_name not in self.get_audit_events():
            raise pki.server.PKIServerException('Invalid audit event: %s' % event_name)

        name = 'log.instance.SignedAudit.filters.%s' % event_name

        if event_filter:
            self.config[name] = event_filter
        else:
            self.config.pop(name, None)

    def disable_audit_event(self, event_name):

        if not event_name:
            raise ValueError("Please specify the Event name")

        if event_name not in self.get_audit_events():
            raise pki.server.PKIServerException('Invalid audit event: %s' % event_name)

        value = self.config['log.instance.SignedAudit.events']
        events = set(value.replace(' ', '').split(','))

        if event_name not in events:
            return False

        events.remove(event_name)
        event_list = ','.join(sorted(events))
        self.config['log.instance.SignedAudit.events'] = event_list

        return True

    def find_audit_event_configs(self, enabled=None, enabled_by_default=None):
        '''
        This method returns current audit configuration based on the specified
        filters.
        '''

        events = self.get_audit_events()
        enabled_events = set(self.get_enabled_audit_events())

        # apply "enabled_by_default" filter
        if enabled_by_default is None:
            # return all events
            names = set(events.keys())

        else:
            # return events enabled by default
            names = set()
            for name, event in events.items():
                if enabled_by_default is event['enabled_by_default']:
                    names.add(name)

        # apply "enabled" filter
        if enabled is None:
            # return all events
            pass

        elif enabled:  # enabled == True
            # return currently enabled events
            names = names.intersection(enabled_events)

        else:  # enabled == False
            # return currently disabled events
            names = names.difference(enabled_events)

        results = []

        # get event properties
        for name in sorted(names):
            event = {}
            event['name'] = name
            event['enabled'] = name in enabled_events
            event['filter'] = self.config.get('log.instance.SignedAudit.filters.%s' % name)
            results.append(event)

        return results

    def get_audit_event_config(self, name):

        if name not in self.get_audit_events():
            raise pki.server.PKIServerException('Invalid audit event: %s' % name)

        enabled_event_names = self.get_enabled_audit_events()

        event = {}
        event['name'] = name
        event['enabled'] = name in enabled_event_names
        event['filter'] = self.config.get('log.instance.SignedAudit.filters.%s' % name)

        return event

    def get_audit_events(self):
        '''
        This method returns audit events applicable to this subsystem
        as a map of objects.
        '''

        # get the list of audit events from audit-events.properties

        tmpdir = tempfile.mkdtemp()

        try:
            # export audit-events.properties from cmsbundle.jar
            cmsbundle_jar = \
                '/usr/share/pki/%s/webapps/%s/WEB-INF/lib/pki-cmsbundle.jar' \
                % (self.name, self.name)

            cmd = [
                'jar',
                'xf',
                cmsbundle_jar,
                'audit-events.properties'
            ]

            logger.debug('Command: %s', ' '.join(cmd))

            subprocess.check_output(
                cmd,
                cwd=tmpdir,
                stderr=subprocess.STDOUT)

            # load audit-events.properties
            filename = os.path.join(tmpdir, 'audit-events.properties')
            events = pki.server.PKIServer.load_audit_events(filename)

        finally:
            shutil.rmtree(tmpdir)

        # get audit events for this subsystem
        results = {}
        subsystem = self.name.upper()

        for name, event in events.items():
            if subsystem in event['subsystems']:
                logger.info('Returning %s', name)
                results[name] = event

        return results

    def get_enabled_audit_events(self):

        # parse enabled audit events
        value = self.config['log.instance.SignedAudit.events']
        events = set(value.replace(' ', '').split(','))

        return sorted(events)

    def get_audit_log_dir(self):

        current_file_path = self.config['log.instance.SignedAudit.fileName']
        return os.path.dirname(current_file_path)

    def get_audit_log_files(self):

        current_file_path = self.config['log.instance.SignedAudit.fileName']
        (log_dir, current_file) = os.path.split(current_file_path)

        # sort log files based on timestamp
        files = [f for f in os.listdir(log_dir) if f != current_file]
        files.sort()

        # put the current log file at the end
        files.append(current_file)

        return files

    def __repr__(self):
        return str(self.instance) + '/' + self.name

    def get_startup_tests(self):
        # Split the line 'selftest.container.selftests.startup'
        available_tests = self.config['selftests.container.order.startup'].split(',')
        target_tests = {}
        for testInfo in available_tests:
            temp = testInfo.split(':')
            test_name = temp[0].strip()

            target_tests[test_name] = False
            # Check if there is some test level mentioned after colon
            if len(temp) > 1:
                # Check if the test is critical
                target_tests[test_name] = temp[1].strip() == SELFTEST_CRITICAL

        return target_tests

    def set_startup_tests(self, target_tests):
        # Remove unnecessary space, curly braces
        self.config['selftests.container.order.startup'] = ", " \
            .join([(key + ':' + SELFTEST_CRITICAL if val else key)
                   for key, val in target_tests.items()])

    def set_startup_test_criticality(self, critical, test=None):
        # Assume action to be taken on ALL available startup tests
        target_tests = self.get_startup_tests()

        # If just one test is provided, take action on ONLY that test
        if test:
            if test not in target_tests:
                raise pki.server.PKIServerException(
                    'No such self test available for %s' % self.name)
            target_tests[test] = critical
        else:
            for testID in target_tests:
                target_tests[testID] = critical
        self.set_startup_tests(target_tests)

    def setup_temp_renewal(self, tmpdir, cert_tag):
        """
        Retrieve CA's cert, Subject Key Identifier (SKI aka AKI) and CSR for
        the *cert_id* provided

        :param tmpdir: Path to temp dir to write cert's .csr and CA's .crt file
        :type tmpdir: str
        :param cert_tag: Cert for which CSR is requested
        :type cert_tag: str
        :return: (ca_signing_cert, aki, csr_file)
        """

        csr_file = os.path.join(tmpdir, cert_tag + '.csr')
        ca_cert_file = os.path.join(tmpdir, 'ca_certificate.crt')

        logger.debug('Exporting CSR for %s cert', cert_tag)

        # Retrieve CSR for cert_id
        cert_request = self.get_subsystem_cert(cert_tag).get('request')
        if cert_request is None:
            raise pki.server.PKIServerException('Unable to find CSR for %s cert' % cert_tag)

        logger.debug('Retrieved CSR: %s', cert_request)

        csr_data = pki.nssdb.convert_csr(cert_request, 'base64', 'pem')
        with open(csr_file, 'w') as f:
            f.write(csr_data)
        logger.info('CSR for %s has been written to %s', cert_tag, csr_file)

        logger.debug('Extracting SKI from CA cert')
        # TODO: Support remote CA.

        # Retrieve Subject Key Identifier from CA cert
        ca_signing_cert = self.instance.get_subsystem('ca').get_subsystem_cert('signing')

        ca_cert_data = ca_signing_cert.get('data')
        if ca_cert_data is None:
            raise pki.server.PKIServerException(
                'Unable to find certificate data for CA signing certificate.')

        logger.debug('Retrieved CA cert details: %s', ca_cert_data)

        ca_cert = pki.nssdb.convert_cert(ca_cert_data, 'base64', 'pem')
        with open(ca_cert_file, 'w') as f:
            f.write(ca_cert)
        logger.info('CA cert written to %s', ca_cert_file)

        ca_cert_retrieve_cmd = [
            'openssl',
            'x509',
            '-in', ca_cert_file,
            '-noout',
            '-text'
        ]

        logger.debug('Command: %s', ' '.join(ca_cert_retrieve_cmd))
        ca_cert_details = subprocess.check_output(ca_cert_retrieve_cmd).decode('utf-8')

        aki = re.search(r'Subject Key Identifier.*\n.*?(.*?)\n', ca_cert_details).group(1)

        # Add 0x to represent this as a Hex
        aki = '0x' + aki.strip().replace(':', '')
        logger.info('AKI: %s', aki)

        return ca_signing_cert, aki, csr_file

    def temp_cert_create(self, nssdb, tmpdir, cert_tag, serial, new_cert_file):
        """
        Generates temp cert with validity of 3 months by default

        **Note**: Currently, supports only *sslserver* cert

        :param nssdb: NSS db instance
        :type nssdb: NSSDatabase
        :param tmpdir: Path to temp dir to write cert's csr and ca's cert file
        :type tmpdir: str
        :param cert_tag: Cert for which temp cert needs to be created
        :type cert_tag: str
        :param serial: Serial number to be assigned to new cert
        :type serial: str
        :param new_cert_file: Path where the new temp cert needs to be written to
        :type new_cert_file: str
        :return: None
        :rtype: None
        """
        logger.info('Generate temp SSL certificate')

        if cert_tag != 'sslserver':
            raise pki.server.PKIServerException(
                'Temp cert for %s is not supported yet.' % cert_tag)

        ca_signing_cert, aki, csr_file = \
            self.setup_temp_renewal(tmpdir=tmpdir, cert_tag=cert_tag)

        # --keyUsage
        key_usage_ext = {
            'digitalSignature': True,
            'nonRepudiation': True,
            'keyEncipherment': True,
            'dataEncipherment': True,
            'critical': True
        }

        # -3
        aki_ext = {
            'auth_key_id': aki
        }

        # --extKeyUsage
        ext_key_usage_ext = {
            'serverAuth': True
        }

        logger.debug('Creating temp cert')

        rc = nssdb.create_cert(
            issuer=ca_signing_cert['nickname'],
            request_file=csr_file,
            cert_file=new_cert_file,
            serial=serial,
            key_usage_ext=key_usage_ext,
            aki_ext=aki_ext,
            ext_key_usage_ext=ext_key_usage_ext)
        if rc:
            raise pki.server.PKIServerException(
                'Failed to generate CA-signed temp SSL certificate. RC: %d' % rc)

    def get_db_config(self):
        """Return DB configuration as dict."""
        shortkeys = [
            'ldapconn.host', 'ldapconn.port', 'ldapconn.secureConn',
            'ldapauth.authtype', 'ldapauth.bindDN', 'ldapauth.bindPWPrompt',
            'ldapauth.clientCertNickname', 'database', 'basedn',
            'multipleSuffix.enable', 'maxConns', 'minConns',
        ]
        db_keys = ['internaldb.{}'.format(x) for x in shortkeys]
        return {k: v for k, v in self.config.items() if k in db_keys}

    def set_db_config(self, new_config):
        """Write the dict of DB configuration to subsystem config.

        Right now this does not perform sanity checks; it just calls
        ``update`` on the config dict.  Fields that are ``None`` will
        overwrite the existing key.  So if you do not want to reset a
        field, ensure the key is absent.

        Likewise, extraneous fields will be set into the main config.

        """
        self.config.update(new_config)

    def import_ldif(self, bind_dn, bind_password, filename):

        # TODO(alee) re-implement this using open_database
        host = self.config['internaldb.ldapconn.host']
        port = self.config['internaldb.ldapconn.port']
        secure = self.config['internaldb.ldapconn.secureConn']

        cmd = [
            'ldapmodify',
            '-c',
            '-D', bind_dn,
            '-w', bind_password,
            '-h', host,
            '-p', port,
            '-f', filename
        ]

        if secure.lower() == 'true':
            cmd.append('-Z')

        logger.debug('Command: %s', ' '.join(cmd))
        subprocess.check_call(cmd)

    def init_database(
            self,
            setup_schema=False,
            create_database=False,
            create_base=False,
            create_containers=False,
            rebuild_indexes=False,
            setup_db_manager=False,
            setup_vlv_indexes=False,
            as_current_user=False):

        cmd = [self.name + '-db-init']

        if setup_schema:
            cmd.append('--setup-schema')

        if create_database:
            cmd.append('--create-database')

        if create_base:
            cmd.append('--create-base')

        if create_containers:
            cmd.append('--create-containers')

        if rebuild_indexes:
            cmd.append('--rebuild-indexes')

        if setup_db_manager:
            cmd.append('--setup-db-manager')

        if setup_vlv_indexes:
            cmd.append('--setup-vlv-indexes')

        if logger.isEnabledFor(logging.DEBUG):
            cmd.append('--debug')

        elif logger.isEnabledFor(logging.INFO):
            cmd.append('--verbose')

        self.run(cmd, as_current_user=as_current_user)

    def empty_database(self, force=False, as_current_user=False):

        cmd = [self.name + '-db-empty']

        if force:
            cmd.append('--force')

        if logger.isEnabledFor(logging.DEBUG):
            cmd.append('--debug')

        elif logger.isEnabledFor(logging.INFO):
            cmd.append('--verbose')

        self.run(cmd, as_current_user=as_current_user)

    def remove_database(self, force=False, as_current_user=False):

        cmd = [self.name + '-db-remove']

        if force:
            cmd.append('--force')

        if logger.isEnabledFor(logging.DEBUG):
            cmd.append('--debug')

        elif logger.isEnabledFor(logging.INFO):
            cmd.append('--verbose')

        self.run(cmd, as_current_user=as_current_user)

    def request_range(self, master_url, range_type, install_token):

        cmd = [
            'pki',
            '-d', self.instance.nssdb_dir,
            '-U', master_url,
            '%s-range-request' % self.name,
            range_type,
            '--session', install_token.token,
            '--output-format', 'json'
        ]

        if logger.isEnabledFor(logging.DEBUG):
            cmd.append('--debug')

        elif logger.isEnabledFor(logging.INFO):
            cmd.append('--verbose')

        logger.debug('Command: %s', ' '.join(cmd))
        output = subprocess.check_output(cmd)

        return json.loads(output.decode())

    def update_ranges(self, master_url, install_token):

        logger.info('Updating request ID range')

        request_range = self.request_range(master_url, 'request', install_token)
        self.config['dbs.beginRequestNumber'] = request_range['begin']
        self.config['dbs.endRequestNumber'] = request_range['end']

        logger.info('Updating serial number range')

        serial_range = self.request_range(master_url, 'serialNo', install_token)
        self.config['dbs.beginSerialNumber'] = serial_range['begin']
        self.config['dbs.endSerialNumber'] = serial_range['end']

        logger.info('Updating replica ID range')

        replica_range = self.request_range(master_url, 'replicaId', install_token)
        self.config['dbs.beginReplicaNumber'] = replica_range['begin']
        self.config['dbs.endReplicaNumber'] = replica_range['end']

        self.config['dbs.enableSerialManagement'] = 'true'

        self.save()

    def retrieve_config(self, master_url, names, substores, install_token):

        cmd = [
            'pki',
            '-d', self.instance.nssdb_dir,
            '-U', master_url,
            '%s-config-export' % self.name,
            '--names', ','.join(names),
            '--substores', ','.join(substores),
            '--session', install_token.token,
            '--output-format', 'json'
        ]

        if logger.isEnabledFor(logging.DEBUG):
            cmd.append('--debug')

        elif logger.isEnabledFor(logging.INFO):
            cmd.append('--verbose')

        logger.debug('Command: %s', ' '.join(cmd))
        output = subprocess.check_output(cmd)

        return json.loads(output.decode())

    def update_config(self, master_url, install_token):

        logger.info('Updating configuration')

        names = [
            'internaldb.ldapauth.password',
            'internaldb.replication.password'
        ]

        substores = [
            'internaldb',
            'internaldb.ldapauth',
            'internaldb.ldapconn'
        ]

        tags = self.config['preop.cert.list'].split(',')
        for tag in tags:
            if tag == 'sslserver':
                continue
            substores.append(self.name + '.' + tag)

        if self.name == 'ca':
            substores.append('ca.connector.KRA')
        else:
            names.append('cloning.ca.type')

        config = self.retrieve_config(master_url, names, substores, install_token)
        properties = config['properties']

        for name in properties:

            if name.startswith('internaldb'):
                new_name = 'preop.internaldb.master' + name[10:]

            elif name.startswith('cloning.ca'):
                new_name = 'preop.ca' + name[10:]

            elif name.startswith('cloning'):
                new_name = 'preop.cert' + name[7:]

            else:
                new_name = name

            value = properties.get(name)
            self.config[new_name] = value

        self.config['preop.clone.configuration'] = 'true'

        self.save()

        master_hostname = self.config['preop.internaldb.master.ldapconn.host']
        master_port = self.config['preop.internaldb.master.ldapconn.port']

        replica_hostname = self.config['internaldb.ldapconn.host']
        replica_port = self.config['internaldb.ldapconn.port']

        if master_hostname == replica_hostname and \
                master_port == replica_port:
            raise Exception('Master and replica must not share LDAP database')

    def run(self, args, as_current_user=False):

        java_home = self.instance.config['JAVA_HOME']
        java_opts = self.instance.config['JAVA_OPTS']

        classpath = [
            pki.server.Tomcat.SHARE_DIR + '/bin/tomcat-juli.jar',
            '/usr/share/java/tomcat-servlet-api.jar',
            pki.server.PKIServer.SHARE_DIR + '/' +
            self.name + '/webapps/' + self.name + '/WEB-INF/lib/*',
            self.instance.common_lib_dir + '/*',
            pki.server.PKIServer.SHARE_DIR + '/lib/*'
        ]

        cmd = []

        # by default run command as systemd user
        if not as_current_user:

            # switch to systemd user if different from current user
            username = pwd.getpwuid(os.getuid()).pw_name
            if username != self.instance.user:
                cmd.extend(['sudo', '-u', self.instance.user])

        cmd.extend([
            java_home + '/bin/java',
            '-classpath', os.pathsep.join(classpath),
            '-Djavax.sql.DataSource.Factory=org.apache.commons.dbcp.BasicDataSourceFactory',
            '-Dcatalina.base=' + self.instance.base_dir,
            '-Dcatalina.home=' + pki.server.Tomcat.SHARE_DIR,
            '-Djava.endorsed.dirs=',
            '-Djava.io.tmpdir=' + self.instance.temp_dir,
            '-Djava.util.logging.config.file=' + self.instance.logging_properties,
            '-Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager'
        ])

        if java_opts:
            cmd.extend(java_opts.split(' '))

        cmd.extend(['org.dogtagpki.server.cli.PKIServerCLI'])

        cmd.extend(args)

        logger.debug('Command: %s', ' '.join(cmd))

        try:
            subprocess.run(cmd, check=True)

        except KeyboardInterrupt:
            logger.debug('Server stopped')


class CASubsystem(PKISubsystem):

    def __init__(self, instance):
        super(CASubsystem, self).__init__(instance, 'ca')

    def get_profile_configs(self):

        profiles_dir = os.path.join(self.base_dir, 'profiles')

        profile_configs = []
        for root, _, files in os.walk(profiles_dir):
            for filename in files:
                profile_configs.append(os.path.join(root, filename))

        return profile_configs

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
        request['id'] = attrs['cn'][0].decode('utf-8')
        request['type'] = attrs['requestType'][0].decode('utf-8')
        request['status'] = attrs['requestState'][0].decode('utf-8')
        request['request'] = attrs['extdata-cert--005frequest'][0] \
            .decode('utf-8')

        return request


class KRASubsystem(PKISubsystem):

    def __init__(self, instance):
        super(KRASubsystem, self).__init__(instance, 'kra')


class OCSPSubsystem(PKISubsystem):

    def __init__(self, instance):
        super(OCSPSubsystem, self).__init__(instance, 'ocsp')


class TKSSubsystem(PKISubsystem):

    def __init__(self, instance):
        super(TKSSubsystem, self).__init__(instance, 'tks')


class TPSSubsystem(PKISubsystem):

    def __init__(self, instance):
        super(TPSSubsystem, self).__init__(instance, 'tps')


class PKISubsystemFactory(object):

    @classmethod
    def create(cls, instance, name):

        if name == 'ca':
            return CASubsystem(instance)

        if name == 'kra':
            return KRASubsystem(instance)

        if name == 'ocsp':
            return OCSPSubsystem(instance)

        if name == 'tks':
            return TKSSubsystem(instance)

        if name == 'tps':
            return TPSSubsystem(instance)

        return PKISubsystem(instance, name)
