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

import codecs
import functools
import getpass
import grp
import io
import logging
import operator
import os
import pwd
import re
import shutil
import subprocess
import tempfile

import ldap
import ldap.filter
import pki
import pki.account
import pki.cert
import pki.client as client
import pki.nssdb
import pki.util
from lxml import etree

INSTANCE_BASE_DIR = '/var/lib/pki'
CONFIG_BASE_DIR = '/etc/pki'
LOG_BASE_DIR = '/var/log/pki'
REGISTRY_DIR = '/etc/sysconfig/pki'

SUBSYSTEM_TYPES = ['ca', 'kra', 'ocsp', 'tks', 'tps']
SUBSYSTEM_CLASSES = {}

SELFTEST_CRITICAL = 'critical'

logger = logging.LoggerAdapter(
    logging.getLogger(__name__),
    extra={'indent': ''})


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
    def setup_password_authentication(username, password, subsystem_name='ca'):
        """Return a PKIConnection, logged in using username and password."""
        connection = client.PKIConnection(
            'https', os.environ['HOSTNAME'], '8443', subsystem_name)
        connection.authenticate(username, password)
        account_client = pki.account.AccountClient(connection)
        account_client.login()
        return connection

    @staticmethod
    def setup_cert_authentication(
            client_nssdb_pass, client_nssdb_pass_file, client_cert,
            client_nssdb, tmpdir, subsystem_name):
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
        :return: Authenticated secure connection to PKI server
        """
        temp_auth_p12 = os.path.join(tmpdir, 'auth.p12')
        temp_auth_cert = os.path.join(tmpdir, 'auth.pem')

        if not client_cert:
            raise PKIServerException('Client cert nickname is required.')

        # Create a PKIConnection object that stores the details of subsystem.
        connection = client.PKIConnection('https', os.environ['HOSTNAME'], '8443',
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
        self.type = None  # e.g. CA, KRA
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

        if os.path.exists(self.cs_conf):

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

        cert_ids = self.config['%s.cert.list' % self.name].split(',')

        for cert_id in cert_ids:
            yield self.get_subsystem_cert(cert_id)

    def get_subsystem_cert(self, cert_id):
        return self.create_subsystem_cert_object(cert_id)

    def create_subsystem_cert_object(self, cert_id):

        logger.info('Getting %s cert info for %s', cert_id, self.name)

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

        if not nickname:
            return cert

        nssdb = self.instance.open_nssdb(token)
        try:
            cert_info = nssdb.get_cert_info(nickname)
            if cert_info:
                cert.update(cert_info)
        finally:
            nssdb.close()

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
            new_file=False):

        cert = self.get_subsystem_cert(cert_id)
        nickname = cert['nickname']
        token = pki.nssdb.normalize_token(cert['token'])

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
        sorted_config = sorted(self.config.items(), key=operator.itemgetter(0))
        with io.open(self.cs_conf, 'w') as f:
            for (key, value) in sorted_config:
                f.write(u'%s=%s\n' % (key, value))

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
            raise PKIServerException('Invalid audit event: %s' % event_name)

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
            raise PKIServerException('Invalid audit event: %s' % event_name)

        name = 'log.instance.SignedAudit.filters.%s' % event_name

        if event_filter:
            self.config[name] = event_filter
        else:
            self.config.pop(name, None)

    def disable_audit_event(self, event_name):

        if not event_name:
            raise ValueError("Please specify the Event name")

        if event_name not in self.get_audit_events():
            raise PKIServerException('Invalid audit event: %s' % event_name)

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
            raise PKIServerException('Invalid audit event: %s' % name)

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
            events = PKIServer.load_audit_events(filename)

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
                raise PKIServerException('No such self test available for %s' % self.name)
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
        cert_request = self.get_subsystem_cert(cert_tag).get('request', None)
        if cert_request is None:
            raise PKIServerException('Unable to find CSR for %s cert' % cert_tag)

        logger.debug('Retrieved CSR: %s', cert_request)

        csr_data = pki.nssdb.convert_csr(cert_request, 'base64', 'pem')
        with open(csr_file, 'w') as f:
            f.write(csr_data)
        logger.info('CSR for %s has been written to %s', cert_tag, csr_file)

        logger.debug('Extracting SKI from CA cert')
        # TODO: Support remote CA.

        # Retrieve Subject Key Identifier from CA cert
        ca_signing_cert = self.instance.get_subsystem('ca').get_subsystem_cert('signing')

        ca_cert_data = ca_signing_cert.get('data', None)
        if ca_cert_data is None:
            raise PKIServerException('Unable to find certificate data for CA signing certificate.')

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
            raise PKIServerException('Temp cert for %s is not supported yet.' % cert_tag)

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
            raise PKIServerException('Failed to generate CA-signed temp SSL '
                                     'certificate. RC: %d' % rc)

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

    def __init__(self, name, instanceType=10):  # noqa: N803

        self.name = name
        self.type = instanceType

        if self.type >= 10:
            self.base_dir = os.path.join(INSTANCE_BASE_DIR, name)
        else:
            self.base_dir = os.path.join(pki.BASE_DIR, name)

        self.conf_dir = os.path.join(CONFIG_BASE_DIR, name)
        self.log_dir = os.path.join(LOG_BASE_DIR, name)

        self.banner_file = os.path.join(self.conf_dir, 'banner.txt')
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

        self.load_passwords()

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

    def get_token_password(self, token=pki.nssdb.INTERNAL_TOKEN_NAME):

        # determine the password name for the token
        if not pki.nssdb.normalize_token(token):
            name = pki.nssdb.INTERNAL_TOKEN_NAME

        else:
            name = 'hardware-%s' % token

        # find password in password.conf
        if name in self.passwords:
            return self.passwords[name]

        # prompt for password if not found
        password = getpass.getpass(prompt='Enter password for %s: ' % token)
        self.passwords[name] = password

        return password

    def open_nssdb(self, token=pki.nssdb.INTERNAL_TOKEN_NAME):
        return pki.nssdb.NSSDatabase(
            directory=self.nssdb_dir,
            token=token,
            password=self.get_token_password(token),
            internal_password=self.get_token_password())

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

    def load_passwords(self):

        self.passwords.clear()

        if os.path.exists(self.password_conf):
            logger.info('Loading password config: %s', self.password_conf)
            pki.util.load_properties(self.password_conf, self.passwords)

    def store_passwords(self):

        pki.util.store_properties(self.password_conf, self.passwords)
        pki.util.chown(self.password_conf, self.uid, self.gid)

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

    def banner_installed(self):
        return os.path.exists(self.banner_file)

    def get_banner(self):
        return codecs.open(self.banner_file, "UTF-8").read().strip()

    def __repr__(self):
        if self.type == 9:
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
            serial=None, temp_cert=False, renew=False, output=None):
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
                        username, password, subsystem_name='ca')
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
                        subsystem_name='ca'
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


class Tomcat(object):

    @classmethod
    def get_major_version(cls):

        # run "tomcat version"
        output = subprocess.check_output(['/usr/sbin/tomcat', 'version'])
        output = output.decode('utf-8')

        # find "Server version: Apache Tomcat/<major version>.<minor version>"
        match = re.search(
            r'^Server version:[^/]*/(\d+).*$',
            output,
            re.MULTILINE  # pylint: disable=no-member
        )

        if not match:
            raise Exception('Unable to determine Tomcat version')

        # return major version
        return match.group(1)
