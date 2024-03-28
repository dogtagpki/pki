# Authors:
#     Matthew Harmsen <mharmsen@redhat.com>
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
# Copyright (C) 2012 Red Hat, Inc.
# All rights reserved.
#

# System Imports
from __future__ import absolute_import
from __future__ import print_function
import argparse
import getpass
import json
import ldap
import logging
import os
import string

import six
from six.moves import input  # pylint: disable=W0622,F0401
from six.moves import configparser  # pylint: disable=F0401
from six.moves.urllib.parse import urlparse  # pylint: disable=F0401,E0611


# PKI Imports
import pki
import pki.upgrade
import pki.account
import pki.client
import pki.system
from . import pkiconfig as config
from . import pkimessages as log
from . import pkilogging

logger = logging.getLogger(__name__)


class PKIConfigParser:

    COMMENT_CHAR = '#'
    OPTION_CHAR = '='

    # Deprecated param can be defined with the following tuple:
    #
    #   (sections, param, new_section, new_param)
    #
    # The 'sections' is a list of sections to check for the deprecated param. None
    # means the following sections will be checked: DEFAULT, Tomcat, and <subsystem>.
    # The 'param' is the deprecated param name.
    # The 'new_section' is the proper section of the new param. None means unchanged.
    # The 'new_param' is the new param name.

    DEPRECATED_DEFAULT_PARAMS = [
        (None, 'pki_admin_keysize',
         None, 'pki_admin_key_size'),
        (None, 'pki_external_ca_cert_path',
         None, 'pki_ca_signing_cert_path'),
        (None, 'pki_external_ca_cert_chain_path',
         None, 'pki_cert_chain_path'),
        (None, 'pki_external_ca_cert_chain_nickname',
         None, 'pki_cert_chain_nickname'),
        (None, 'pki_ssl_server_key_algorithm',
         None, 'pki_sslserver_key_algorithm'),
        (None, 'pki_ssl_server_key_size',
         None, 'pki_sslserver_key_size'),
        (None, 'pki_ssl_server_key_type',
         None, 'pki_sslserver_key_type'),
        (None, 'pki_ssl_server_nickname',
         None, 'pki_sslserver_nickname'),
        (None, 'pki_ssl_server_subject_dn',
         None, 'pki_sslserver_subject_dn'),
        (None, 'pki_ssl_server_token',
         None, 'pki_sslserver_token'),
        (None, 'pki_database_path',
         None, None),
        (None, 'pki_server_database_path',
         None, None),
        (None, 'pki_pin',
         None, 'pki_server_database_password'),
        (None, 'pki_ajp_host',
         None, 'pki_ajp_host_ipv4'),
        (None, 'pki_restart_configured_instance',
         None, None),
        (None, 'pki_existing',
         None, None),
    ]

    DEPRECATED_CA_PARAMS = [
        (['CA'], 'pki_external_csr_path',
         None, 'pki_ca_signing_csr_path'),
        (['CA'], 'pki_ds_hostname',
         None, 'pki_ds_url'),
        (['CA'], 'pki_ds_ldap_port',
         None, 'pki_ds_url'),
        (['CA'], 'pki_ds_ldaps_port',
         None, 'pki_ds_url'),
        (['CA'], 'pki_ds_secure_connection',
         None, 'pki_ds_url'),
    ]

    DEPRECATED_KRA_PARAMS = [
        (['KRA'], 'pki_external_admin_csr_path',
         None, 'pki_admin_csr_path'),
        (['KRA'], 'pki_external_audit_signing_csr_path',
         None, 'pki_audit_signing_csr_path'),
        (['KRA'], 'pki_external_sslserver_csr_path',
         None, 'pki_sslserver_csr_path'),
        (['KRA'], 'pki_external_storage_csr_path',
         None, 'pki_storage_csr_path'),
        (['KRA'], 'pki_external_subsystem_csr_path',
         None, 'pki_subsystem_csr_path'),
        (['KRA'], 'pki_external_transport_csr_path',
         None, 'pki_transport_csr_path'),
        (['KRA'], 'pki_external_admin_cert_path',
         None, 'pki_admin_cert_path'),
        (['KRA'], 'pki_external_audit_signing_cert_path',
         None, 'pki_audit_signing_cert_path'),
        (['KRA'], 'pki_external_sslserver_cert_path',
         None, 'pki_sslserver_cert_path'),
        (['KRA'], 'pki_external_storage_cert_path',
         None, 'pki_storage_cert_path'),
        (['KRA'], 'pki_external_subsystem_cert_path',
         None, 'pki_subsystem_cert_path'),
        (['KRA'], 'pki_external_transport_cert_path',
         None, 'pki_transport_cert_path'),
        (['KRA'], 'pki_ds_hostname',
         None, 'pki_ds_url'),
        (['KRA'], 'pki_ds_ldap_port',
         None, 'pki_ds_url'),
        (['KRA'], 'pki_ds_ldaps_port',
         None, 'pki_ds_url'),
        (['KRA'], 'pki_ds_secure_connection',
         None, 'pki_ds_url'),
    ]

    DEPRECATED_OCSP_PARAMS = [
        (['OCSP'], 'pki_external_admin_csr_path',
         None, 'pki_admin_csr_path'),
        (['OCSP'], 'pki_external_audit_signing_csr_path',
         None, 'pki_audit_signing_csr_path'),
        (['OCSP'], 'pki_external_signing_csr_path',
         None, 'pki_ocsp_signing_csr_path'),
        (['OCSP'], 'pki_external_sslserver_csr_path',
         None, 'pki_sslserver_csr_path'),
        (['OCSP'], 'pki_external_subsystem_csr_path',
         None, 'pki_subsystem_csr_path'),
        (['OCSP'], 'pki_external_admin_cert_path',
         None, 'pki_admin_cert_path'),
        (['OCSP'], 'pki_external_audit_signing_cert_path',
         None, 'pki_audit_signing_cert_path'),
        (['OCSP'], 'pki_external_signing_cert_path',
         None, 'pki_ocsp_signing_cert_path'),
        (['OCSP'], 'pki_external_sslserver_cert_path',
         None, 'pki_sslserver_cert_path'),
        (['OCSP'], 'pki_external_subsystem_cert_path',
         None, 'pki_subsystem_cert_path'),
        (['OCSP'], 'pki_ds_hostname',
         None, 'pki_ds_url'),
        (['OCSP'], 'pki_ds_ldap_port',
         None, 'pki_ds_url'),
        (['OCSP'], 'pki_ds_ldaps_port',
         None, 'pki_ds_url'),
        (['OCSP'], 'pki_ds_secure_connection',
         None, 'pki_ds_url'),
    ]

    DEPRECATED_TKS_PARAMS = [
        (['TKS'], 'pki_ds_hostname',
         None, 'pki_ds_url'),
        (['TKS'], 'pki_ds_ldap_port',
         None, 'pki_ds_url'),
        (['TKS'], 'pki_ds_ldaps_port',
         None, 'pki_ds_url'),
        (['TKS'], 'pki_ds_secure_connection',
         None, 'pki_ds_url'),
    ]

    DEPRECATED_TPS_PARAMS = [
        (['TPS'], 'pki_ds_hostname',
         None, 'pki_ds_url'),
        (['TPS'], 'pki_ds_ldap_port',
         None, 'pki_ds_url'),
        (['TPS'], 'pki_ds_ldaps_port',
         None, 'pki_ds_url'),
        (['TPS'], 'pki_ds_secure_connection',
         None, 'pki_ds_url'),
    ]

    DEPRECATED_PARAMS = DEPRECATED_DEFAULT_PARAMS + \
        DEPRECATED_CA_PARAMS + \
        DEPRECATED_KRA_PARAMS + \
        DEPRECATED_OCSP_PARAMS + \
        DEPRECATED_TKS_PARAMS + \
        DEPRECATED_TPS_PARAMS

    def __init__(self, description, epilog, deployer=None):
        self.deployer = deployer

        # Read and process command-line options
        self.arg_parser = argparse.ArgumentParser(
            description=description,
            add_help=False,
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog=epilog)

        # Establish 'Mandatory' command-line options
        self.mandatory = self.arg_parser.add_argument_group(
            'mandatory arguments')

        # Establish 'Optional' command-line options
        self.optional = self.arg_parser.add_argument_group(
            'optional arguments')
        self.optional.add_argument(
            '-s',
            dest='pki_subsystem', action='store',
            nargs=1, choices=config.PKI_SUBSYSTEMS,
            metavar='<subsystem>',
            help='where <subsystem> is '
            'CA, KRA, OCSP, TKS, or TPS')
        self.optional.add_argument(
            '-h', '--help',
            dest='help', action='help',
            help='show this help message and exit')
        self.optional.add_argument(
            '-v', '--verbose',
            dest='pki_verbosity', action='count', default=0,
            help='Run in verbose mode')
        self.optional.add_argument(
            '--debug',
            dest='debug', action='store_true',
            help='Run in debug mode')

        self.indent = 0
        self.authdb_connection = None

        self.mdict = deployer.mdict

    def process_command_line_arguments(self):

        args = self.arg_parser.parse_args()

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.pki_verbosity == 1:
            logging.getLogger().setLevel(logging.INFO)

        elif args.pki_verbosity >= 2:
            logging.getLogger().setLevel(logging.DEBUG)

        return args

    def validate(self):
        # always default that configuration file exists
        if not os.path.exists(config.default_deployment_cfg) or \
                not os.path.isfile(config.default_deployment_cfg):
            logger.error(
                log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                config.default_deployment_cfg)
            self.arg_parser.print_help()
            self.arg_parser.exit(-1)

        if config.user_deployment_cfg:
            # verify user configuration file exists
            if not os.path.exists(config.user_deployment_cfg) or \
                    not os.path.isfile(config.user_deployment_cfg):
                logger.error(
                    log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                    config.user_deployment_cfg)
                self.arg_parser.print_help()
                self.arg_parser.exit(-1)

    def _getenv(self, key):
        """Get value from env

        Environment variables are sourced by the shell script wrappers.
        """
        value = os.environ.get(key)
        if value is None:
            raise KeyError("{} env var is missing.".format(key))
        if not value:
            raise KeyError("{} env var is empty.".format(key))
        return value

    def get_nss_db_type(self):
        """Get and validate NSS_DEFAULT_DB_TYPE

        Value is globally configured in /usr/share/pki/etc/pki.conf and
        sourced by shell wrapper scripts.
        """
        dbtype = self._getenv('NSS_DEFAULT_DB_TYPE')
        if dbtype not in {'dbm', 'sql'}:
            raise ValueError(
                "Unsupported NSS_DEFAULT_DB_TYPE value '{}'".format(dbtype)
            )
        return dbtype

    def init_config(self, pki_instance_name=None):
        self.deployer.nss_db_type = self.get_nss_db_type()
        java_home = self._getenv('JAVA_HOME').strip()

        application_version = str(pki.util.Version(
            pki.specification_version()))

        charset = string.digits + string.ascii_lowercase + string.ascii_uppercase
        self.deployer.main_config = configparser.ConfigParser({
            'application_version': application_version,
            'pki_dns_domainname': self.deployer.dns_domainname,
            'pki_subsystem': self.deployer.subsystem_type,
            'pki_subsystem_type': self.deployer.subsystem_type.lower(),
            'nss_default_db_type': self.deployer.nss_db_type,
            'java_home': java_home,
            'home_dir': os.path.expanduser("~"),
            'pki_hostname': self.deployer.hostname,
            'pki_random_ajp_secret': pki.generate_password(charset, length=25)})

        if pki_instance_name:
            self.deployer.main_config.set('DEFAULT', 'pki_instance_name', pki_instance_name)

        # Make keys case-sensitive!
        self.deployer.main_config.optionxform = str

        self.deployer.user_config = configparser.ConfigParser()
        self.deployer.user_config.optionxform = str

        with open(config.default_deployment_cfg, encoding='utf-8') as f:
            if six.PY2:
                self.deployer.main_config.readfp(f)
            else:
                self.deployer.main_config.read_file(f)

        self.deployer.flatten_master_dict()

    # The following code is based heavily upon
    # "http://www.decalage.info/en/python/configparser"
    @staticmethod
    def read_simple_configuration_file(filename):
        values = {}
        with open(filename, encoding='utf-8') as f:
            for line in f:
                # First, remove comments:
                if PKIConfigParser.COMMENT_CHAR in line:
                    # split on comment char, keep only the part before
                    line, _ = line.split(PKIConfigParser.COMMENT_CHAR, 1)
                # Second, find lines with an name=value:
                if PKIConfigParser.OPTION_CHAR in line:
                    # split on name char:
                    name, value = line.split(PKIConfigParser.OPTION_CHAR, 1)
                    # strip spaces:
                    name = name.strip()
                    value = value.strip()
                    # store in dictionary:
                    values[name] = value
        return values

    def print_text(self, message):
        print(' ' * self.indent + message)

    def read_text(self, message, section=None, key=None, default=None,
                  options=None, sign=':', allow_empty=True,
                  case_sensitive=True):

        if default is None and key is not None:
            default = self.mdict[key]
        if default:
            message = message + ' [' + default + ']'
        message = ' ' * self.indent + message + sign + ' '

        done = False
        value = ''
        while not done:
            value = input(message)
            value = value.strip()

            if len(value) == 0:  # empty value
                if allow_empty:
                    value = default
                    done = True
                    break

            else:  # non-empty value
                if options is not None:
                    for v in options:
                        if case_sensitive:
                            if v == value:
                                done = True
                                break
                        else:
                            if v.lower() == value.lower():
                                done = True
                                break
                else:
                    done = True
                    break

        value = value.replace("%", "%%")
        if section:
            self.deployer.set_property(key, value, section=section)

        return value

    def read_password(self, message, section=None, key=None,  # noqa: N803
                      verifyMessage=None):
        message = ' ' * self.indent + message + ': '
        if verifyMessage is not None:  # nopep8
            verifyMessage = ' ' * self.indent + verifyMessage + ': '  # nopep8

        while True:
            password = ''
            while len(password) == 0:
                password = getpass.getpass(prompt=message)

            if verifyMessage is not None:
                verification = ''
                while len(verification) == 0:
                    verification = getpass.getpass(prompt=verifyMessage)

                if password != verification:
                    self.print_text('Passwords do not match.')
                    continue

            break

        password = password.replace("%", "%%")
        if section:
            self.deployer.set_property(key, password, section=section)

        return password

    def read_pki_configuration_file(self):
        """Read configuration file sections into dictionaries"""
        rv = 0
        try:
            if config.user_deployment_cfg:
                # We don't allow interpolation in password settings, which
                # means that we need to deal with escaping '%' characters
                # that might be present.
                no_interpolation = (
                    'pki_admin_password',
                    'pki_backup_password',
                    'pki_client_database_password',
                    'pki_client_pin',
                    'pki_client_pkcs12_password',
                    'pki_clone_pkcs12_password',
                    'pki_ds_password',
                    'pki_one_time_pin',
                    'pki_pin',
                    'pki_replication_password',
                    'pki_security_domain_password',
                    'pki_server_database_password',
                    'pki_server_pkcs12_password',
                    'pki_token_password')

                print('Loading deployment configuration from ' +
                      config.user_deployment_cfg + '.')

                self.validate_user_config(config.user_deployment_cfg)

                self.deployer.main_config.read([config.user_deployment_cfg])
                self.deployer.user_config.read([config.user_deployment_cfg])

                # Look through each section and see if any password settings
                # are present.  If so, escape any '%' characters.
                sections = self.deployer.main_config.sections()
                if sections:
                    sections.append('DEFAULT')
                    for section in sections:
                        for key in no_interpolation:
                            try:
                                val = self.deployer.main_config.get(
                                    section, key, raw=True)
                                val = val.replace("%", "%%")  # pylint: disable=E1101
                                if val:
                                    self.deployer.main_config.set(
                                        section, key, val)
                            except configparser.NoOptionError:
                                continue

                sections = self.deployer.user_config.sections()
                if sections:
                    sections.append('DEFAULT')
                    for section in sections:
                        for key in no_interpolation:
                            try:
                                val = self.deployer.user_config.get(
                                    section, key, raw=True)
                                val = val.replace("%", "%%")  # pylint: disable=E1101
                                if val:
                                    self.deployer.user_config.set(
                                        section, key, val)
                            except configparser.NoOptionError:
                                continue
        except configparser.ParsingError:
            logger.exception(log.PKI_UNABLE_TO_PARSE_1, config.user_deployment_cfg)
            rv = 1
        return rv

    def validate_user_config(self, filename):

        # Read user configuration without default values and interpolations.

        user_config = configparser.RawConfigParser()
        user_config.read(filename)

        # Check all deprecated params.

        for (sections, param, new_section, new_param) in PKIConfigParser.DEPRECATED_PARAMS:

            # If list of sections is not defined, check DEFAULT, Tomcat, and <subsystem> sections.
            # Check DEFAULT first because params in DEFAULT will appear in all other sections.

            if not sections:
                sections = ['DEFAULT', 'Tomcat', self.deployer.subsystem_type]

            # Find param in the listed sections.

            section = None
            for s in sections:

                if user_config.has_option(s, param):
                    section = s
                    break

            # If param not found, skip.
            if not section:
                continue

            # no new section and no replacement param -> display removal warning
            if not new_section and not new_param:
                logger.warning(
                    'The \'%s\' in [%s] is no longer used. Remove the parameter.',
                    param, section)
                return

            # display deprecation warning
            message = 'The \'%s\' in [%s] has been deprecated.' % (param, section)

            # If new param is defined in a different section, include it in message.

            if new_section and new_section != section:
                message = '%s Use \'%s\' in [%s] instead.' % (message, new_param, new_section)
            else:
                message = '%s Use \'%s\' instead.' % (message, new_param)

            logger.warning(message)

    def authdb_connect(self):

        hostname = self.mdict['pki_authdb_hostname']
        port = self.mdict['pki_authdb_port']

        if config.str2bool(self.mdict['pki_authdb_secure_conn']):
            protocol = 'ldaps'
        else:
            protocol = 'ldap'

        self.authdb_connection = ldap.initialize(
            protocol + '://' + hostname + ':' + port)
        self.authdb_connection.search_s('', ldap.SCOPE_BASE)

    def authdb_base_dn_exists(self):
        try:
            results = self.authdb_connection.search_s(
                self.mdict['pki_authdb_basedn'],
                ldap.SCOPE_BASE)

            if results is None or len(results) == 0:
                return False

            return True

        except ldap.NO_SUCH_OBJECT:
            return False

    def get_server_status(self, system_type, system_uri):
        parse = urlparse(self.mdict[system_uri])
        # Because this is utilized exclusively during pkispawn, we can safely
        # ignore validating the certificate; it might not yet have been
        # configured anyways.
        conn = pki.client.PKIConnection(
            protocol=parse.scheme,
            hostname=parse.hostname,
            port=str(parse.port),
            trust_env=False,
            verify=False)
        client = pki.system.SystemStatusClient(conn, subsystem=system_type)
        response = client.get_status()
        json_response = json.loads(response)
        return json_response['Response']['Status']

    def normalize_cert_token(self, name):

        # get cert token
        token = self.mdict.get(name)

        # if not specified, get default token name
        if not token:
            token = self.mdict.get('pki_token_name')

        # DO NOT normalise the token name here, to avoid re-interpreting
        # the internal token as the default token.

        # update cert token
        self.mdict[name] = token

    def compose_pki_master_dictionary(self):
        """
        Create a single master PKI dictionary from the
        sectional dictionaries
        """
        try:
            # 'pkispawn'/'pkidestroy' name/value pairs
            self.mdict['pki_deployment_executable'] = \
                config.pki_deployment_executable
            self.mdict['pki_install_time'] = self.deployer.install_time
            self.mdict['pki_timestamp'] = self.deployer.log_timestamp
            self.mdict['pki_certificate_timestamp'] = self.deployer.certificate_timestamp
            self.mdict['pki_architecture'] = self.deployer.architecture
            self.mdict['pki_user_deployment_cfg'] = config.user_deployment_cfg
            self.mdict['pki_deployed_instance_name'] = \
                config.pki_deployed_instance_name

            self.deployer.flatten_master_dict()

            pkilogging.sensitive_parameters = \
                self.mdict['sensitive_parameters'].split()

            # Always create "false" values for these missing "boolean" keys
            if 'pki_enable_access_log' not in self.mdict or\
               not len(self.mdict['pki_enable_access_log']):
                self.mdict['pki_enable_access_log'] = "false"
            if 'pki_external' not in self.mdict or\
               not len(self.mdict['pki_external']):
                self.mdict['pki_external'] = "false"
            if 'pki_req_ext_add' not in self.mdict or\
               not len(self.mdict['pki_req_ext_add']):
                self.mdict['pki_req_ext_add'] = "false"
            if 'pki_external_step_two' not in self.mdict or\
               not len(self.mdict['pki_external_step_two']):
                self.mdict['pki_external_step_two'] = "false"
            if 'pki_standalone' not in self.mdict or\
               not len(self.mdict['pki_standalone']):
                self.mdict['pki_standalone'] = "false"
            if 'pki_subordinate' not in self.mdict or\
               not len(self.mdict['pki_subordinate']):
                self.mdict['pki_subordinate'] = "false"

            self.mdict['pki_standalone'] = self.mdict['pki_standalone'].lower()

            # Configuration scriptlet
            # 'Security Domain' Configuration name/value pairs
            # 'Subsystem Name'  Configuration name/value pairs
            # 'Token'           Configuration name/value pairs
            #
            #     Tomcat - [CA], [KRA], [OCSP], [TKS], [TPS]
            #            - [CA Clone], [KRA Clone], [OCSP Clone], [TKS Clone],
            #              [TPS Clone]
            #            - [External CA]
            #            - [Subordinate CA]
            #
            #     The following variables are defined below:
            #
            #         self.mdict['pki_security_domain_type']
            #
            #     The following variables are established via the specified PKI
            #     deployment configuration file and are NOT redefined below:
            #
            #         self.mdict['pki_clone_pkcs12_password']
            #         self.mdict['pki_security_domain_password']
            #         self.mdict['pki_token_password']
            #         self.mdict['pki_clone_pkcs12_path']
            #         self.mdict['pki_clone_uri']
            #         self.mdict['pki_security_domain_https_port']
            #
            #     The following variables are established via the specified PKI
            #     deployment configuration file and potentially "normalized"
            #     below:
            #
            #         self.mdict['pki_token_name']
            #
            #     The following variables are established via the specified PKI
            #     deployment configuration file and potentially overridden
            #     below:
            #
            #         self.mdict['pki_security_domain_user']
            #         self.mdict['pki_issuing_ca']
            #

            # if the case insensitive softokn name is the 'default' value
            if pki.nssdb.internal_token(self.mdict['pki_token_name']):
                # always normalize 'default' softokn name
                self.mdict['pki_token_name'] = pki.nssdb.INTERNAL_TOKEN_NAME

            # normalize cert tokens
            self.normalize_cert_token('pki_audit_signing_token')
            self.normalize_cert_token('pki_sslserver_token')
            self.normalize_cert_token('pki_subsystem_token')
            self.normalize_cert_token('pki_ca_signing_token')
            self.normalize_cert_token('pki_ocsp_signing_token')
            self.normalize_cert_token('pki_storage_token')
            self.normalize_cert_token('pki_transport_token')

            # if security domain user is not defined
            if not len(self.mdict['pki_security_domain_user']):

                # use the CA admin uid if it's defined
                if self.deployer.main_config.has_option('CA', 'pki_admin_uid') and\
                        len(self.deployer.main_config.get('CA', 'pki_admin_uid')) > 0:
                    self.mdict['pki_security_domain_user'] = \
                        self.deployer.main_config.get('CA', 'pki_admin_uid')

                # or use the Default admin uid if it's defined
                elif self.deployer.main_config.has_option('DEFAULT', 'pki_admin_uid') and\
                        len(self.deployer.main_config.get('DEFAULT', 'pki_admin_uid')) > 0:
                    self.mdict['pki_security_domain_user'] = \
                        self.deployer.main_config.get('DEFAULT', 'pki_admin_uid')

                # otherwise use the default CA admin uid
                else:
                    self.mdict['pki_security_domain_user'] = "caadmin"

            if not config.str2bool(self.mdict['pki_skip_configuration']) and \
                    config.str2bool(self.mdict['pki_standalone']):

                # Stand-alone PKI
                self.mdict['pki_security_domain_type'] = "new"

            elif self.deployer.subsystem_type != "CA" or \
                    config.str2bool(self.mdict['pki_clone']) or \
                    config.str2bool(self.mdict['pki_subordinate']) and \
                    not config.str2bool(self.mdict['pki_subordinate_create_new_security_domain']):

                # PKI KRA, PKI OCSP, PKI TKS, PKI TPS,
                # CA Clone, KRA Clone, OCSP Clone, TKS Clone, TPS Clone
                # Subordinate CA (existing)
                self.mdict['pki_security_domain_type'] = "existing"

            elif config.str2bool(self.mdict['pki_external']):

                # External CA
                self.mdict['pki_security_domain_type'] = "new"

            else:
                # PKI CA (master) and Subordinate CA (new)
                self.mdict['pki_security_domain_type'] = "new"

            # 'External CA' Configuration name/value pairs
            #
            #     Tomcat - [External CA]
            #
            #     The following variables are established via the specified PKI
            #     deployment configuration file and are NOT redefined below:
            #
            #        self.mdict['pki_cert_chain_path']
            #        self.mdict['pki_ca_signing_cert_path']
            #        self.mdict['pki_ca_signing_csr_path']
            #        self.mdict['pki_external_step_two']
            #

            self.mdict['pki_admin_profile_id'] = "caAdminCert"

        except OSError as exc:
            logger.error(log.PKI_OSERROR_1, exc)
            raise
        except KeyError as err:
            logger.error(log.PKIHELPER_DICTIONARY_MASTER_MISSING_KEY_1, err)
            raise
        except configparser.InterpolationSyntaxError as err:
            logger.error(log.PKIHELPER_DICTIONARY_INTERPOLATION_1)
            logger.error(log.PKIHELPER_DICTIONARY_INTERPOLATION_2, err)
            raise
        return

    @staticmethod
    def read_existing_deployment_data(instance_name):
        data = {}
        instance_root = os.path.join('/var/lib/pki', instance_name)
        if not os.path.exists(instance_root):
            return data
        deployment_root = os.path.join('/etc/sysconfig/pki/tomcat',
                                       instance_name)

        for root, _dirs, names in os.walk(deployment_root):
            if 'deployment.cfg' in names:
                deployment_file = os.path.join(root, 'deployment.cfg')
                data = PKIConfigParser.read_simple_configuration_file(
                    deployment_file)
                break

        return data
