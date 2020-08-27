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
import ldap
import logging
import os
import xml.etree.ElementTree as ET

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

logger = logging.getLogger('pkiparser')


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
         None, 'pki_server_database_path'),
        (None, 'pki_pin',
         None, 'pki_server_database_password'),
    ]

    DEPRECATED_CA_PARAMS = [
        (['CA'], 'pki_external_csr_path',
         None, 'pki_ca_signing_csr_path')
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
         None, 'pki_subsystem_cert_path')
    ]

    DEPRECATED_PARAMS = DEPRECATED_DEFAULT_PARAMS + \
        DEPRECATED_CA_PARAMS + \
        DEPRECATED_KRA_PARAMS + \
        DEPRECATED_OCSP_PARAMS

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

        # Master and Slot dictionaries
        self.mdict = deployer.mdict
        self.slots_dict = deployer.slots

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
            print("ERROR:  " +
                  log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %
                  config.default_deployment_cfg)
            print()
            self.arg_parser.print_help()
            self.arg_parser.exit(-1)

        if config.user_deployment_cfg:
            # verify user configuration file exists
            if not os.path.exists(config.user_deployment_cfg) or \
                    not os.path.isfile(config.user_deployment_cfg):
                print("ERROR:  " +
                      log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %
                      config.user_deployment_cfg)
                print()
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

        # Check if a instance name is provided before assigning a default
        # instance_name
        if pki_instance_name:
            default_instance_name = pki_instance_name
        else:
            default_instance_name = 'pki-tomcat'

        default_http_port = '8080'
        default_https_port = '8443'

        application_version = str(pki.util.Version(
            pki.specification_version()))

        self.deployer.main_config = configparser.SafeConfigParser({
            'application_version': application_version,
            'pki_instance_name': default_instance_name,
            'pki_http_port': default_http_port,
            'pki_https_port': default_https_port,
            'pki_dns_domainname': self.deployer.dns_domainname,
            'pki_subsystem': self.deployer.subsystem_name,
            'pki_subsystem_type': self.deployer.subsystem_name.lower(),
            'nss_default_db_type': self.deployer.nss_db_type,
            'java_home': java_home,
            'home_dir': os.path.expanduser("~"),
            'pki_hostname': self.deployer.hostname,
            'pki_random_ajp_secret': pki.generate_password()})

        # Make keys case-sensitive!
        self.deployer.main_config.optionxform = str

        self.deployer.user_config = configparser.SafeConfigParser()
        self.deployer.user_config.optionxform = str

        with open(config.default_deployment_cfg) as f:
            self.deployer.main_config.readfp(f)

        self.deployer.flatten_master_dict()

    # The following code is based heavily upon
    # "http://www.decalage.info/en/python/configparser"
    @staticmethod
    def read_simple_configuration_file(filename):
        values = {}
        with open(filename) as f:
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
        except configparser.ParsingError as err:
            print(err)
            rv = err
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
                sections = ['DEFAULT', 'Tomcat', self.deployer.subsystem_name]

            # Find param in the listed sections.

            section = None
            for s in sections:

                if user_config.has_option(s, param):
                    section = s
                    break

            # If param not found, skip.
            if not section:
                continue

            # Param found, display deprecation warning.

            message = 'The \'%s\' in [%s] has been deprecated.' % (param, section)

            # If new param is defined in a different section, include it in message.

            if new_section and new_section != section:
                message = '%s Use \'%s\' in [%s] instead.' % (message, new_param, new_section)
            else:
                message = '%s Use \'%s\' instead.' % (message, new_param)

            print('WARNING: %s' % message)

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
        root = ET.fromstring(response)
        return root.findtext("Status")

    def normalize_cert_token(self, name):

        # get cert token
        token = self.mdict.get(name)

        # if not specified, get default token name
        if not token:
            token = self.mdict.get('pki_token_name')

        # DO NOT normalise the token name here, to avoid re-interpreting
        # the internal token as the default token.  The token name must
        # be conveyed to the Java SystemConfigService as-is.

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
            self.mdict['pki_default_deployment_cfg'] = \
                config.default_deployment_cfg
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
            if 'pki_san_inject' not in self.mdict or\
               not len(self.mdict['pki_san_inject']):
                self.mdict['pki_san_inject'] = "false"

            # PKI Target (slot substitution) name/value pairs
            self.mdict['pki_target_cs_cfg'] = \
                os.path.join(
                    self.mdict['pki_subsystem_configuration_path'],
                    "CS.cfg")

            self.mdict['pki_target_server_xml'] = \
                os.path.join(
                    self.mdict['pki_instance_configuration_path'],
                    "server.xml")
            self.mdict['pki_target_context_xml'] = \
                os.path.join(
                    self.mdict['pki_instance_configuration_path'],
                    "context.xml")
            self.mdict['pki_target_tomcat_conf_instance_id'] = \
                "/etc/sysconfig/" + \
                self.mdict['pki_instance_name']
            self.mdict['pki_target_tomcat_conf'] = \
                os.path.join(
                    self.mdict['pki_instance_configuration_path'],
                    "tomcat.conf")
            # in-place slot substitution name/value pairs
            self.mdict['pki_target_subsystem_web_xml'] = \
                os.path.join(
                    self.mdict['pki_tomcat_webapps_subsystem_path'],
                    "WEB-INF",
                    "web.xml")
            self.mdict['pki_target_subsystem_web_xml_orig'] = \
                os.path.join(
                    self.mdict['pki_tomcat_webapps_subsystem_path'],
                    "WEB-INF",
                    "web.xml.orig")

            self.mdict['pki_target_registry_cfg'] = \
                os.path.join(
                    self.mdict['pki_subsystem_configuration_path'],
                    "registry.cfg")

            # subystem-specific slot substitution name/value pairs
            if self.mdict['pki_subsystem'] == "CA":
                self.mdict['pki_target_flatfile_txt'] = \
                    os.path.join(
                        self.mdict['pki_subsystem_configuration_path'],
                        "flatfile.txt")
                self.mdict['pki_target_proxy_conf'] = \
                    os.path.join(
                        self.mdict['pki_subsystem_configuration_path'],
                        "proxy.conf")
                # '*.profile'
                self.mdict['pki_target_admincert_profile'] = \
                    os.path.join(
                        self.mdict['pki_subsystem_configuration_path'],
                        "adminCert.profile")
                self.mdict['pki_target_caauditsigningcert_profile'] = \
                    os.path.join(
                        self.mdict['pki_subsystem_configuration_path'],
                        "caAuditSigningCert.profile")
                self.mdict['pki_target_cacert_profile'] = \
                    os.path.join(
                        self.mdict['pki_subsystem_configuration_path'],
                        "caCert.profile")
                self.mdict['pki_target_caocspcert_profile'] = \
                    os.path.join(
                        self.mdict['pki_subsystem_configuration_path'],
                        "caOCSPCert.profile")
                self.mdict['pki_target_servercert_profile'] = \
                    os.path.join(
                        self.mdict['pki_subsystem_configuration_path'],
                        "serverCert.profile")
                self.mdict['pki_target_subsystemcert_profile'] = \
                    os.path.join(
                        self.mdict['pki_subsystem_configuration_path'],
                        "subsystemCert.profile")
                # in-place slot substitution name/value pairs
                if config.str2bool(self.mdict['pki_profiles_in_ldap']):
                    self.mdict['PKI_PROFILE_SUBSYSTEM_SLOT'] = \
                        'LDAPProfileSubsystem'
                else:
                    self.mdict['PKI_PROFILE_SUBSYSTEM_SLOT'] = \
                        'ProfileSubsystem'
            elif self.mdict['pki_subsystem'] == "TPS":
                self.mdict['pki_target_registry_cfg'] = \
                    os.path.join(
                        self.mdict['pki_subsystem_configuration_path'],
                        "registry.cfg")
                self.mdict['pki_target_phone_home_xml'] = \
                    os.path.join(
                        self.mdict['pki_subsystem_configuration_path'],
                        "phoneHome.xml")

            # Slot assignment name/value pairs
            #     NOTE:  Master key == Slots key; Master value ==> Slots value
            self.mdict['PKI_INSTANCE_NAME_SLOT'] = \
                self.mdict['pki_instance_name']
            self.mdict['PKI_REGISTRY_FILE_SLOT'] = \
                os.path.join(self.mdict['pki_subsystem_registry_path'],
                             self.mdict['pki_instance_name'])

            self.mdict['INSTALL_TIME_SLOT'] = \
                self.mdict['pki_install_time']
            self.mdict['PKI_ADMIN_SECURE_PORT_SLOT'] = \
                self.mdict['pki_https_port']
            self.mdict['PKI_AGENT_SECURE_PORT_SLOT'] = \
                self.mdict['pki_https_port']
            self.mdict['PKI_AJP_PORT_SLOT'] = \
                self.mdict['pki_ajp_port']
            self.mdict['PKI_AJP_HOST_SLOT'] = \
                self.mdict['pki_ajp_host']
            self.mdict['PKI_AJP_SECRET_SLOT'] = \
                self.mdict['pki_ajp_secret']
            self.mdict['PKI_AJP_REDIRECT_PORT_SLOT'] = \
                self.mdict['pki_https_port']
            self.mdict['PKI_CA_HOSTNAME_SLOT'] = \
                self.mdict['pki_ca_hostname']
            self.mdict['PKI_CA_PORT_SLOT'] = \
                self.mdict['pki_ca_port']
            self.mdict['PKI_CFG_PATH_NAME_SLOT'] = \
                self.mdict['pki_target_cs_cfg']
            self.mdict['PKI_CLOSE_SEPARATE_PORTS_SERVER_COMMENT_SLOT'] = \
                "-->"
            self.mdict['PKI_CLOSE_SEPARATE_PORTS_WEB_COMMENT_SLOT'] = \
                "-->"
            self.mdict['PKI_DS_SECURE_CONNECTION_SLOT'] = \
                self.mdict['pki_ds_secure_connection'].lower()
            self.mdict['PKI_EE_SECURE_CLIENT_AUTH_PORT_SLOT'] = \
                self.mdict['pki_https_port']
            self.mdict['PKI_EE_SECURE_CLIENT_AUTH_PORT_SERVER_COMMENT_SLOT'] = \
                ""
            self.mdict['PKI_EE_SECURE_CLIENT_AUTH_PORT_UI_SLOT'] = \
                self.mdict['pki_https_port']
            self.mdict['PKI_EE_SECURE_PORT_SLOT'] = \
                self.mdict['pki_https_port']
            self.mdict['PKI_EE_SECURE_PORT_SERVER_COMMENT_SLOT'] = \
                ""
            self.mdict['PKI_GROUP_SLOT'] = \
                self.mdict['pki_group']
            self.mdict['PKI_INSTANCE_PATH_SLOT'] = \
                self.mdict['pki_instance_path']
            self.mdict['PKI_INSTANCE_ROOT_SLOT'] = \
                self.mdict['pki_path']
            self.mdict['PKI_HOSTNAME_SLOT'] = \
                self.mdict['pki_hostname']
            self.mdict['PKI_OPEN_SEPARATE_PORTS_SERVER_COMMENT_SLOT'] = \
                "<!--"
            self.mdict['PKI_OPEN_SEPARATE_PORTS_WEB_COMMENT_SLOT'] = \
                "<!--"
            self.mdict['PKI_PIDDIR_SLOT'] = \
                os.path.join("/var/run/pki", "tomcat")
            if config.str2bool(self.mdict['pki_enable_proxy']):
                self.mdict['PKI_CLOSE_AJP_PORT_COMMENT_SLOT'] = \
                    ""
                self.mdict['PKI_CLOSE_ENABLE_PROXY_COMMENT_SLOT'] = \
                    ""
                self.mdict['PKI_PROXY_SECURE_PORT_SLOT'] = \
                    self.mdict['pki_proxy_https_port']
                self.mdict['PKI_PROXY_UNSECURE_PORT_SLOT'] = \
                    self.mdict['pki_proxy_http_port']
                self.mdict['PKI_OPEN_AJP_PORT_COMMENT_SLOT'] = \
                    ""
                self.mdict['PKI_OPEN_ENABLE_PROXY_COMMENT_SLOT'] = \
                    ""
            else:
                self.mdict['PKI_CLOSE_AJP_PORT_COMMENT_SLOT'] = \
                    "-->"
                self.mdict['PKI_CLOSE_ENABLE_PROXY_COMMENT_SLOT'] = \
                    "-->"
                self.mdict['PKI_PROXY_SECURE_PORT_SLOT'] = ""
                self.mdict['PKI_PROXY_UNSECURE_PORT_SLOT'] = ""
                self.mdict['PKI_OPEN_AJP_PORT_COMMENT_SLOT'] = \
                    "<!--"
                self.mdict['PKI_OPEN_ENABLE_PROXY_COMMENT_SLOT'] = \
                    "<!--"
            if config.str2bool(self.mdict['pki_standalone']):
                # Stand-alone PKI
                self.mdict['PKI_CLOSE_STANDALONE_COMMENT_SLOT'] = \
                    ""
                self.mdict['PKI_OPEN_STANDALONE_COMMENT_SLOT'] = \
                    ""
                self.mdict['PKI_STANDALONE_SLOT'] = "true"
            else:
                self.mdict['PKI_CLOSE_STANDALONE_COMMENT_SLOT'] = \
                    "-->"
                self.mdict['PKI_OPEN_STANDALONE_COMMENT_SLOT'] = \
                    "<!--"
                self.mdict['PKI_STANDALONE_SLOT'] = "false"
            if config.str2bool(self.mdict['pki_enable_access_log']):
                self.mdict['PKI_CLOSE_TOMCAT_ACCESS_LOG_COMMENT_SLOT'] = \
                    ""
                self.mdict['PKI_OPEN_TOMCAT_ACCESS_LOG_COMMENT_SLOT'] = \
                    ""
            else:
                self.mdict['PKI_CLOSE_TOMCAT_ACCESS_LOG_COMMENT_SLOT'] = \
                    "-->"
                self.mdict['PKI_OPEN_TOMCAT_ACCESS_LOG_COMMENT_SLOT'] = \
                    "<!--"
            self.mdict['PKI_TMPDIR_SLOT'] = \
                self.mdict['pki_tomcat_tmpdir_path']
            self.mdict['PKI_SECURE_PORT_SLOT'] = \
                self.mdict['pki_https_port']
            self.mdict['PKI_SECURE_PORT_CONNECTOR_NAME_SLOT'] = \
                "Secure"
            self.mdict['PKI_SECURE_PORT_SERVER_COMMENT_SLOT'] = \
                "<!-- " + \
                "Shared Ports:  Agent, EE, and Admin Secure Port Connector " + \
                "-->"
            self.mdict['PKI_SECURITY_MANAGER_SLOT'] = \
                self.mdict['pki_security_manager']
            self.mdict['PKI_SERVER_XML_CONF_SLOT'] = \
                self.mdict['pki_target_server_xml']
            self.mdict['PKI_SSL_SERVER_NICKNAME_SLOT'] = \
                self.mdict['pki_sslserver_nickname']
            self.mdict['PKI_SUBSYSTEM_TYPE_SLOT'] = \
                self.mdict['pki_subsystem'].lower()
            self.mdict['PKI_SYSTEMD_SERVICENAME_SLOT'] = \
                "pki-tomcatd" + "@" + \
                self.mdict['pki_instance_name'] + ".service"
            self.mdict['PKI_UNSECURE_PORT_SLOT'] = \
                self.mdict['pki_http_port']
            self.mdict['PKI_UNSECURE_PORT_CONNECTOR_NAME_SLOT'] = \
                "Unsecure"
            self.mdict['PKI_UNSECURE_PORT_SERVER_COMMENT_SLOT'] = \
                "<!-- Shared Ports:  Unsecure Port Connector -->"
            self.mdict['PKI_USER_SLOT'] = \
                self.mdict['pki_user']
            self.mdict['PKI_WEBAPPS_NAME_SLOT'] = \
                "webapps"

            if self.mdict['pki_subsystem'] == "TPS":
                self.mdict['SERVER_KEYGEN_SLOT'] = \
                    self.mdict['pki_enable_server_side_keygen']

            if self.mdict['pki_subsystem'] == "CA":
                self.mdict['MASTER_CRL_ENABLE_SLOT'] = \
                    self.mdict['pki_master_crl_enable']

            self.mdict['TOMCAT_CFG_SLOT'] = \
                self.mdict['pki_target_tomcat_conf']
            self.mdict['TOMCAT_LOG_DIR_SLOT'] = \
                self.mdict['pki_instance_log_path']
            self.mdict['TOMCAT_PIDFILE_SLOT'] = \
                "/var/run/pki/tomcat/" + self.mdict['pki_instance_name'] + \
                ".pid"
            self.mdict['TOMCAT_SERVER_PORT_SLOT'] = \
                self.mdict['pki_tomcat_server_port']

            # tps parameters
            self.mdict['TOKENDB_HOST_SLOT'] = \
                self.mdict['pki_ds_hostname']

            if config.str2bool(self.mdict['pki_ds_secure_connection']):
                self.mdict['TOKENDB_PORT_SLOT'] = \
                    self.mdict['pki_ds_ldaps_port']
            else:
                self.mdict['TOKENDB_PORT_SLOT'] = \
                    self.mdict['pki_ds_ldap_port']

            self.mdict['TOKENDB_ROOT_SLOT'] = \
                self.mdict['pki_ds_base_dn']

            self.mdict['TPS_DIR_SLOT'] = \
                self.mdict['pki_source_subsystem_path']

            if self.mdict['pki_subsystem'] == "CA":
                self.mdict['PKI_ENABLE_RANDOM_SERIAL_NUMBERS'] = \
                    self.mdict['pki_random_serial_numbers_enable'].lower()
            # Tomcat NSS security database name/value pairs
            self.mdict['pki_shared_pfile'] = \
                os.path.join(
                    self.mdict['pki_instance_configuration_path'],
                    "pfile")
            self.mdict['pki_shared_password_conf'] = \
                os.path.join(
                    self.mdict['pki_instance_configuration_path'],
                    "password.conf")

            self.mdict['pki_self_signed_subject'] = \
                "cn=" + self.mdict['pki_hostname'] + "," + \
                "o=" + self.mdict['pki_certificate_timestamp']
            self.mdict['pki_self_signed_serial_number'] = 0
            self.mdict['pki_self_signed_validity_period'] = 12
            self.mdict['pki_self_signed_trustargs'] = "CTu,CTu,CTu"

            # Tomcat NSS security database convenience
            # symbolic links
            self.mdict['pki_subsystem_configuration_password_conf_link'] = \
                os.path.join(
                    self.mdict['pki_subsystem_configuration_path'],
                    "password.conf")

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
            if not pki.nssdb.normalize_token(self.mdict['pki_token_name']):
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

            elif self.deployer.subsystem_name != "CA" or \
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

            if 'pki_import_admin_cert' not in self.mdict:
                self.mdict['pki_import_admin_cert'] = 'false'
            elif not config.str2bool(self.mdict['pki_skip_configuration']) and \
                    (config.str2bool(self.mdict['pki_standalone'])):
                # Stand-alone PKI
                self.mdict['pki_import_admin_cert'] = 'false'

            self.mdict['pki_ca_signing_tag'] = "signing"
            if self.mdict['pki_subsystem'] == "CA":
                self.mdict['pki_ocsp_signing_tag'] = "ocsp_signing"
            elif self.mdict['pki_subsystem'] == "OCSP":
                self.mdict['pki_ocsp_signing_tag'] = "signing"
            self.mdict['pki_sslserver_tag'] = "sslserver"
            self.mdict['pki_subsystem_tag'] = "subsystem"
            self.mdict['pki_audit_signing_tag'] = "audit_signing"
            self.mdict['pki_transport_tag'] = "transport"
            self.mdict['pki_storage_tag'] = "storage"

            # Finalization name/value pairs
            self.mdict['pki_default_deployment_cfg_replica'] = \
                os.path.join(self.mdict['pki_subsystem_registry_path'],
                             config.DEFAULT_DEPLOYMENT_CONFIGURATION)
            self.mdict['pki_user_deployment_cfg_replica'] = \
                os.path.join(self.mdict['pki_subsystem_registry_path'],
                             config.USER_DEPLOYMENT_CONFIGURATION)
            self.mdict['pki_user_deployment_cfg_spawn_archive'] = \
                self.mdict['pki_subsystem_archive_log_path'] + "/" + \
                "spawn" + "_" + \
                config.USER_DEPLOYMENT_CONFIGURATION + "." + \
                self.mdict['pki_timestamp']
            self.mdict['pki_manifest'] = \
                self.mdict['pki_subsystem_registry_path'] + "/" + \
                "manifest"
            self.mdict['pki_manifest_spawn_archive'] = \
                self.mdict['pki_subsystem_archive_log_path'] + "/" + \
                "spawn" + "_" + "manifest" + "." + \
                self.mdict['pki_timestamp']
            # Compose this "systemd" execution management command
            self.mdict['pki_registry_initscript_command'] = \
                "systemctl" + " " + \
                "restart" + " " + \
                "pki-tomcatd" + "@" + \
                self.mdict['pki_instance_name'] + "." + "service"

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

    def compose_pki_slots_dictionary(self):
        """Read the slots configuration file to create
           the appropriate PKI slots dictionary"""
        rv = 0
        try:
            parser = configparser.ConfigParser()
            # Make keys case-sensitive!
            parser.optionxform = str
            parser.read(config.PKI_DEPLOYMENT_SLOTS_CONFIGURATION_FILE)
            # Slots configuration file name/value pairs
            self.slots_dict.update(dict(parser.items('Tomcat')))
        except configparser.ParsingError as err:
            rv = err
        return rv

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
