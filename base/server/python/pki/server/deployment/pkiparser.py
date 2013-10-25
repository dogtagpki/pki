#!/usr/bin/python -t
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
import ConfigParser
import argparse
import getpass
import ldap
import logging
import os
import random
import requests
import string
import subprocess
import xml.etree.ElementTree as ET
from urlparse import urlparse

# PKI Imports
import pki
import pki.upgrade
import pki.account
import pki.client
import pki.system
from . import pkiconfig as config
from . import pkimessages as log
from . import pkilogging


class PKIConfigParser:

    COMMENT_CHAR = '#'
    OPTION_CHAR = '='

    def __init__(self, description, epilog):
        self.pki_config = None

        #Read and process command-line options
        self.arg_parser = argparse.ArgumentParser(
                     description=description,
                     add_help=False,
                     formatter_class=argparse.RawDescriptionHelpFormatter,
                     epilog=epilog)

        # Establish 'Mandatory' command-line options
        self.mandatory = self.arg_parser.add_argument_group('mandatory arguments')

        # Establish 'Optional' command-line options
        self.optional = self.arg_parser.add_argument_group('optional arguments')
        self.optional.add_argument('-s',
                               dest='pki_subsystem', action='store',
                               nargs=1, choices=config.PKI_SUBSYSTEMS,
                               metavar='<subsystem>',
                               help='where <subsystem> is '
                                    'CA, KRA, OCSP, RA, TKS, or TPS')
        self.optional.add_argument('-h', '--help',
                              dest='help', action='help',
                              help='show this help message and exit')
        self.optional.add_argument('-v',
                              dest='pki_verbosity', action='count',
                              help='display verbose information (details below)')

        # Establish 'Test' command-line options
        test = self.arg_parser.add_argument_group('test arguments')
        test.add_argument('-p',
                          dest='pki_root_prefix', action='store',
                          nargs=1, metavar='<prefix>',
                          help='directory prefix to specify local directory '
                               '[TEST ONLY]')
        self.indent = 0
        self.ds_connection = None
        self.sd_connection = None
        self.authdb_connection = None

        # Master and Slot dictionaries
        self.pki_master_dict = dict()
        self.pki_slots_dict = dict()

    # PKI Deployment Helper Functions
    def process_command_line_arguments(self):

        # Parse command-line options
        args = self.arg_parser.parse_args()

        # Process 'Mandatory' command-line options

        # Process 'Optional' command-line options
        #    '-v'
        if args.pki_verbosity == 1:
            config.pki_console_log_level = logging.INFO
        elif args.pki_verbosity >= 2:
            config.pki_console_log_level = logging.DEBUG
        else:
            # Set default log levels
            config.pki_console_log_level = logging.WARNING

        # Debug log is always at DEBUG level
        config.pki_log_level = logging.DEBUG

        # Process 'Test' command-line options
        #    '-p'
        if args.pki_root_prefix is None:
            config.pki_root_prefix = ""
        else:
            config.pki_root_prefix = str(args.pki_root_prefix).strip('[\']')

        return args


    def validate(self):

        # Validate command-line options
        if len(config.pki_root_prefix) > 0:
            if not os.path.exists(config.pki_root_prefix) or\
                 not os.path.isdir(config.pki_root_prefix):
                print "ERROR:  " + \
                      log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 % \
                      config.pki_root_prefix
                print
                self.arg_parser.print_help()
                self.arg_parser.exit(-1)

        # always default that configuration file exists
        if not os.path.exists(config.default_deployment_cfg) or\
            not os.path.isfile(config.default_deployment_cfg):
            print "ERROR:  " + \
                  log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % \
                  config.default_deployment_cfg
            print
            self.arg_parser.print_help()
            self.arg_parser.exit(-1)

        if config.user_deployment_cfg:
            # verify user configuration file exists
            if not os.path.exists(config.user_deployment_cfg) or\
                not os.path.isfile(config.user_deployment_cfg):
                print "ERROR:  " + \
                      log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 % \
                      config.user_deployment_cfg
                print
                self.arg_parser.print_help()
                self.arg_parser.exit(-1)


    def init_config(self):

        # RESTEasy
        resteasy_lib = subprocess.check_output(
            'source /etc/pki/pki.conf && echo $RESTEASY_LIB',
            shell=True)
        # workaround for pylint error E1103
        resteasy_lib = str(resteasy_lib).strip()

        # JNI jar location
        jni_jar_dir = subprocess.check_output(
            'source /usr/share/pki/etc/pki.conf && echo $JNI_JAR_DIR',
            shell=True)
        # workaround for pylint error E1103
        jni_jar_dir = str(jni_jar_dir).strip()

        if config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
            default_instance_name = 'pki-tomcat'
            default_http_port = '8080'
            default_https_port = '8443'
        else:
            default_instance_name = 'pki-apache'
            default_http_port = '80'
            default_https_port = '443'

        application_version = str(pki.upgrade.Version(pki.implementation_version()))

        self.pki_config = ConfigParser.SafeConfigParser({
            'application_version': application_version,
            'pki_instance_name': default_instance_name,
            'pki_http_port': default_http_port,
            'pki_https_port': default_https_port,
            'pki_dns_domainname': config.pki_dns_domainname,
            'pki_subsystem': config.pki_subsystem,
            'pki_subsystem_type': config.pki_subsystem.lower(),
            'pki_root_prefix' : config.pki_root_prefix,
            'resteasy_lib': resteasy_lib,
            'jni_jar_dir': jni_jar_dir,
            'home_dir': os.path.expanduser("~"),
            'pki_hostname': config.pki_hostname})

        # Make keys case-sensitive!
        self.pki_config.optionxform = str

        config.user_config = ConfigParser.SafeConfigParser()
        config.user_config.optionxform = str

        with open(config.default_deployment_cfg) as f:
            self.pki_config.readfp(f)

        self.flatten_master_dict()


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


    def set_property(self, section, key, value):
        if section != "DEFAULT" and not self.pki_config.has_section(section):
            self.pki_config.add_section(section)
        self.pki_config.set(section, key, value)
        self.flatten_master_dict()

        if section != "DEFAULT" and not config.user_config.has_section(section):
            config.user_config.add_section(section)
        config.user_config.set(section, key, value)


    def print_text(self, message):
        print ' ' * self.indent + message

    def read_text(self, message,
        section=None, key=None, default=None,
        options=None, sign=':', allowEmpty=True, caseSensitive=True):

        if default is None and key is not None:
            default = self.pki_master_dict[key]
        if default:
            message = message + ' [' + default + ']'
        message = ' ' * self.indent + message + sign + ' '

        done = False
        while not done:
            value = raw_input(message)
            value = value.strip()

            if len(value) == 0:  # empty value
                if allowEmpty:
                    value = default
                    done = True
                    break

            else:  # non-empty value
                if options is not None:
                    for v in options:
                        if caseSensitive:
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
            self.set_property(section, key, value)

        return value


    def read_password(self, message, section=None, key=None,
        verifyMessage=None):
        message = ' ' * self.indent + message + ': '
        if verifyMessage is not None:
            verifyMessage = ' ' * self.indent + verifyMessage + ': '

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
            self.set_property(section, key, password)

        return password

    def read_pki_configuration_file(self):
        "Read configuration file sections into dictionaries"
        rv = 0
        try:
            if config.user_deployment_cfg:
                # We don't allow interpolation in password settings, which
                # means that we need to deal with escaping '%' characters
                # that might be present.
                no_interpolation = ('pki_admin_password', 'pki_backup_password',
                                    'pki_client_database_password',
                                    'pki_client_pkcs12_password',
                                    'pki_ds_password', 'pki_security_domain_password')

                print 'Loading deployment configuration from ' + config.user_deployment_cfg + '.'
                self.pki_config.read([config.user_deployment_cfg])
                config.user_config.read([config.user_deployment_cfg])

                # Look through each section and see if any password settings
                # are present.  If so, escape any '%' characters.
                sections = self.pki_config.sections()
                if sections:
                    sections.append('DEFAULT')
                    for section in sections:
                        for key in no_interpolation:
                            try:
                                val =  self.pki_config.get(section, key, raw=True)
                                if val:
                                    self.pki_config.set(section, key, val.replace("%", "%%"))
                            except ConfigParser.NoOptionError:
                                continue

                sections = config.user_config.sections()
                if sections:
                    sections.append('DEFAULT')
                    for section in sections:
                        for key in no_interpolation:
                            try:
                                val =  config.user_config.get(section, key, raw=True)
                                if val:
                                    config.user_config.set(section, key, val.replace("%", "%%"))
                            except ConfigParser.NoOptionError:
                                continue
        except ConfigParser.ParsingError, err:
            print err
            rv = err
        return rv


    def flatten_master_dict(self):
        self.pki_master_dict.update(__name__="PKI Master Dictionary")

        default_dict = dict(self.pki_config.items('DEFAULT'))
        default_dict[0] = None
        self.pki_master_dict.update(default_dict)

        web_server_dict = None
        if config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
            if self.pki_config.has_section('Tomcat'):
                web_server_dict = dict(self.pki_config.items('Tomcat'))
        else:
            if self.pki_config.has_section('Apache'):
                web_server_dict = dict(self.pki_config.items('Apache'))

        if web_server_dict:
            web_server_dict[0] = None
            self.pki_master_dict.update(web_server_dict)

        if self.pki_config.has_section(config.pki_subsystem):
            subsystem_dict = dict(self.pki_config.items(config.pki_subsystem))
            subsystem_dict[0] = None
            self.pki_master_dict.update(subsystem_dict)


    def ds_connect(self):

        hostname = self.pki_master_dict['pki_ds_hostname']

        if config.str2bool(self.pki_master_dict['pki_ds_secure_connection']):
            protocol = 'ldaps'
            port = self.pki_master_dict['pki_ds_ldaps_port']
        else:
            protocol = 'ldap'
            port = self.pki_master_dict['pki_ds_ldap_port']

        self.ds_connection = ldap.initialize(protocol + '://' + hostname + ':' + port)
        self.ds_connection.search_s('', ldap.SCOPE_BASE)

    def ds_bind(self):
        self.ds_connection.simple_bind_s(
            self.pki_master_dict['pki_ds_bind_dn'],
            self.pki_master_dict['pki_ds_password'])

    def ds_base_dn_exists(self):
        try:
            results = self.ds_connection.search_s(
                self.pki_master_dict['pki_ds_base_dn'],
                ldap.SCOPE_BASE)

            if results is None or len(results) == 0:
                return False

            return True

        except ldap.NO_SUCH_OBJECT:
            return False

    def ds_close(self):
        self.ds_connection.unbind_s()

    def sd_connect(self):
        self.sd_connection = pki.client.PKIConnection(
            protocol='https',
            hostname=self.pki_master_dict['pki_security_domain_hostname'],
            port=self.pki_master_dict['pki_security_domain_https_port'],
            subsystem='ca')

    def sd_get_info(self):
        sd = pki.system.SecurityDomainClient(self.sd_connection)
        try:
            info = sd.getSecurityDomainInfo()
        except requests.exceptions.HTTPError as e:
            config.pki_log.info(
                "unable to access security domain through REST interface.  " + \
                "Trying old interface. " + str(e),
                 extra=config.PKI_INDENTATION_LEVEL_2)
            info = sd.getOldSecurityDomainInfo()
        return info

    def sd_authenticate(self):
        self.sd_connection.authenticate(
            self.pki_master_dict['pki_security_domain_user'],
            self.pki_master_dict['pki_security_domain_password'])

        account = pki.account.AccountClient(self.sd_connection)
        try:
            account.login()
            account.logout()
        except requests.exceptions.HTTPError as e:
            code = e.response.status_code
            if code == 404 or code == 501:
                config.pki_log.warning(
                    "unable to validate security domain user/password " + \
                    "through REST interface. Interface not available",
                     extra=config.PKI_INDENTATION_LEVEL_2)
            else:
                raise

    def authdb_connect(self):

        hostname = self.pki_master_dict['pki_authdb_hostname']
        port = self.pki_master_dict['pki_authdb_port']

        if config.str2bool(self.pki_master_dict['pki_authdb_secure_conn']):
            protocol = 'ldaps'
        else:
            protocol = 'ldap'

        self.authdb_connection = ldap.initialize(protocol + '://' + hostname + ':' + port)
        self.authdb_connection.search_s('', ldap.SCOPE_BASE)

    def authdb_base_dn_exists(self):
        try:
            results = self.authdb_connection.search_s(
                self.pki_master_dict['pki_authdb_basedn'],
                ldap.SCOPE_BASE)

            if results is None or len(results) == 0:
                return False

            return True

        except ldap.NO_SUCH_OBJECT:
            return False

    def get_server_status(self, system_type, system_uri):
        parse = urlparse(self.pki_master_dict[system_uri])
        conn = pki.client.PKIConnection(
                   protocol=parse.scheme,
                   hostname=parse.hostname,
                   port=str(parse.port),
                   subsystem=system_type)
        client = pki.system.SystemStatusClient(conn)
        response = client.getStatus()
        root = ET.fromstring(response)
        return root.findtext("Status")

    def compose_pki_master_dictionary(self):
        "Create a single master PKI dictionary from the sectional dictionaries"
        try:
            # 'pkispawn'/'pkidestroy' name/value pairs
            self.pki_master_dict['pki_deployment_executable'] = \
                config.pki_deployment_executable
            self.pki_master_dict['pki_install_time'] = config.pki_install_time
            self.pki_master_dict['pki_timestamp'] = config.pki_timestamp
            self.pki_master_dict['pki_certificate_timestamp'] = \
                config.pki_certificate_timestamp
            self.pki_master_dict['pki_architecture'] = config.pki_architecture
            self.pki_master_dict['pki_default_deployment_cfg'] = config.default_deployment_cfg
            self.pki_master_dict['pki_user_deployment_cfg'] = config.user_deployment_cfg
            self.pki_master_dict['pki_deployed_instance_name'] = \
                config.pki_deployed_instance_name
            # Generate random 'pin's for use as security database passwords
            # and add these to the "sensitive" key value pairs read in from
            # the configuration file
            pin_low = 100000000000
            pin_high = 999999999999
            self.pki_master_dict['pki_pin'] = \
                random.randint(pin_low, pin_high)
            self.pki_master_dict['pki_client_pin'] = \
                random.randint(pin_low, pin_high)

            self.flatten_master_dict()

            pkilogging.sensitive_parameters = self.pki_master_dict['sensitive_parameters'].split()

            # Always create "false" values for these missing "boolean" keys
            if not self.pki_master_dict.has_key('pki_enable_access_log') or\
               not len(self.pki_master_dict['pki_enable_access_log']):
                self.pki_master_dict['pki_enable_access_log'] = "false"
            if not self.pki_master_dict.has_key('pki_external') or\
               not len(self.pki_master_dict['pki_external']):
                self.pki_master_dict['pki_external'] = "false"
            if not self.pki_master_dict.has_key('pki_external_step_two') or\
               not len(self.pki_master_dict['pki_external_step_two']):
                self.pki_master_dict['pki_external_step_two'] = "false"
            if not self.pki_master_dict.has_key('pki_standalone') or\
               not len(self.pki_master_dict['pki_standalone']):
                self.pki_master_dict['pki_standalone'] = "false"
            if not self.pki_master_dict.has_key('pki_subordinate') or\
               not len(self.pki_master_dict['pki_subordinate']):
                self.pki_master_dict['pki_subordinate'] = "false"

            # PKI Target (slot substitution) name/value pairs
            self.pki_master_dict['pki_target_cs_cfg'] = \
                os.path.join(
                    self.pki_master_dict['pki_subsystem_configuration_path'],
                    "CS.cfg")
            self.pki_master_dict['pki_target_registry'] = \
                os.path.join(self.pki_master_dict['pki_instance_registry_path'],
                             self.pki_master_dict['pki_instance_name'])
            if (config.str2bool(self.pki_master_dict['pki_external_step_two'])):
                # For CA (External CA Step 2) and Stand-alone PKI (Step 2),
                # use the 'pki_one_time_pin' established during the setup
                # of (Step 1)
                if os.path.exists(self.pki_master_dict['pki_target_cs_cfg'])\
                   and\
                   os.path.isfile(self.pki_master_dict['pki_target_cs_cfg']):
                    cs_cfg = self.read_simple_configuration_file(
                                 self.pki_master_dict['pki_target_cs_cfg'])
                    self.pki_master_dict['pki_one_time_pin'] = \
                        cs_cfg.get('preop.pin')
                else:
                    config.pki_log.error(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                        self.pki_master_dict['pki_target_cs_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    raise Exception(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1)
            else:
                # Generate a one-time pin to be used prior to configuration
                # and add this to the "sensitive" key value pairs read in from
                # the configuration file
                self.pki_master_dict['pki_one_time_pin'] = \
                    ''.join(random.choice(string.ascii_letters + string.digits)\
                    for x in range(20))
            if self.pki_master_dict['pki_subsystem'] in\
               config.PKI_TOMCAT_SUBSYSTEMS:
                self.pki_master_dict['pki_target_catalina_properties'] = \
                    os.path.join(
                        self.pki_master_dict['pki_instance_configuration_path'],
                        "catalina.properties")
                self.pki_master_dict['pki_target_servercertnick_conf'] = \
                    os.path.join(
                        self.pki_master_dict['pki_instance_configuration_path'],
                        "serverCertNick.conf")
                self.pki_master_dict['pki_target_server_xml'] = \
                    os.path.join(
                        self.pki_master_dict['pki_instance_configuration_path'],
                        "server.xml")
                self.pki_master_dict['pki_target_context_xml'] = \
                    os.path.join(
                        self.pki_master_dict['pki_instance_configuration_path'],
                        "context.xml")
                self.pki_master_dict['pki_target_tomcat_conf_instance_id'] = \
                    self.pki_master_dict['pki_root_prefix'] + \
                    "/etc/sysconfig/" + \
                    self.pki_master_dict['pki_instance_name']
                self.pki_master_dict['pki_target_tomcat_conf'] = \
                    os.path.join(
                        self.pki_master_dict['pki_instance_configuration_path'],
                        "tomcat.conf")
                # in-place slot substitution name/value pairs
                self.pki_master_dict['pki_target_velocity_properties'] = \
                    os.path.join(
                        self.pki_master_dict['pki_tomcat_webapps_subsystem_path'],
                        "WEB-INF",
                        "velocity.properties")
                self.pki_master_dict['pki_target_subsystem_web_xml'] = \
                    os.path.join(
                        self.pki_master_dict['pki_tomcat_webapps_subsystem_path'],
                        "WEB-INF",
                        "web.xml")
                self.pki_master_dict['pki_target_subsystem_web_xml_orig'] = \
                    os.path.join(
                        self.pki_master_dict['pki_tomcat_webapps_subsystem_path'],
                        "WEB-INF",
                        "web.xml.orig")
                # subystem-specific slot substitution name/value pairs
                if self.pki_master_dict['pki_subsystem'] == "CA":
                    self.pki_master_dict['pki_target_flatfile_txt'] = \
                        os.path.join(self.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "flatfile.txt")
                    self.pki_master_dict['pki_target_proxy_conf'] = \
                        os.path.join(self.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "proxy.conf")
                    self.pki_master_dict['pki_target_registry_cfg'] = \
                        os.path.join(self.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "registry.cfg")
                    # '*.profile'
                    self.pki_master_dict['pki_target_admincert_profile'] = \
                        os.path.join(self.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "adminCert.profile")
                    self.pki_master_dict['pki_target_caauditsigningcert_profile']\
 = os.path.join(self.pki_master_dict\
                                       ['pki_subsystem_configuration_path'],
                                       "caAuditSigningCert.profile")
                    self.pki_master_dict['pki_target_cacert_profile'] = \
                        os.path.join(self.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "caCert.profile")
                    self.pki_master_dict['pki_target_caocspcert_profile'] = \
                        os.path.join(self.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "caOCSPCert.profile")
                    self.pki_master_dict['pki_target_servercert_profile'] = \
                        os.path.join(self.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "serverCert.profile")
                    self.pki_master_dict['pki_target_subsystemcert_profile'] = \
                        os.path.join(self.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "subsystemCert.profile")
                    # in-place slot substitution name/value pairs
                    self.pki_master_dict['pki_target_profileselect_template'] = \
                        os.path.join(
                            self.pki_master_dict\
                            ['pki_tomcat_webapps_subsystem_path'],
                            "ee",
                            self.pki_master_dict['pki_subsystem'].lower(),
                            "ProfileSelect.template")
                elif self.pki_master_dict['pki_subsystem'] == "KRA":
                    # '*.profile'
                    self.pki_master_dict['pki_target_servercert_profile'] = \
                        os.path.join(self.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "serverCert.profile")
                    self.pki_master_dict['pki_target_storagecert_profile'] = \
                        os.path.join(self.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "storageCert.profile")
                    self.pki_master_dict['pki_target_subsystemcert_profile'] = \
                        os.path.join(self.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "subsystemCert.profile")
                    self.pki_master_dict['pki_target_transportcert_profile'] = \
                        os.path.join(self.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "transportCert.profile")
            # Slot assignment name/value pairs
            #     NOTE:  Master key == Slots key; Master value ==> Slots value
            self.pki_master_dict['PKI_INSTANCE_NAME_SLOT'] = \
                self.pki_master_dict['pki_instance_name']
            self.pki_master_dict['PKI_INSTANCE_INITSCRIPT_SLOT'] = \
                os.path.join(self.pki_master_dict['pki_instance_path'],
                             self.pki_master_dict['pki_instance_name'])
            self.pki_master_dict['PKI_REGISTRY_FILE_SLOT'] = \
                os.path.join(self.pki_master_dict['pki_subsystem_registry_path'],
                             self.pki_master_dict['pki_instance_name'])
            if self.pki_master_dict['pki_subsystem'] in\
               config.PKI_APACHE_SUBSYSTEMS:
                self.pki_master_dict['FORTITUDE_APACHE_SLOT'] = None
                self.pki_master_dict['FORTITUDE_AUTH_MODULES_SLOT'] = None
                self.pki_master_dict['FORTITUDE_DIR_SLOT'] = None
                self.pki_master_dict['FORTITUDE_LIB_DIR_SLOT'] = None
                self.pki_master_dict['FORTITUDE_MODULE_SLOT'] = None
                self.pki_master_dict['FORTITUDE_NSS_MODULES_SLOT'] = None
                self.pki_master_dict['HTTPD_CONF_SLOT'] = None
                self.pki_master_dict['LIB_PREFIX_SLOT'] = None
                self.pki_master_dict['NON_CLIENTAUTH_SECURE_PORT_SLOT'] = None
                self.pki_master_dict['NSS_CONF_SLOT'] = None
                self.pki_master_dict['OBJ_EXT_SLOT'] = None
                self.pki_master_dict['PKI_LOCKDIR_SLOT'] = \
                    os.path.join("/var/lock/pki",
                                 "apache")
                self.pki_master_dict['PKI_PIDDIR_SLOT'] = \
                    os.path.join("/var/run/pki",
                                 "apache")
                self.pki_master_dict['PKI_WEB_SERVER_TYPE_SLOT'] = "apache"
                self.pki_master_dict['PORT_SLOT'] = None
                self.pki_master_dict['PROCESS_ID_SLOT'] = None
                self.pki_master_dict['REQUIRE_CFG_PL_SLOT'] = None
                self.pki_master_dict['SECURE_PORT_SLOT'] = None
                self.pki_master_dict['SECURITY_LIBRARIES_SLOT'] = None
                self.pki_master_dict['PKI_HOSTNAME_SLOT'] = None
                self.pki_master_dict['SERVER_ROOT_SLOT'] = None
                self.pki_master_dict['SYSTEM_LIBRARIES_SLOT'] = None
                self.pki_master_dict['SYSTEM_USER_LIBRARIES_SLOT'] = None
                self.pki_master_dict['TMP_DIR_SLOT'] = None
            elif self.pki_master_dict['pki_subsystem'] in\
                 config.PKI_TOMCAT_SUBSYSTEMS:
                self.pki_master_dict['INSTALL_TIME_SLOT'] = \
                    self.pki_master_dict['pki_install_time']
                self.pki_master_dict['PKI_ADMIN_SECURE_PORT_SLOT'] = \
                    self.pki_master_dict['pki_https_port']
                self.pki_master_dict\
                ['PKI_ADMIN_SECURE_PORT_CONNECTOR_NAME_SLOT'] = \
                    "Unused"
                self.pki_master_dict\
                ['PKI_ADMIN_SECURE_PORT_SERVER_COMMENT_SLOT'] = \
                    ""
                self.pki_master_dict['PKI_AGENT_CLIENTAUTH_SLOT'] = \
                    "want"
                self.pki_master_dict['PKI_AGENT_SECURE_PORT_SLOT'] = \
                    self.pki_master_dict['pki_https_port']
                self.pki_master_dict['PKI_AJP_PORT_SLOT'] = \
                    self.pki_master_dict['pki_ajp_port']
                self.pki_master_dict['PKI_AJP_REDIRECT_PORT_SLOT'] = \
                    self.pki_master_dict['pki_https_port']
                self.pki_master_dict['PKI_CA_HOSTNAME_SLOT'] = \
                    self.pki_master_dict['pki_ca_hostname']
                self.pki_master_dict['PKI_CA_PORT_SLOT'] = \
                    self.pki_master_dict['pki_ca_port']
                self.pki_master_dict['PKI_CERT_DB_PASSWORD_SLOT'] = \
                    self.pki_master_dict['pki_pin']
                self.pki_master_dict['PKI_CFG_PATH_NAME_SLOT'] = \
                    self.pki_master_dict['pki_target_cs_cfg']
                self.pki_master_dict\
                ['PKI_CLOSE_SEPARATE_PORTS_SERVER_COMMENT_SLOT'] = \
                    "-->"
                self.pki_master_dict\
                ['PKI_CLOSE_SEPARATE_PORTS_WEB_COMMENT_SLOT'] = \
                    "-->"
                self.pki_master_dict['PKI_EE_SECURE_CLIENT_AUTH_PORT_SLOT'] = \
                    self.pki_master_dict['pki_https_port']
                self.pki_master_dict\
                ['PKI_EE_SECURE_CLIENT_AUTH_PORT_CONNECTOR_NAME_SLOT'] = \
                    "Unused"
                self.pki_master_dict\
                ['PKI_EE_SECURE_CLIENT_AUTH_PORT_SERVER_COMMENT_SLOT'] = \
                    ""
                self.pki_master_dict['PKI_EE_SECURE_CLIENT_AUTH_PORT_UI_SLOT'] = \
                    self.pki_master_dict['pki_https_port']
                self.pki_master_dict['PKI_EE_SECURE_PORT_SLOT'] = \
                    self.pki_master_dict['pki_https_port']
                self.pki_master_dict['PKI_EE_SECURE_PORT_CONNECTOR_NAME_SLOT'] = \
                    "Unused"
                self.pki_master_dict['PKI_EE_SECURE_PORT_SERVER_COMMENT_SLOT'] = \
                    ""
                self.pki_master_dict['PKI_GROUP_SLOT'] = \
                    self.pki_master_dict['pki_group']
                self.pki_master_dict['PKI_INSTANCE_PATH_SLOT'] = \
                    self.pki_master_dict['pki_instance_path']
                self.pki_master_dict['PKI_INSTANCE_ROOT_SLOT'] = \
                    self.pki_master_dict['pki_path']
                self.pki_master_dict['PKI_LOCKDIR_SLOT'] = \
                    os.path.join("/var/lock/pki",
                                 "tomcat")
                self.pki_master_dict['PKI_HOSTNAME_SLOT'] = \
                    self.pki_master_dict['pki_hostname']
                self.pki_master_dict\
                ['PKI_OPEN_SEPARATE_PORTS_SERVER_COMMENT_SLOT'] = \
                    "<!--"
                self.pki_master_dict\
                ['PKI_OPEN_SEPARATE_PORTS_WEB_COMMENT_SLOT'] = \
                    "<!--"
                self.pki_master_dict['PKI_PIDDIR_SLOT'] = \
                    os.path.join("/var/run/pki",
                                 "tomcat")
                if config.str2bool(self.pki_master_dict['pki_enable_proxy']):
                    self.pki_master_dict['PKI_CLOSE_AJP_PORT_COMMENT_SLOT'] = \
                        ""
                    self.pki_master_dict['PKI_CLOSE_ENABLE_PROXY_COMMENT_SLOT'] = \
                        ""
                    self.pki_master_dict['PKI_PROXY_SECURE_PORT_SLOT'] = \
                        self.pki_master_dict['pki_proxy_https_port']
                    self.pki_master_dict['PKI_PROXY_UNSECURE_PORT_SLOT'] = \
                        self.pki_master_dict['pki_proxy_http_port']
                    self.pki_master_dict['PKI_OPEN_AJP_PORT_COMMENT_SLOT'] = \
                        ""
                    self.pki_master_dict['PKI_OPEN_ENABLE_PROXY_COMMENT_SLOT'] = \
                        ""
                else:
                    self.pki_master_dict['PKI_CLOSE_AJP_PORT_COMMENT_SLOT'] = \
                        "-->"
                    self.pki_master_dict['PKI_CLOSE_ENABLE_PROXY_COMMENT_SLOT'] = \
                        "-->"
                    self.pki_master_dict['PKI_PROXY_SECURE_PORT_SLOT'] = ""
                    self.pki_master_dict['PKI_PROXY_UNSECURE_PORT_SLOT'] = ""
                    self.pki_master_dict['PKI_OPEN_AJP_PORT_COMMENT_SLOT'] = \
                        "<!--"
                    self.pki_master_dict['PKI_OPEN_ENABLE_PROXY_COMMENT_SLOT'] = \
                        "<!--"
                if (config.str2bool(self.pki_master_dict['pki_standalone'])):
                    # Stand-alone PKI
                    self.pki_master_dict['PKI_CLOSE_STANDALONE_COMMENT_SLOT'] = \
                        ""
                    self.pki_master_dict['PKI_OPEN_STANDALONE_COMMENT_SLOT'] = \
                        ""
                    self.pki_master_dict['PKI_STANDALONE_SLOT'] = "true"
                else:
                    self.pki_master_dict['PKI_CLOSE_STANDALONE_COMMENT_SLOT'] = \
                        "-->"
                    self.pki_master_dict['PKI_OPEN_STANDALONE_COMMENT_SLOT'] = \
                        "<!--"
                    self.pki_master_dict['PKI_STANDALONE_SLOT'] = "false"
                if (config.str2bool(self.pki_master_dict['pki_enable_access_log'])):
                    self.pki_master_dict['PKI_CLOSE_TOMCAT_ACCESS_LOG_COMMENT_SLOT'] = \
                        ""
                    self.pki_master_dict['PKI_OPEN_TOMCAT_ACCESS_LOG_COMMENT_SLOT'] = \
                        ""
                else:
                    self.pki_master_dict['PKI_CLOSE_TOMCAT_ACCESS_LOG_COMMENT_SLOT'] = \
                        "-->"
                    self.pki_master_dict['PKI_OPEN_TOMCAT_ACCESS_LOG_COMMENT_SLOT'] = \
                        "<!--"
                self.pki_master_dict['PKI_TMPDIR_SLOT'] = \
                    self.pki_master_dict['pki_tomcat_tmpdir_path']
                self.pki_master_dict['PKI_RESTEASY_LIB_SLOT'] = \
                    self.pki_master_dict['resteasy_lib']
                self.pki_master_dict['PKI_RANDOM_NUMBER_SLOT'] = \
                    self.pki_master_dict['pki_one_time_pin']
                self.pki_master_dict['PKI_SECURE_PORT_SLOT'] = \
                    self.pki_master_dict['pki_https_port']
                self.pki_master_dict['PKI_SECURE_PORT_CONNECTOR_NAME_SLOT'] = \
                    "Secure"
                self.pki_master_dict['PKI_SECURE_PORT_SERVER_COMMENT_SLOT'] = \
                    "<!-- " + \
                    "Shared Ports:  Agent, EE, and Admin Secure Port Connector " + \
                    "-->"
                self.pki_master_dict['PKI_SECURITY_MANAGER_SLOT'] = \
                    self.pki_master_dict['pki_security_manager']
                self.pki_master_dict['PKI_SERVER_XML_CONF_SLOT'] = \
                    self.pki_master_dict['pki_target_server_xml']
                self.pki_master_dict['PKI_SSL_SERVER_NICKNAME_SLOT'] = \
                    self.pki_master_dict['pki_ssl_server_nickname']
                self.pki_master_dict['PKI_SUBSYSTEM_TYPE_SLOT'] = \
                    self.pki_master_dict['pki_subsystem'].lower()
                self.pki_master_dict['PKI_SYSTEMD_SERVICENAME_SLOT'] = \
                    "pki-tomcatd" + "@" + \
                    self.pki_master_dict['pki_instance_name'] + ".service"
                self.pki_master_dict['PKI_UNSECURE_PORT_SLOT'] = \
                    self.pki_master_dict['pki_http_port']
                self.pki_master_dict['PKI_UNSECURE_PORT_CONNECTOR_NAME_SLOT'] = \
                    "Unsecure"
                self.pki_master_dict['PKI_UNSECURE_PORT_SERVER_COMMENT_SLOT'] = \
                    "<!-- Shared Ports:  Unsecure Port Connector -->"
                self.pki_master_dict['PKI_USER_SLOT'] = \
                    self.pki_master_dict['pki_user']
                self.pki_master_dict['PKI_WEB_SERVER_TYPE_SLOT'] = \
                    "tomcat"
                self.pki_master_dict['PKI_WEBAPPS_NAME_SLOT'] = \
                    "webapps"
                self.pki_master_dict['TOMCAT_CFG_SLOT'] = \
                    self.pki_master_dict['pki_target_tomcat_conf']
                self.pki_master_dict['TOMCAT_INSTANCE_COMMON_LIB_SLOT'] = \
                    os.path.join(
                        self.pki_master_dict['pki_tomcat_common_lib_path'],
                        "*.jar")
                self.pki_master_dict['TOMCAT_LOG_DIR_SLOT'] = \
                    self.pki_master_dict['pki_instance_log_path']
                self.pki_master_dict['TOMCAT_PIDFILE_SLOT'] = \
                    "/var/run/pki/tomcat/" + self.pki_master_dict['pki_instance_name'] + ".pid"
                self.pki_master_dict['TOMCAT_SERVER_PORT_SLOT'] = \
                    self.pki_master_dict['pki_tomcat_server_port']
                self.pki_master_dict['TOMCAT_SSL2_CIPHERS_SLOT'] = \
                    "-SSL2_RC4_128_WITH_MD5," + \
                    "-SSL2_RC4_128_EXPORT40_WITH_MD5," + \
                    "-SSL2_RC2_128_CBC_WITH_MD5," + \
                    "-SSL2_RC2_128_CBC_EXPORT40_WITH_MD5," + \
                    "-SSL2_DES_64_CBC_WITH_MD5," + \
                    "-SSL2_DES_192_EDE3_CBC_WITH_MD5"
                self.pki_master_dict['TOMCAT_SSL3_CIPHERS_SLOT'] = \
                    "-SSL3_FORTEZZA_DMS_WITH_NULL_SHA," + \
                    "-SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA," + \
                    "+SSL3_RSA_WITH_RC4_128_SHA," + \
                    "-SSL3_RSA_EXPORT_WITH_RC4_40_MD5," + \
                    "+SSL3_RSA_WITH_3DES_EDE_CBC_SHA," + \
                    "-SSL3_RSA_WITH_DES_CBC_SHA," + \
                    "-SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5," + \
                    "-SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA," + \
                    "-SSL_RSA_FIPS_WITH_DES_CBC_SHA," + \
                    "+SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA," + \
                    "-SSL3_RSA_WITH_NULL_MD5," + \
                    "-TLS_RSA_EXPORT1024_WITH_RC4_56_SHA," + \
                    "-TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA," + \
                    "+TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
                self.pki_master_dict['TOMCAT_SSL_OPTIONS_SLOT'] = \
                    "ssl2=true," + \
                    "ssl3=true," + \
                    "tls=true"
                self.pki_master_dict['TOMCAT_TLS_CIPHERS_SLOT'] = \
                    "-TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA," + \
                    "-TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA," + \
                    "+TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA," + \
                    "+TLS_ECDH_RSA_WITH_AES_128_CBC_SHA," + \
                    "+TLS_ECDH_RSA_WITH_AES_256_CBC_SHA," + \
                    "-TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA," + \
                    "+TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA," + \
                    "+TLS_RSA_WITH_3DES_EDE_CBC_SHA," + \
                    "+TLS_RSA_WITH_AES_128_CBC_SHA," + \
                    "+TLS_RSA_WITH_AES_256_CBC_SHA," + \
                    "+TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA," + \
                    "+TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA," + \
                    "-TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA," + \
                    "-TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA," + \
                    "-TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA," + \
                    "+TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA," + \
                    "+TLS_DHE_DSS_WITH_AES_128_CBC_SHA," + \
                    "+TLS_DHE_DSS_WITH_AES_256_CBC_SHA," + \
                    "+TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA," + \
                    "+TLS_DHE_RSA_WITH_AES_128_CBC_SHA," + \
                    "+TLS_DHE_RSA_WITH_AES_256_CBC_SHA"

                # tps parameters
                self.pki_master_dict['TOKENDB_HOST_SLOT'] = \
                    self.pki_master_dict['pki_ds_hostname']

                if config.str2bool(self.pki_master_dict['pki_ds_secure_connection']):
                    self.pki_master_dict['TOKENDB_PORT_SLOT'] = \
                        self.pki_master_dict['pki_ds_ldaps_port']
                else:
                    self.pki_master_dict['TOKENDB_PORT_SLOT'] = \
                        self.pki_master_dict['pki_ds_ldap_port']

                self.pki_master_dict['TOKENDB_ROOT_SLOT'] = \
                    self.pki_master_dict['pki_ds_base_dn']

                self.pki_master_dict['TPS_DIR_SLOT'] = \
                    self.pki_master_dict['pki_source_subsystem_path']

                if self.pki_master_dict['pki_subsystem'] == "CA":
                    self.pki_master_dict['PKI_ENABLE_RANDOM_SERIAL_NUMBERS'] = \
                        self.pki_master_dict\
                        ['pki_random_serial_numbers_enable'].lower()
            # Shared Apache/Tomcat NSS security database name/value pairs
            self.pki_master_dict['pki_shared_pfile'] = \
                os.path.join(
                    self.pki_master_dict['pki_instance_configuration_path'],
                    "pfile")
            self.pki_master_dict['pki_shared_password_conf'] = \
                os.path.join(
                    self.pki_master_dict['pki_instance_configuration_path'],
                    "password.conf")
            self.pki_master_dict['pki_cert_database'] = \
                os.path.join(self.pki_master_dict['pki_database_path'],
                             "cert8.db")
            self.pki_master_dict['pki_key_database'] = \
                os.path.join(self.pki_master_dict['pki_database_path'],
                             "key3.db")
            self.pki_master_dict['pki_secmod_database'] = \
                os.path.join(self.pki_master_dict['pki_database_path'],
                             "secmod.db")
            self.pki_master_dict['pki_self_signed_token'] = "internal"
            self.pki_master_dict['pki_self_signed_nickname'] = \
                self.pki_master_dict['pki_ssl_server_nickname']
            self.pki_master_dict['pki_self_signed_subject'] = \
                "cn=" + self.pki_master_dict['pki_hostname'] + "," + \
                "o=" + self.pki_master_dict['pki_certificate_timestamp']
            self.pki_master_dict['pki_self_signed_serial_number'] = 0
            self.pki_master_dict['pki_self_signed_validity_period'] = 12
            self.pki_master_dict['pki_self_signed_issuer_name'] = \
                "cn=" + self.pki_master_dict['pki_hostname'] + "," + \
                "o=" + self.pki_master_dict['pki_certificate_timestamp']
            self.pki_master_dict['pki_self_signed_trustargs'] = "CTu,CTu,CTu"
            self.pki_master_dict['pki_self_signed_noise_file'] = \
                os.path.join(
                    self.pki_master_dict['pki_subsystem_configuration_path'],
                    "noise")
            self.pki_master_dict['pki_self_signed_noise_bytes'] = 1024
            # Shared Apache/Tomcat NSS security database convenience symbolic links
            self.pki_master_dict\
            ['pki_subsystem_configuration_password_conf_link'] = \
                os.path.join(
                    self.pki_master_dict['pki_subsystem_configuration_path'],
                    "password.conf")

            if not len(self.pki_master_dict['pki_client_database_password']):
                # use randomly generated client 'pin'
                self.pki_master_dict['pki_client_database_password'] = \
                    str(self.pki_master_dict['pki_client_pin'])

            # Configuration scriptlet
            # 'Security Domain' Configuration name/value pairs
            # 'Subsystem Name'  Configuration name/value pairs
            # 'Token'           Configuration name/value pairs
            #
            #     Apache - [RA]
            #     Tomcat - [CA], [KRA], [OCSP], [TKS], [TPS]
            #            - [CA Clone], [KRA Clone], [OCSP Clone], [TKS Clone], [TPS Clone]
            #            - [External CA]
            #            - [Subordinate CA]
            #
            #     The following variables are defined below:
            #
            #         self.pki_master_dict['pki_security_domain_type']
            #         self.pki_master_dict['pki_security_domain_uri']
            #
            #     The following variables are established via the specified PKI
            #     deployment configuration file and are NOT redefined below:
            #
            #         self.pki_master_dict['pki_clone_pkcs12_password']
            #         self.pki_master_dict['pki_security_domain_password']
            #         self.pki_master_dict['pki_token_password']
            #         self.pki_master_dict['pki_clone_pkcs12_path']
            #         self.pki_master_dict['pki_clone_uri']
            #         self.pki_master_dict['pki_security_domain_https_port']
            #         self.pki_master_dict['pki_token_name']
            #
            #     The following variables are established via the specified PKI
            #     deployment configuration file and potentially overridden below:
            #
            #         self.pki_master_dict['pki_security_domain_user']
            #         self.pki_master_dict['pki_issuing_ca']
            #

            # if security domain user is not defined
            if not len(self.pki_master_dict['pki_security_domain_user']):

                # use the CA admin uid if it's defined
                if self.pki_config.has_option('CA', 'pki_admin_uid') and\
                    len(self.pki_config.get('CA', 'pki_admin_uid')) > 0:
                    self.pki_master_dict['pki_security_domain_user'] = \
                        self.pki_config.get('CA', 'pki_admin_uid')

                # or use the Default admin uid if it's defined
                elif self.pki_config.has_option('DEFAULT', 'pki_admin_uid') and\
                    len(self.pki_config.get('DEFAULT', 'pki_admin_uid')) > 0:
                    self.pki_master_dict['pki_security_domain_user'] = \
                        self.pki_config.get('DEFAULT', 'pki_admin_uid')

                # otherwise use the default CA admin uid
                else:
                    self.pki_master_dict['pki_security_domain_user'] = "caadmin"

            if not config.str2bool(self.pki_master_dict['pki_skip_configuration']) and\
               (config.str2bool(self.pki_master_dict['pki_standalone'])):
                # Stand-alone PKI
                self.pki_master_dict['pki_security_domain_type'] = "new"
                self.pki_master_dict['pki_issuing_ca'] = "External CA"
            elif config.pki_subsystem != "CA" or\
                 config.str2bool(self.pki_master_dict['pki_clone']) or\
                 config.str2bool(self.pki_master_dict['pki_subordinate']):
                # PKI KRA, PKI OCSP, PKI RA, PKI TKS, PKI TPS,
                # CA Clone, KRA Clone, OCSP Clone, TKS Clone, TPS Clone, or
                # Subordinate CA
                self.pki_master_dict['pki_security_domain_type'] = "existing"
                self.pki_master_dict['pki_security_domain_uri'] = \
                    "https" + "://" + \
                    self.pki_master_dict['pki_security_domain_hostname'] + ":" + \
                    self.pki_master_dict['pki_security_domain_https_port']

            elif config.str2bool(self.pki_master_dict['pki_external']):
                # External CA
                self.pki_master_dict['pki_security_domain_type'] = "new"
                self.pki_master_dict['pki_issuing_ca'] = "External CA"
            else:
                # PKI CA
                self.pki_master_dict['pki_security_domain_type'] = "new"

            # 'External CA' Configuration name/value pairs
            #
            #     Tomcat - [External CA]
            #
            #     The following variables are established via the specified PKI
            #     deployment configuration file and are NOT redefined below:
            #
            #        self.pki_master_dict['pki_external_ca_cert_chain_path']
            #        self.pki_master_dict['pki_external_ca_cert_path']
            #        self.pki_master_dict['pki_external_csr_path']
            #        self.pki_master_dict['pki_external_step_two']
            #

            # 'Backup' Configuration name/value pairs
            #
            #     Apache - [RA]
            #     Tomcat - [CA], [KRA], [OCSP], [TKS], [TPS]
            #            - [External CA]
            #            - [Subordinate CA]
            #
            #     The following variables are established via the specified PKI
            #     deployment configuration file and are NOT redefined below:
            #
            #        self.pki_master_dict['pki_backup_password']
            #        self.pki_master_dict['pki_backup_keys']
            #
            if config.str2bool(self.pki_master_dict['pki_backup_keys']):
                # NOTE:  ALWAYS store the PKCS #12 backup keys file
                #        in with the NSS "server" security databases
                self.pki_master_dict['pki_backup_keys_p12'] = \
                    self.pki_master_dict['pki_database_path'] + "/" + \
                    self.pki_master_dict['pki_subsystem'].lower() + "_" + \
                    "backup" + "_" + "keys" + "." + "p12"

            self.pki_master_dict['pki_admin_profile_id'] = "caAdminCert"

            if not 'pki_import_admin_cert' in self.pki_master_dict:
                self.pki_master_dict['pki_import_admin_cert'] = 'false'
            elif not config.str2bool(self.pki_master_dict['pki_skip_configuration']) and\
                 (config.str2bool(self.pki_master_dict['pki_standalone'])):
                # Stand-alone PKI
                self.pki_master_dict['pki_import_admin_cert'] = 'false'

            if (config.str2bool(self.pki_master_dict['pki_standalone'])):
                self.pki_master_dict['pki_ca_signing_tag'] = "external_signing"
            else:
                self.pki_master_dict['pki_ca_signing_tag'] = "signing"
            if self.pki_master_dict['pki_subsystem'] == "CA":
                self.pki_master_dict['pki_ocsp_signing_tag'] = "ocsp_signing"
            elif self.pki_master_dict['pki_subsystem'] == "OCSP":
                self.pki_master_dict['pki_ocsp_signing_tag'] = "signing"
            self.pki_master_dict['pki_ssl_server_tag'] = "sslserver"
            self.pki_master_dict['pki_subsystem_tag'] = "subsystem"
            self.pki_master_dict['pki_audit_signing_tag'] = "audit_signing"
            self.pki_master_dict['pki_transport_tag'] = "transport"
            self.pki_master_dict['pki_storage_tag'] = "storage"

            # Finalization name/value pairs
            self.pki_master_dict['pki_default_deployment_cfg_replica'] = \
                os.path.join(self.pki_master_dict['pki_subsystem_registry_path'],
                             config.DEFAULT_DEPLOYMENT_CONFIGURATION)
            self.pki_master_dict['pki_user_deployment_cfg_replica'] = \
                os.path.join(self.pki_master_dict['pki_subsystem_registry_path'],
                             config.USER_DEPLOYMENT_CONFIGURATION)
            self.pki_master_dict['pki_user_deployment_cfg_spawn_archive'] = \
                self.pki_master_dict['pki_subsystem_archive_log_path'] + "/" + \
                "spawn" + "_" + \
                config.USER_DEPLOYMENT_CONFIGURATION + "." + \
                self.pki_master_dict['pki_timestamp']
            self.pki_master_dict['pki_manifest'] = \
                self.pki_master_dict['pki_subsystem_registry_path'] + "/" + \
                "manifest"
            self.pki_master_dict['pki_manifest_spawn_archive'] = \
                self.pki_master_dict['pki_subsystem_archive_log_path'] + "/" + \
                "spawn" + "_" + "manifest" + "." + \
                self.pki_master_dict['pki_timestamp']
            # Construct the configuration URL containing the one-time pin
            # and add this to the "sensitive" key value pairs read in from
            # the configuration file
            #
            # NOTE:  This is the one and only parameter containing a sensitive
            #        parameter that may be stored in a log file and displayed
            #        to the screen.
            #
            self.pki_master_dict['pki_configuration_url'] = \
                "https://{}:{}/{}/{}?pin={}".format(
                    self.pki_master_dict['pki_hostname'],
                    self.pki_master_dict['pki_https_port'],
                    self.pki_master_dict['pki_subsystem'].lower(),
                    "admin/console/config/login",
                    self.pki_master_dict['pki_one_time_pin'])
            # Compose this "systemd" execution management command
            if self.pki_master_dict['pki_subsystem'] in\
               config.PKI_APACHE_SUBSYSTEMS:
                self.pki_master_dict['pki_registry_initscript_command'] = \
                    "systemctl" + " " + \
                    "restart" + " " + \
                    "pki-apached" + "@" + \
                    self.pki_master_dict['pki_instance_name'] + "." + "service"
            elif self.pki_master_dict['pki_subsystem'] in\
                 config.PKI_TOMCAT_SUBSYSTEMS:
                self.pki_master_dict['pki_registry_initscript_command'] = \
                    "systemctl" + " " + \
                    "restart" + " " + \
                    "pki-tomcatd" + "@" + \
                    self.pki_master_dict['pki_instance_name'] + "." + "service"
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise
        except KeyError as err:
            config.pki_log.error(log.PKIHELPER_DICTIONARY_MASTER_MISSING_KEY_1,
                                 err, extra=config.PKI_INDENTATION_LEVEL_2)
            raise
        except ConfigParser.InterpolationSyntaxError as err:
            config.pki_log.error(log.PKIHELPER_DICTIONARY_INTERPOLATION_1,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            config.pki_log.error(log.PKIHELPER_DICTIONARY_INTERPOLATION_2, err,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            raise
        return


    def compose_pki_slots_dictionary(self):
        """Read the slots configuration file to create
           the appropriate PKI slots dictionary"""
        rv = 0
        try:
            parser = ConfigParser.ConfigParser()
            # Make keys case-sensitive!
            parser.optionxform = str
            parser.read(config.PKI_DEPLOYMENT_SLOTS_CONFIGURATION_FILE)
            # Slots configuration file name/value pairs
            if config.pki_subsystem in config.PKI_APACHE_SUBSYSTEMS:
                self.pki_slots_dict = dict(parser.items('Apache'))
            elif config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
                self.pki_slots_dict = dict(parser.items('Tomcat'))
        except ConfigParser.ParsingError, err:
            rv = err
        return rv
