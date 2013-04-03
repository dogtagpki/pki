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
import string
import subprocess
import sys
import time


# PKI Deployment Imports
import pkilogging
import pkiconfig as config
import pkimessages as log

import pki.account
import pki.client
import pki.system

class PKIConfigParser:

    COMMENT_CHAR = '#'
    OPTION_CHAR =  '='

    def __init__(self, description, epilog):
        self.pki_config = None

        "Read and process command-line options"
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

    # PKI Deployment Helper Functions
    def process_command_line_arguments(self, argv):

        # Parse command-line options
        args = self.arg_parser.parse_args()

        # Process 'Mandatory' command-line options

        # Process 'Optional' command-line options
        #    '-v'
        if args.pki_verbosity == 1:
            config.pki_console_log_level = logging.INFO
            config.pki_log_level = logging.INFO
        elif args.pki_verbosity == 2:
            config.pki_console_log_level = logging.INFO
            config.pki_log_level = logging.DEBUG
        elif args.pki_verbosity == 3:
            config.pki_console_log_level = logging.DEBUG
            config.pki_log_level = logging.DEBUG
        elif args.pki_verbosity > 3:
            print "ERROR:  " + log.PKI_VERBOSITY_LEVELS_MESSAGE
            print
            self.arg_parser.print_help()
            self.arg_parser.exit(-1);
        else:
            # Set default log levels
            config.pki_console_log_level = logging.WARNING
            config.pki_log_level = logging.INFO

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
                print "ERROR:  " +\
                      log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 %\
                      config.pki_root_prefix
                print
                self.arg_parser.print_help()
                self.arg_parser.exit(-1);

        # always default that configuration file exists
        if not os.path.exists(config.default_deployment_cfg) or\
            not os.path.isfile(config.default_deployment_cfg):
            print "ERROR:  " +\
                  log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %\
                  config.default_deployment_cfg
            print
            self.arg_parser.print_help()
            self.arg_parser.exit(-1);

        if config.user_deployment_cfg:
            # verify user configuration file exists
            if not os.path.exists(config.user_deployment_cfg) or\
                not os.path.isfile(config.user_deployment_cfg):
                print "ERROR:  " +\
                      log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %\
                      config.user_deployment_cfg
                print
                parser.arg_parser.print_help()
                parser.arg_parser.exit(-1);


    def init_config(self):

        # RESTEasy
        resteasy_lib = subprocess.check_output(\
            'source /etc/pki/pki.conf && echo $RESTEASY_LIB',
            shell=True).strip()

        # JNI jar location
        jni_jar_dir = subprocess.check_output(\
            'source /etc/pki/pki.conf && echo $JNI_JAR_DIR',
            shell=True).strip()

        if config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
            default_instance_name = 'pki-tomcat'
            default_http_port = '8080'
            default_https_port = '8443'
        else:
            default_instance_name = 'pki-apache'
            default_http_port = '80'
            default_https_port = '443'

        self.pki_config = ConfigParser.SafeConfigParser({
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
        f = open(filename)
        for line in f:
            # First, remove comments:
            if PKIConfigParser.COMMENT_CHAR in line:
                # split on comment char, keep only the part before
                line, comment = line.split(PKIConfigParser.COMMENT_CHAR, 1)
            # Second, find lines with an name=value:
            if PKIConfigParser.OPTION_CHAR in line:
                # split on name char:
                name, value = line.split(PKIConfigParser.OPTION_CHAR, 1)
                # strip spaces:
                name = name.strip()
                value = value.strip()
                # store in dictionary:
                values[name] = value
        f.close()
        return values


    def set_property(self, section, property, value):
        if section != "DEFAULT" and not self.pki_config.has_section(section):
            self.pki_config.add_section(section)
        self.pki_config.set(section, property, value)
        self.flatten_master_dict()

        if section != "DEFAULT" and not config.user_config.has_section(section):
            config.user_config.add_section(section)
        config.user_config.set(section, property, value)


    def print_text(self, message):
        print ' ' * self.indent + message

    def read_text(self, message,
        section=None, property=None, default=None,
        options=None, sign=':', allowEmpty=True, caseSensitive=True):

        if default is None and property is not None:
            default = config.pki_master_dict[property]
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
            self.set_property(section, property, value)

        return value


    def read_password(self, message, section=None, property=None,
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
            self.set_property(section, property, password)

        return password

    def read_pki_configuration_file(self):
        "Read configuration file sections into dictionaries"
        rv = 0
        try:
            if config.user_deployment_cfg:
                print 'Loading deployment configuration from ' + config.user_deployment_cfg + '.'
                self.pki_config.read([config.user_deployment_cfg])

        except ConfigParser.ParsingError, err:
            print err
            rv = err
        return rv


    def flatten_master_dict(self):
        config.pki_master_dict.update(__name__="PKI Master Dictionary")

        default_dict = dict(self.pki_config.items('DEFAULT'))
        default_dict[0] = None
        config.pki_master_dict.update(default_dict)

        web_server_dict = None
        if config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
            if self.pki_config.has_section('Tomcat'):
                web_server_dict = dict(self.pki_config.items('Tomcat'))
        else:
            if self.pki_config.has_section('Apache'):
                web_server_dict = dict(self.pki_config.items('Apache'))

        if web_server_dict:
            web_server_dict[0] = None
            config.pki_master_dict.update(web_server_dict)

        if self.pki_config.has_section(config.pki_subsystem):
            subsystem_dict = dict(self.pki_config.items(config.pki_subsystem))
            subsystem_dict[0] = None
            config.pki_master_dict.update(subsystem_dict)


    def ds_connect(self):

        hostname = config.pki_master_dict['pki_ds_hostname']

        if config.str2bool(config.pki_master_dict['pki_ds_secure_connection']):
            protocol = 'ldaps'
            port = config.pki_master_dict['pki_ds_ldaps_port']
        else:
            protocol = 'ldap'
            port = config.pki_master_dict['pki_ds_ldap_port']

        self.ds_connection = ldap.initialize(protocol + '://' + hostname + ':' + port)
        self.ds_connection.search_s('', ldap.SCOPE_BASE)

    def ds_bind(self):
        self.ds_connection.simple_bind_s(
            config.pki_master_dict['pki_ds_bind_dn'],
            config.pki_master_dict['pki_ds_password'])

    def ds_base_dn_exists(self):
        try:
            results = self.ds_connection.search_s(
                config.pki_master_dict['pki_ds_base_dn'],
                ldap.SCOPE_BASE)

            if results is None or len(results) == 0:
                return False

            return True

        except ldap.NO_SUCH_OBJECT as e:
            return False

    def ds_close(self):
        self.ds_connection.unbind_s()

    def sd_connect(self):
        self.sd_connection = pki.client.PKIConnection(
            protocol='https',
            hostname=config.pki_master_dict['pki_security_domain_hostname'],
            port=config.pki_master_dict['pki_security_domain_https_port'],
            subsystem='ca')

    def sd_get_info(self):
        sd = pki.system.SecurityDomainClient(self.sd_connection)
        return sd.getSecurityDomainInfo()

    def sd_authenticate(self):
        self.sd_connection.authenticate(
            config.pki_master_dict['pki_security_domain_user'],
            config.pki_master_dict['pki_security_domain_password'])

        account = pki.account.AccountClient(self.sd_connection)
        account.login()
        account.logout()

    def compose_pki_master_dictionary(self):
        "Create a single master PKI dictionary from the sectional dictionaries"
        try:
            # 'pkispawn'/'pkidestroy' name/value pairs
            config.pki_master_dict['pki_deployment_executable'] =\
                config.pki_deployment_executable
            config.pki_master_dict['pki_install_time'] = config.pki_install_time
            config.pki_master_dict['pki_timestamp'] = config.pki_timestamp
            config.pki_master_dict['pki_certificate_timestamp'] =\
                config.pki_certificate_timestamp
            config.pki_master_dict['pki_architecture'] = config.pki_architecture
            config.pki_master_dict['pki_default_deployment_cfg'] = config.default_deployment_cfg
            config.pki_master_dict['pki_user_deployment_cfg'] = config.user_deployment_cfg
            config.pki_master_dict['pki_deployed_instance_name'] =\
                config.pki_deployed_instance_name
            # Generate random 'pin's for use as security database passwords
            # and add these to the "sensitive" key value pairs read in from
            # the configuration file
            pin_low  = 100000000000
            pin_high = 999999999999
            config.pki_master_dict['pki_pin'] =\
                random.randint(pin_low, pin_high)
            config.pki_master_dict['pki_client_pin'] =\
                random.randint(pin_low, pin_high)

            self.flatten_master_dict()

            pkilogging.sensitive_parameters = config.pki_master_dict['sensitive_parameters'].split()

            # PKI Target (slot substitution) name/value pairs
            config.pki_master_dict['pki_target_cs_cfg'] =\
                os.path.join(
                    config.pki_master_dict['pki_subsystem_configuration_path'],
                    "CS.cfg")
            config.pki_master_dict['pki_target_registry'] =\
                os.path.join(config.pki_master_dict['pki_instance_registry_path'],
                             config.pki_master_dict['pki_instance_name'])
            if config.pki_master_dict['pki_subsystem'] == "CA" and\
               config.str2bool(config.pki_master_dict['pki_external_step_two']):
                # Use the 'pki_one_time_pin' established during the setup of
                # External CA Step 1
                if os.path.exists(config.pki_master_dict['pki_target_cs_cfg'])\
                   and\
                   os.path.isfile(config.pki_master_dict['pki_target_cs_cfg']):
                    cs_cfg = self.read_simple_configuration_file(
                                 config.pki_master_dict['pki_target_cs_cfg'])
                    config.pki_master_dict['pki_one_time_pin'] =\
                        cs_cfg.get('preop.pin')
                else:
                    config.pki_log.error(log.PKI_FILE_MISSING_OR_NOT_A_FILE_1,
                        config.pki_master_dict['pki_target_cs_cfg'],
                        extra=config.PKI_INDENTATION_LEVEL_2)
                    sys.exit(1)
            else:
                # Generate a one-time pin to be used prior to configuration
                # and add this to the "sensitive" key value pairs read in from
                # the configuration file
                config.pki_master_dict['pki_one_time_pin'] =\
                    ''.join(random.choice(string.ascii_letters + string.digits)\
                    for x in range(20))
            if config.pki_master_dict['pki_subsystem'] in\
               config.PKI_TOMCAT_SUBSYSTEMS:
                config.pki_master_dict['pki_target_catalina_properties'] =\
                    os.path.join(
                        config.pki_master_dict['pki_instance_configuration_path'],
                        "catalina.properties")
                config.pki_master_dict['pki_target_servercertnick_conf'] =\
                    os.path.join(
                        config.pki_master_dict['pki_instance_configuration_path'],
                        "serverCertNick.conf")
                config.pki_master_dict['pki_target_server_xml'] =\
                    os.path.join(
                        config.pki_master_dict['pki_instance_configuration_path'],
                        "server.xml")
                config.pki_master_dict['pki_target_context_xml'] =\
                    os.path.join(
                        config.pki_master_dict['pki_instance_configuration_path'],
                        "context.xml")
                config.pki_master_dict['pki_target_tomcat_conf_instance_id'] =\
                    config.pki_master_dict['pki_root_prefix'] +\
                    "/etc/sysconfig/" +\
                    config.pki_master_dict['pki_instance_name']
                config.pki_master_dict['pki_target_tomcat_conf'] =\
                    os.path.join(
                        config.pki_master_dict['pki_instance_configuration_path'],
                        "tomcat.conf")
                # in-place slot substitution name/value pairs
                config.pki_master_dict['pki_target_velocity_properties'] =\
                    os.path.join(
                        config.pki_master_dict['pki_tomcat_webapps_subsystem_path'],
                        "WEB-INF",
                        "velocity.properties")
                config.pki_master_dict['pki_target_subsystem_web_xml'] =\
                    os.path.join(
                        config.pki_master_dict['pki_tomcat_webapps_subsystem_path'],
                        "WEB-INF",
                        "web.xml")
                config.pki_master_dict['pki_target_subsystem_web_xml_orig'] =\
                    os.path.join(
                        config.pki_master_dict['pki_tomcat_webapps_subsystem_path'],
                        "WEB-INF",
                        "web.xml.orig")
                # subystem-specific slot substitution name/value pairs
                if config.pki_master_dict['pki_subsystem'] == "CA":
                    config.pki_master_dict['pki_target_flatfile_txt'] =\
                        os.path.join(config.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "flatfile.txt")
                    config.pki_master_dict['pki_target_proxy_conf'] =\
                        os.path.join(config.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "proxy.conf")
                    config.pki_master_dict['pki_target_registry_cfg'] =\
                        os.path.join(config.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "registry.cfg")
                    # '*.profile'
                    config.pki_master_dict['pki_target_admincert_profile'] =\
                        os.path.join(config.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "adminCert.profile")
                    config.pki_master_dict['pki_target_caauditsigningcert_profile']\
                        = os.path.join(config.pki_master_dict\
                                       ['pki_subsystem_configuration_path'],
                                       "caAuditSigningCert.profile")
                    config.pki_master_dict['pki_target_cacert_profile'] =\
                        os.path.join(config.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "caCert.profile")
                    config.pki_master_dict['pki_target_caocspcert_profile'] =\
                        os.path.join(config.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "caOCSPCert.profile")
                    config.pki_master_dict['pki_target_servercert_profile'] =\
                        os.path.join(config.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "serverCert.profile")
                    config.pki_master_dict['pki_target_subsystemcert_profile'] =\
                        os.path.join(config.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "subsystemCert.profile")
                    # in-place slot substitution name/value pairs
                    config.pki_master_dict['pki_target_profileselect_template'] =\
                        os.path.join(
                            config.pki_master_dict\
                            ['pki_tomcat_webapps_subsystem_path'],
                            "ee",
                            config.pki_master_dict['pki_subsystem'].lower(),
                            "ProfileSelect.template")
                elif config.pki_master_dict['pki_subsystem'] == "KRA":
                    # '*.profile'
                    config.pki_master_dict['pki_target_servercert_profile'] =\
                        os.path.join(config.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "serverCert.profile")
                    config.pki_master_dict['pki_target_storagecert_profile'] =\
                        os.path.join(config.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "storageCert.profile")
                    config.pki_master_dict['pki_target_subsystemcert_profile'] =\
                        os.path.join(config.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "subsystemCert.profile")
                    config.pki_master_dict['pki_target_transportcert_profile'] =\
                        os.path.join(config.pki_master_dict\
                                     ['pki_subsystem_configuration_path'],
                                     "transportCert.profile")
            # Slot assignment name/value pairs
            #     NOTE:  Master key == Slots key; Master value ==> Slots value
            config.pki_master_dict['PKI_INSTANCE_ID_SLOT'] =\
                config.pki_master_dict['pki_instance_name']
            config.pki_master_dict['PKI_INSTANCE_INITSCRIPT_SLOT'] =\
                os.path.join(config.pki_master_dict['pki_instance_path'],
                             config.pki_master_dict['pki_instance_name'])
            config.pki_master_dict['PKI_REGISTRY_FILE_SLOT'] =\
                os.path.join(config.pki_master_dict['pki_subsystem_registry_path'],
                             config.pki_master_dict['pki_instance_name'])
            if config.pki_master_dict['pki_subsystem'] in\
               config.PKI_APACHE_SUBSYSTEMS:
                config.pki_master_dict['FORTITUDE_APACHE_SLOT'] = None
                config.pki_master_dict['FORTITUDE_AUTH_MODULES_SLOT'] = None
                config.pki_master_dict['FORTITUDE_DIR_SLOT'] = None
                config.pki_master_dict['FORTITUDE_LIB_DIR_SLOT'] = None
                config.pki_master_dict['FORTITUDE_MODULE_SLOT'] = None
                config.pki_master_dict['FORTITUDE_NSS_MODULES_SLOT'] = None
                config.pki_master_dict['HTTPD_CONF_SLOT'] = None
                config.pki_master_dict['LIB_PREFIX_SLOT'] = None
                config.pki_master_dict['NON_CLIENTAUTH_SECURE_PORT_SLOT'] = None
                config.pki_master_dict['NSS_CONF_SLOT'] = None
                config.pki_master_dict['OBJ_EXT_SLOT'] = None
                config.pki_master_dict['PKI_LOCKDIR_SLOT'] =\
                    os.path.join("/var/lock/pki",
                                 "apache")
                config.pki_master_dict['PKI_PIDDIR_SLOT'] =\
                    os.path.join("/var/run/pki",
                                 "apache")
                config.pki_master_dict['PKI_WEB_SERVER_TYPE_SLOT'] = "apache"
                config.pki_master_dict['PORT_SLOT'] = None
                config.pki_master_dict['PROCESS_ID_SLOT'] = None
                config.pki_master_dict['REQUIRE_CFG_PL_SLOT'] = None
                config.pki_master_dict['SECURE_PORT_SLOT'] = None
                config.pki_master_dict['SECURITY_LIBRARIES_SLOT'] = None
                config.pki_master_dict['SERVER_NAME_SLOT'] = None
                config.pki_master_dict['SERVER_ROOT_SLOT'] = None
                config.pki_master_dict['SYSTEM_LIBRARIES_SLOT'] = None
                config.pki_master_dict['SYSTEM_USER_LIBRARIES_SLOT'] = None
                config.pki_master_dict['TMP_DIR_SLOT'] = None
                config.pki_master_dict['TPS_DIR_SLOT'] = None
            elif config.pki_master_dict['pki_subsystem'] in\
                 config.PKI_TOMCAT_SUBSYSTEMS:
                config.pki_master_dict['INSTALL_TIME_SLOT'] =\
                    config.pki_master_dict['pki_install_time']
                config.pki_master_dict['PKI_ADMIN_SECURE_PORT_SLOT'] =\
                    config.pki_master_dict['pki_https_port']
                config.pki_master_dict\
                ['PKI_ADMIN_SECURE_PORT_CONNECTOR_NAME_SLOT'] =\
                    "Unused"
                config.pki_master_dict\
                ['PKI_ADMIN_SECURE_PORT_SERVER_COMMENT_SLOT'] =\
                    ""
                config.pki_master_dict['PKI_AGENT_CLIENTAUTH_SLOT'] =\
                    "want"
                config.pki_master_dict['PKI_AGENT_SECURE_PORT_SLOT'] =\
                    config.pki_master_dict['pki_https_port']
                config.pki_master_dict['PKI_AJP_PORT_SLOT'] =\
                    config.pki_master_dict['pki_ajp_port']
                config.pki_master_dict['PKI_AJP_REDIRECT_PORT_SLOT'] =\
                    config.pki_master_dict['pki_https_port']
                config.pki_master_dict['PKI_CERT_DB_PASSWORD_SLOT'] =\
                    config.pki_master_dict['pki_pin']
                config.pki_master_dict['PKI_CFG_PATH_NAME_SLOT'] =\
                    config.pki_master_dict['pki_target_cs_cfg']
                config.pki_master_dict\
                ['PKI_CLOSE_SEPARATE_PORTS_SERVER_COMMENT_SLOT'] =\
                    "-->"
                config.pki_master_dict\
                ['PKI_CLOSE_SEPARATE_PORTS_WEB_COMMENT_SLOT'] =\
                    "-->"
                config.pki_master_dict['PKI_EE_SECURE_CLIENT_AUTH_PORT_SLOT'] =\
                    config.pki_master_dict['pki_https_port']
                config.pki_master_dict\
                ['PKI_EE_SECURE_CLIENT_AUTH_PORT_CONNECTOR_NAME_SLOT'] =\
                    "Unused"
                config.pki_master_dict\
                ['PKI_EE_SECURE_CLIENT_AUTH_PORT_SERVER_COMMENT_SLOT'] =\
                    ""
                config.pki_master_dict['PKI_EE_SECURE_CLIENT_AUTH_PORT_UI_SLOT'] =\
                    config.pki_master_dict['pki_https_port']
                config.pki_master_dict['PKI_EE_SECURE_PORT_SLOT'] =\
                    config.pki_master_dict['pki_https_port']
                config.pki_master_dict['PKI_EE_SECURE_PORT_CONNECTOR_NAME_SLOT'] =\
                    "Unused"
                config.pki_master_dict['PKI_EE_SECURE_PORT_SERVER_COMMENT_SLOT'] =\
                    ""
                config.pki_master_dict['PKI_GROUP_SLOT'] =\
                    config.pki_master_dict['pki_group']
                config.pki_master_dict['PKI_INSTANCE_PATH_SLOT'] =\
                    config.pki_master_dict['pki_instance_path']
                config.pki_master_dict['PKI_INSTANCE_ROOT_SLOT'] =\
                    config.pki_master_dict['pki_path']
                config.pki_master_dict['PKI_LOCKDIR_SLOT'] =\
                    os.path.join("/var/lock/pki",
                                 "tomcat")
                config.pki_master_dict['PKI_MACHINE_NAME_SLOT'] =\
                    config.pki_master_dict['pki_hostname']
                config.pki_master_dict\
                ['PKI_OPEN_SEPARATE_PORTS_SERVER_COMMENT_SLOT'] =\
                    "<!--"
                config.pki_master_dict\
                ['PKI_OPEN_SEPARATE_PORTS_WEB_COMMENT_SLOT'] =\
                    "<!--"
                config.pki_master_dict['PKI_PIDDIR_SLOT'] =\
                    os.path.join("/var/run/pki",
                                 "tomcat")
                if config.str2bool(config.pki_master_dict['pki_enable_proxy']):
                    config.pki_master_dict['PKI_CLOSE_AJP_PORT_COMMENT_SLOT'] =\
                        ""
                    config.pki_master_dict['PKI_CLOSE_ENABLE_PROXY_COMMENT_SLOT'] =\
                        ""
                    config.pki_master_dict['PKI_PROXY_SECURE_PORT_SLOT'] =\
                        config.pki_master_dict['pki_proxy_https_port']
                    config.pki_master_dict['PKI_PROXY_UNSECURE_PORT_SLOT'] =\
                        config.pki_master_dict['pki_proxy_http_port']
                    config.pki_master_dict['PKI_OPEN_AJP_PORT_COMMENT_SLOT'] =\
                        ""
                    config.pki_master_dict['PKI_OPEN_ENABLE_PROXY_COMMENT_SLOT'] =\
                        ""
                else:
                    config.pki_master_dict['PKI_CLOSE_AJP_PORT_COMMENT_SLOT'] =\
                        "-->"
                    config.pki_master_dict['PKI_CLOSE_ENABLE_PROXY_COMMENT_SLOT'] =\
                        "-->"
                    config.pki_master_dict['PKI_PROXY_SECURE_PORT_SLOT'] = ""
                    config.pki_master_dict['PKI_PROXY_UNSECURE_PORT_SLOT'] = ""
                    config.pki_master_dict['PKI_OPEN_AJP_PORT_COMMENT_SLOT'] =\
                        "<!--"
                    config.pki_master_dict['PKI_OPEN_ENABLE_PROXY_COMMENT_SLOT'] =\
                        "<!--"
                config.pki_master_dict['PKI_TMPDIR_SLOT'] =\
                    config.pki_master_dict['pki_tomcat_tmpdir_path']
                config.pki_master_dict['PKI_RESTEASY_LIB_SLOT'] =\
                    config.pki_master_dict['resteasy_lib']
                config.pki_master_dict['PKI_RANDOM_NUMBER_SLOT'] =\
                    config.pki_master_dict['pki_one_time_pin']
                config.pki_master_dict['PKI_SECURE_PORT_SLOT'] =\
                    config.pki_master_dict['pki_https_port']
                config.pki_master_dict['PKI_SECURE_PORT_CONNECTOR_NAME_SLOT'] =\
                    "Secure"
                config.pki_master_dict['PKI_SECURE_PORT_SERVER_COMMENT_SLOT'] =\
                    "<!-- " +\
                    "Shared Ports:  Agent, EE, and Admin Secure Port Connector " +\
                    "-->"
                config.pki_master_dict['PKI_SECURITY_MANAGER_SLOT'] =\
                    config.pki_master_dict['pki_security_manager']
                config.pki_master_dict['PKI_SERVER_XML_CONF_SLOT'] =\
                    config.pki_master_dict['pki_target_server_xml']
                config.pki_master_dict['PKI_SUBSYSTEM_DIR_SLOT'] =\
                    config.pki_master_dict['pki_subsystem'].lower() + "/"
                config.pki_master_dict['PKI_SUBSYSTEM_TYPE_SLOT'] =\
                    config.pki_master_dict['pki_subsystem'].lower()
                config.pki_master_dict['PKI_SYSTEMD_SERVICENAME_SLOT'] =\
                    "pki-tomcatd" + "@" +\
                    config.pki_master_dict['pki_instance_name'] + ".service"
                config.pki_master_dict['PKI_UNSECURE_PORT_SLOT'] =\
                    config.pki_master_dict['pki_http_port']
                config.pki_master_dict['PKI_UNSECURE_PORT_CONNECTOR_NAME_SLOT'] =\
                    "Unsecure"
                config.pki_master_dict['PKI_UNSECURE_PORT_SERVER_COMMENT_SLOT'] =\
                    "<!-- Shared Ports:  Unsecure Port Connector -->"
                config.pki_master_dict['PKI_USER_SLOT'] =\
                    config.pki_master_dict['pki_user']
                config.pki_master_dict['PKI_WEB_SERVER_TYPE_SLOT'] =\
                    "tomcat"
                config.pki_master_dict['PKI_WEBAPPS_NAME_SLOT'] =\
                    "webapps"
                config.pki_master_dict['TOMCAT_CFG_SLOT'] =\
                    config.pki_master_dict['pki_target_tomcat_conf']
                config.pki_master_dict['TOMCAT_INSTANCE_COMMON_LIB_SLOT'] =\
                    os.path.join(
                        config.pki_master_dict['pki_tomcat_common_lib_path'],
                        "*.jar")
                config.pki_master_dict['TOMCAT_LOG_DIR_SLOT'] =\
                    config.pki_master_dict['pki_instance_log_path']
                config.pki_master_dict['TOMCAT_PIDFILE_SLOT'] =\
                    "/var/run/pki/tomcat/" + config.pki_master_dict['pki_instance_name'] + ".pid"
                config.pki_master_dict['TOMCAT_SERVER_PORT_SLOT'] =\
                    config.pki_master_dict['pki_tomcat_server_port']
                config.pki_master_dict['TOMCAT_SSL2_CIPHERS_SLOT'] =\
                    "-SSL2_RC4_128_WITH_MD5," +\
                    "-SSL2_RC4_128_EXPORT40_WITH_MD5," +\
                    "-SSL2_RC2_128_CBC_WITH_MD5," +\
                    "-SSL2_RC2_128_CBC_EXPORT40_WITH_MD5," +\
                    "-SSL2_DES_64_CBC_WITH_MD5," +\
                    "-SSL2_DES_192_EDE3_CBC_WITH_MD5"
                config.pki_master_dict['TOMCAT_SSL3_CIPHERS_SLOT'] =\
                    "-SSL3_FORTEZZA_DMS_WITH_NULL_SHA," +\
                    "-SSL3_FORTEZZA_DMS_WITH_RC4_128_SHA," +\
                    "+SSL3_RSA_WITH_RC4_128_SHA," +\
                    "-SSL3_RSA_EXPORT_WITH_RC4_40_MD5," +\
                    "+SSL3_RSA_WITH_3DES_EDE_CBC_SHA," +\
                    "+SSL3_RSA_WITH_DES_CBC_SHA," +\
                    "-SSL3_RSA_EXPORT_WITH_RC2_CBC_40_MD5," +\
                    "-SSL3_FORTEZZA_DMS_WITH_FORTEZZA_CBC_SHA," +\
                    "-SSL_RSA_FIPS_WITH_DES_CBC_SHA," +\
                    "+SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA," +\
                    "-SSL3_RSA_WITH_NULL_MD5," +\
                    "-TLS_RSA_EXPORT1024_WITH_RC4_56_SHA," +\
                    "-TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA," +\
                    "+TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA"
                config.pki_master_dict['TOMCAT_SSL_OPTIONS_SLOT'] =\
                    "ssl2=true," +\
                    "ssl3=true," +\
                    "tls=true"
                config.pki_master_dict['TOMCAT_TLS_CIPHERS_SLOT'] =\
                    "-TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA," +\
                    "-TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA," +\
                    "+TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA," +\
                    "+TLS_ECDH_RSA_WITH_AES_128_CBC_SHA," +\
                    "+TLS_ECDH_RSA_WITH_AES_256_CBC_SHA," +\
                    "-TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA," +\
                    "+TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA," +\
                    "+TLS_RSA_WITH_3DES_EDE_CBC_SHA," +\
                    "+TLS_RSA_WITH_AES_128_CBC_SHA," +\
                    "+TLS_RSA_WITH_AES_256_CBC_SHA," +\
                    "+TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA," +\
                    "+TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA," +\
                    "-TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA," +\
                    "-TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA," +\
                    "-TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA," +\
                    "+TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA," +\
                    "+TLS_DHE_DSS_WITH_AES_128_CBC_SHA," +\
                    "+TLS_DHE_DSS_WITH_AES_256_CBC_SHA," +\
                    "+TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA," +\
                    "+TLS_DHE_RSA_WITH_AES_128_CBC_SHA," +\
                    "+TLS_DHE_RSA_WITH_AES_256_CBC_SHA"
            # Shared Apache/Tomcat NSS security database name/value pairs
            config.pki_master_dict['pki_shared_pfile'] =\
                os.path.join(
                    config.pki_master_dict['pki_instance_configuration_path'],
                    "pfile")
            config.pki_master_dict['pki_shared_password_conf'] =\
                os.path.join(
                    config.pki_master_dict['pki_instance_configuration_path'],
                    "password.conf")
            config.pki_master_dict['pki_cert_database'] =\
                os.path.join(config.pki_master_dict['pki_database_path'],
                             "cert8.db")
            config.pki_master_dict['pki_key_database'] =\
                os.path.join(config.pki_master_dict['pki_database_path'],
                             "key3.db")
            config.pki_master_dict['pki_secmod_database'] =\
                os.path.join(config.pki_master_dict['pki_database_path'],
                             "secmod.db")
            config.pki_master_dict['pki_self_signed_token'] = "internal"
            config.pki_master_dict['pki_self_signed_nickname'] =\
                "Server-Cert cert-" + config.pki_master_dict['pki_instance_name']
            config.pki_master_dict['pki_self_signed_subject'] =\
                "cn=" + config.pki_master_dict['pki_hostname'] + "," +\
                "o=" + config.pki_master_dict['pki_certificate_timestamp']
            config.pki_master_dict['pki_self_signed_serial_number'] = 0
            config.pki_master_dict['pki_self_signed_validity_period'] = 12
            config.pki_master_dict['pki_self_signed_issuer_name'] =\
                "cn=" + config.pki_master_dict['pki_hostname'] + "," +\
                "o=" + config.pki_master_dict['pki_certificate_timestamp']
            config.pki_master_dict['pki_self_signed_trustargs'] = "CTu,CTu,CTu"
            config.pki_master_dict['pki_self_signed_noise_file'] =\
                os.path.join(
                    config.pki_master_dict['pki_subsystem_configuration_path'],
                    "noise")
            config.pki_master_dict['pki_self_signed_noise_bytes'] = 1024
            # Shared Apache/Tomcat NSS security database convenience symbolic links
            config.pki_master_dict\
            ['pki_subsystem_configuration_password_conf_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_subsystem_configuration_path'],
                    "password.conf")

            if not len(config.pki_master_dict['pki_client_database_password']):
                # use randomly generated client 'pin'
                config.pki_master_dict['pki_client_database_password'] =\
                    str(config.pki_master_dict['pki_client_pin'])

            # Configuration scriptlet
            # 'Security Domain' Configuration name/value pairs
            # 'Subsystem Name'  Configuration name/value pairs
            # 'Token'           Configuration name/value pairs
            #
            #     Apache - [RA], [TPS]
            #     Tomcat - [CA], [KRA], [OCSP], [TKS]
            #            - [CA Clone], [KRA Clone], [OCSP Clone], [TKS Clone]
            #            - [External CA]
            #            - [Subordinate CA]
            #
            #     The following variables are defined below:
            #
            #         config.pki_master_dict['pki_security_domain_type']
            #         config.pki_master_dict['pki_security_domain_uri']
            #
            #     The following variables are established via the specified PKI
            #     deployment configuration file and are NOT redefined below:
            #
            #         config.pki_master_dict['pki_clone_pkcs12_password']
            #         config.pki_master_dict['pki_security_domain_password']
            #         config.pki_master_dict['pki_token_password']
            #         config.pki_master_dict['pki_clone_pkcs12_path']
            #         config.pki_master_dict['pki_clone_uri']
            #         config.pki_master_dict['pki_security_domain_https_port']
            #         config.pki_master_dict['pki_token_name']
            #
            #     The following variables are established via the specified PKI
            #     deployment configuration file and potentially overridden below:
            #
            #         config.pki_master_dict['pki_security_domain_user']
            #         config.pki_master_dict['pki_issuing_ca']
            #

            # if security domain user is not defined
            if not len(config.pki_master_dict['pki_security_domain_user']):

                # use the CA admin uid if it's defined
                if self.pki_config.has_option('CA', 'pki_admin_uid') and\
                    len(self.pki_config.get('CA', 'pki_admin_uid')) > 0:
                    config.pki_master_dict['pki_security_domain_user'] =\
                        self.pki_config.get('CA', 'pki_admin_uid')

                # or use the Default admin uid if it's defined
                elif self.pki_config.has_option('DEFAULT', 'pki_admin_uid') and\
                    len(self.pki_config.get('DEFAULT', 'pki_admin_uid')) > 0:
                    config.pki_master_dict['pki_security_domain_user'] =\
                        self.pki_config.get('DEFAULT', 'pki_admin_uid')

                # otherwise use the default CA admin uid
                else:
                    config.pki_master_dict['pki_security_domain_user'] = "caadmin"

            if config.pki_subsystem != "CA" or\
               config.str2bool(config.pki_master_dict['pki_clone']) or\
               config.str2bool(config.pki_master_dict['pki_subordinate']):
                # PKI KRA, PKI OCSP, PKI RA, PKI TKS, PKI TPS,
                # CA Clone, KRA Clone, OCSP Clone, TKS Clone, or
                # Subordinate CA
                config.pki_master_dict['pki_security_domain_type'] = "existing"
                config.pki_master_dict['pki_security_domain_uri'] =\
                    "https" + "://" +\
                    config.pki_master_dict['pki_security_domain_hostname'] + ":" +\
                    config.pki_master_dict['pki_security_domain_https_port']

            elif config.str2bool(config.pki_master_dict['pki_external']):
                # External CA
                config.pki_master_dict['pki_security_domain_type'] = "new"
                if not len(config.pki_master_dict['pki_issuing_ca']):
                    config.pki_master_dict['pki_issuing_ca'] = "External CA"
            else:
                # PKI CA
                config.pki_master_dict['pki_security_domain_type'] = "new"

            # 'External CA' Configuration name/value pairs
            #
            #     Tomcat - [External CA]
            #
            #     The following variables are established via the specified PKI
            #     deployment configuration file and are NOT redefined below:
            #
            #        config.pki_master_dict['pki_external_ca_cert_chain_path']
            #        config.pki_master_dict['pki_external_ca_cert_path']
            #        config.pki_master_dict['pki_external_csr_path']
            #        config.pki_master_dict['pki_external_step_two']
            #

            # 'Backup' Configuration name/value pairs
            #
            #     Apache - [RA], [TPS]
            #     Tomcat - [CA], [KRA], [OCSP], [TKS]
            #            - [External CA]
            #            - [Subordinate CA]
            #
            #     The following variables are established via the specified PKI
            #     deployment configuration file and are NOT redefined below:
            #
            #        config.pki_master_dict['pki_backup_password']
            #        config.pki_master_dict['pki_backup_keys']
            #
            if config.str2bool(config.pki_master_dict['pki_backup_keys']):
                # NOTE:  ALWAYS store the PKCS #12 backup keys file
                #        in with the NSS "server" security databases
                config.pki_master_dict['pki_backup_keys_p12'] =\
                    config.pki_master_dict['pki_database_path'] + "/" +\
                    config.pki_master_dict['pki_subsystem'].lower() + "_" +\
                    "backup" + "_" + "keys" + "." + "p12"

            config.pki_master_dict['pki_admin_profile_id'] = "caAdminCert"

            if not 'pki_import_admin_cert' in config.pki_master_dict:
                config.pki_master_dict['pki_import_admin_cert'] = 'false'

            config.pki_master_dict['pki_ca_signing_tag'] = "signing"
            if config.pki_master_dict['pki_subsystem'] == "CA":
                config.pki_master_dict['pki_ocsp_signing_tag'] = "ocsp_signing"
            elif config.pki_master_dict['pki_subsystem'] == "OCSP":
                config.pki_master_dict['pki_ocsp_signing_tag'] = "signing"
            config.pki_master_dict['pki_ssl_server_tag'] = "sslserver"
            config.pki_master_dict['pki_subsystem_tag'] = "subsystem"
            config.pki_master_dict['pki_audit_signing_tag'] = "audit_signing"
            config.pki_master_dict['pki_transport_tag'] = "transport"
            config.pki_master_dict['pki_storage_tag'] = "storage"

            # Finalization name/value pairs
            config.pki_master_dict['pki_default_deployment_cfg_replica'] =\
                os.path.join(config.pki_master_dict['pki_subsystem_registry_path'],
                             config.DEFAULT_DEPLOYMENT_CONFIGURATION)
            config.pki_master_dict['pki_user_deployment_cfg_replica'] =\
                os.path.join(config.pki_master_dict['pki_subsystem_registry_path'],
                             config.USER_DEPLOYMENT_CONFIGURATION)
            config.pki_master_dict['pki_user_deployment_cfg_spawn_archive'] =\
                config.pki_master_dict['pki_subsystem_archive_log_path'] + "/" +\
                "spawn" + "_" +\
                config.USER_DEPLOYMENT_CONFIGURATION + "." +\
                config.pki_master_dict['pki_timestamp']
            config.pki_master_dict['pki_manifest'] =\
                config.pki_master_dict['pki_subsystem_registry_path'] + "/" +\
                "manifest"
            config.pki_master_dict['pki_manifest_spawn_archive'] =\
                config.pki_master_dict['pki_subsystem_archive_log_path'] + "/" +\
                "spawn" + "_" + "manifest" + "." +\
                config.pki_master_dict['pki_timestamp']
            # Construct the configuration URL containing the one-time pin
            # and add this to the "sensitive" key value pairs read in from
            # the configuration file
            #
            # NOTE:  This is the one and only parameter containing a sensitive
            #        parameter that may be stored in a log file and displayed
            #        to the screen.
            #
            config.pki_master_dict['pki_configuration_url'] =\
                "https://{}:{}/{}/{}?pin={}".format(
                    config.pki_master_dict['pki_hostname'],
                    config.pki_master_dict['pki_https_port'],
                    config.pki_master_dict['pki_subsystem'].lower(),
                    "admin/console/config/login",
                    config.pki_master_dict['pki_one_time_pin'])
            # Compose this "systemd" execution management command
            if config.pki_master_dict['pki_subsystem'] in\
               config.PKI_APACHE_SUBSYSTEMS:
                config.pki_master_dict['pki_registry_initscript_command'] =\
                    "systemctl" + " " +\
                    "restart" + " " +\
                    "pki-apached" + "@" +\
                    config.pki_master_dict['pki_instance_name'] + "." + "service"
            elif config.pki_master_dict['pki_subsystem'] in\
                 config.PKI_TOMCAT_SUBSYSTEMS:
                config.pki_master_dict['pki_registry_initscript_command'] =\
                    "systemctl" + " " +\
                    "restart" + " " +\
                    "pki-tomcatd" + "@" +\
                    config.pki_master_dict['pki_instance_name'] + "." + "service"
        except OSError as exc:
            config.pki_log.error(log.PKI_OSERROR_1, exc,
                                 extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
        except KeyError as err:
            config.pki_log.error(log.PKIHELPER_DICTIONARY_MASTER_MISSING_KEY_1,
                                 err, extra=config.PKI_INDENTATION_LEVEL_2)
            sys.exit(1)
        return


    def compose_pki_slots_dictionary(self):
        """Read the slots configuration file to create
           the appropriate PKI slots dictionary"""
        rv = 0
        try:
            config.pki_slots_dict = dict()
            parser = ConfigParser.ConfigParser()
            # Make keys case-sensitive!
            parser.optionxform = str
            parser.read(config.PKI_DEPLOYMENT_SLOTS_CONFIGURATION_FILE)
            # Slots configuration file name/value pairs
            if config.pki_subsystem in config.PKI_APACHE_SUBSYSTEMS:
                config.pki_slots_dict = dict(parser._sections['Apache'])
            elif config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
                config.pki_slots_dict = dict(parser._sections['Tomcat'])
        except ConfigParser.ParsingError, err:
            rv = err
        return rv
