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
import logging
import os
import random
import string
import sys
import time


# PKI Deployment Imports
import pkiconfig as config
import pkimessages as log


# PKI Deployment Helper Functions
def process_command_line_arguments(argv):
    "Read and process command-line options"
    config.pki_deployment_executable = os.path.basename(argv[0])
    description = None
    if config.pki_deployment_executable == 'pkispawn':
        description = 'PKI Instance Installation and Configuration'
        epilog = log.PKISPAWN_EPILOG
    elif config.pki_deployment_executable == 'pkidestroy':
        description = 'PKI Instance Removal'
        epilog = log.PKIDESTROY_EPILOG
    parser = argparse.ArgumentParser(
                 description=description,
                 add_help=False,
                 formatter_class=argparse.RawDescriptionHelpFormatter,
                 epilog=epilog)
    # Establish 'Mandatory' command-line options
    mandatory = parser.add_argument_group('mandatory arguments')
    mandatory.add_argument('-s',
                           dest='pki_subsystem', action='store',
                           nargs=1, choices=config.PKI_SUBSYSTEMS,
                           required=True, metavar='<subsystem>',
                           help='where <subsystem> is '
                                'CA, KRA, OCSP, RA, TKS, or TPS')
    if config.pki_deployment_executable == 'pkispawn':
        mandatory.add_argument('-f',
                               dest='pkideployment_cfg', action='store',
                               nargs=1, required=True, metavar='<file>',
                               help='configuration filename '
                                    '(MUST specify complete path)')
    elif config.pki_deployment_executable == 'pkidestroy':
        mandatory.add_argument('-i',
                               dest='pki_deployed_instance_name',
                               action='store',
                               nargs=1, metavar='<instance>',
                               help='FORMAT:  ${pki_instance_name}'
                                    '[.${pki_admin_domain_name}]')
    # Establish 'Optional' command-line options
    optional = parser.add_argument_group('optional arguments')
    optional.add_argument('--dry_run',
                          dest='pki_dry_run_flag', action='store_true',
                          help='do not actually perform any actions')
    optional.add_argument('-h', '--help',
                          dest='help', action='help',
                          help='show this help message and exit')
    if config.pki_deployment_executable == 'pkispawn':
        optional.add_argument('-u',
                              dest='pki_update_flag', action='store_true',
                              help='update instance of specified subsystem')
    optional.add_argument('-v',
                          dest='pki_verbosity', action='count',
                          help='display verbose information (details below)')
    # Establish 'Test' command-line options
    test = parser.add_argument_group('test arguments')
    test.add_argument('-p',
                      dest='pki_root_prefix', action='store',
                      nargs=1, metavar='<prefix>',
                      help='directory prefix to specify local directory '
                           '[TEST ONLY]')
    # Parse command-line options
    args = parser.parse_args()
    # Process 'Mandatory' command-line options
    #    '-s'
    config.pki_subsystem = str(args.pki_subsystem).strip('[\']')
    if config.pki_deployment_executable == 'pkispawn':
        #    '-f'
        config.pkideployment_cfg = str(args.pkideployment_cfg).strip('[\']')
    elif config.pki_deployment_executable == 'pkidestroy':
        #    '-i'
        config.pki_deployed_instance_name =\
            str(args.pki_deployed_instance_name).strip('[\']')
    # Process 'Optional' command-line options
    #    '--dry_run'
    if args.pki_dry_run_flag:
        config.pki_dry_run_flag = args.pki_dry_run_flag
    if config.pki_deployment_executable == 'pkispawn':
        #    '-u'
        config.pki_update_flag = args.pki_update_flag
    #    '-v'
    if args.pki_verbosity == 1:
        config.pki_jython_log_level = config.PKI_JYTHON_INFO_LOG_LEVEL
        config.pki_console_log_level = logging.INFO
        config.pki_log_level = logging.INFO
    elif args.pki_verbosity == 2:
        config.pki_jython_log_level = config.PKI_JYTHON_INFO_LOG_LEVEL
        config.pki_console_log_level = logging.INFO
        config.pki_log_level = logging.DEBUG
    elif args.pki_verbosity == 3:
        config.pki_jython_log_level = config.PKI_JYTHON_DEBUG_LOG_LEVEL
        config.pki_console_log_level = logging.DEBUG
        config.pki_log_level = logging.DEBUG
    elif args.pki_verbosity > 3:
        print "ERROR:  " + log.PKI_VERBOSITY_LEVELS_MESSAGE
        print
        parser.print_help()
        parser.exit(-1);
    else:
        # Set default log levels
        config.pki_jython_log_level = config.PKI_JYTHON_WARNING_LOG_LEVEL
        config.pki_console_log_level = logging.WARNING
        config.pki_log_level = logging.INFO
    # Process 'Test' command-line options
    #    '-p'
    if not args.pki_root_prefix is None:
        config.pki_root_prefix = str(args.pki_root_prefix).strip('[\']')
    # Validate command-line options
    if config.pki_root_prefix is None or\
       len(config.pki_root_prefix) == 0:
        config.pki_root_prefix = ""
    elif not os.path.exists(config.pki_root_prefix) or\
         not os.path.isdir(config.pki_root_prefix):
        print "ERROR:  " +\
              log.PKI_DIRECTORY_MISSING_OR_NOT_A_DIRECTORY_1 %\
              config.pki_root_prefix
        print
        parser.print_help()
        parser.exit(-1);
    if config.pki_deployment_executable == 'pkidestroy':
        # verify that previously deployed instance exists
        deployed_pki_instance_path = config.pki_root_prefix +\
                                     config.PKI_DEPLOYMENT_BASE_ROOT + "/" +\
                                     config.pki_deployed_instance_name
        if not os.path.exists(deployed_pki_instance_path):
            print "ERROR:  " + log.PKI_INSTANCE_DOES_NOT_EXIST_1 %\
                  deployed_pki_instance_path
            print
            parser.exit(-1);
        # verify that previously deployed subsystem for this instance exists
        deployed_pki_subsystem_path = deployed_pki_instance_path + "/" +\
                                      config.pki_subsystem.lower()
        if not os.path.exists(deployed_pki_subsystem_path):
            print "ERROR:  " + log.PKI_SUBSYSTEM_DOES_NOT_EXIST_2 %\
                  (config.pki_subsystem, deployed_pki_instance_path)
            print
            parser.exit(-1);
        # establish complete path to previously deployed configuration file
        config.pkideployment_cfg =\
            deployed_pki_subsystem_path + "/" +\
            "registry" + "/" +\
            config.pki_subsystem.lower() + "/" +\
            config.PKI_DEPLOYMENT_DEFAULT_CONFIGURATION_FILE
    # always verify that configuration file exists
    if not os.path.exists(config.pkideployment_cfg) or\
       not os.path.isfile(config.pkideployment_cfg):
        print "ERROR:  " +\
              log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %\
              config.pkideployment_cfg
        print
        parser.print_help()
        parser.exit(-1);
    return


# The following code is based heavily upon
# "http://www.decalage.info/en/python/configparser"
COMMENT_CHAR = '#'
OPTION_CHAR =  '='

def read_simple_configuration_file(filename):
    values = {}
    f = open(filename)
    for line in f:
        # First, remove comments:
        if COMMENT_CHAR in line:
            # split on comment char, keep only the part before
            line, comment = line.split(COMMENT_CHAR, 1)
        # Second, find lines with an name=value:
        if OPTION_CHAR in line:
            # split on name char:
            name, value = line.split(OPTION_CHAR, 1)
            # strip spaces:
            name = name.strip()
            value = value.strip()
            # store in dictionary:
            values[name] = value
    f.close()
    return values


def read_pki_configuration_file():
    "Read configuration file sections into dictionaries"
    rv = 0
    try:
        parser = ConfigParser.ConfigParser()
        # Make keys case-sensitive!
        parser.optionxform = str
        parser.read(config.pkideployment_cfg)
        config.pki_sensitive_dict = dict(parser._sections['Sensitive'])
        config.pki_common_dict = dict(parser._sections['Common'])
        if config.pki_subsystem == "CA":
            config.pki_web_server_dict = dict(parser._sections['Tomcat'])
            config.pki_subsystem_dict = dict(parser._sections['CA'])
        elif config.pki_subsystem == "KRA":
            config.pki_web_server_dict = dict(parser._sections['Tomcat'])
            config.pki_subsystem_dict = dict(parser._sections['KRA'])
        elif config.pki_subsystem == "OCSP":
            config.pki_web_server_dict = dict(parser._sections['Tomcat'])
            config.pki_subsystem_dict = dict(parser._sections['OCSP'])
        elif config.pki_subsystem == "RA":
            config.pki_web_server_dict = dict(parser._sections['Apache'])
            config.pki_subsystem_dict = dict(parser._sections['RA'])
        elif config.pki_subsystem == "TKS":
            config.pki_web_server_dict = dict(parser._sections['Tomcat'])
            config.pki_subsystem_dict = dict(parser._sections['TKS'])
        elif config.pki_subsystem == "TPS":
            config.pki_web_server_dict = dict(parser._sections['Apache'])
            config.pki_subsystem_dict = dict(parser._sections['TPS'])
        # Insert empty record into dictionaries for "pretty print" statements
        #     NEVER print "sensitive" key value pairs!!!
        config.pki_common_dict[0] = None
        config.pki_web_server_dict[0] = None
        config.pki_subsystem_dict[0] = None
    except ConfigParser.ParsingError, err:
        rv = err
    return rv


def compose_pki_master_dictionary():
    "Create a single master PKI dictionary from the sectional dictionaries"
    try:
        config.pki_master_dict = dict()
        # 'pkispawn'/'pkirespawn'/'pkidestroy' name/value pairs
        config.pki_master_dict['pki_deployment_executable'] =\
            config.pki_deployment_executable
        config.pki_master_dict['pki_install_time'] = config.pki_install_time
        config.pki_master_dict['pki_timestamp'] = config.pki_timestamp
        config.pki_master_dict['pki_certificate_timestamp'] =\
            config.pki_certificate_timestamp
        config.pki_master_dict['pki_architecture'] = config.pki_architecture
        config.pki_master_dict['pki_hostname'] = config.pki_hostname
        config.pki_master_dict['pki_dns_domainname'] =\
            config.pki_dns_domainname
        config.pki_master_dict['pki_dry_run_flag'] = config.pki_dry_run_flag
        config.pki_master_dict['pki_jython_log_level'] =\
            config.pki_jython_log_level
        config.pki_master_dict['pki_deployment_cfg'] = config.pkideployment_cfg
        config.pki_master_dict['pki_deployed_instance_name'] =\
            config.pki_deployed_instance_name
        # Generate random 'pin's for use as security database passwords
        # and add these to the "sensitive" key value pairs read in from
        # the configuration file
        pin_low  = 100000000000
        pin_high = 999999999999
        config.pki_sensitive_dict['pki_pin'] =\
            random.randint(pin_low, pin_high)
        config.pki_sensitive_dict['pki_client_pin'] =\
            random.randint(pin_low, pin_high)
        # Generate a one-time pin to be used prior to configuration
        # and add this to the "sensitive" key value pairs read in from
        # the configuration file
        config.pki_sensitive_dict['pki_one_time_pin'] =\
            ''.join(random.choice(string.ascii_letters + string.digits)\
            for x in range(20))
        # Configuration file name/value pairs
        #     NEVER add "sensitive" key value pairs to the master dictionary!!!
        config.pki_master_dict.update(config.pki_common_dict)
        config.pki_master_dict.update(config.pki_web_server_dict)
        config.pki_master_dict.update(config.pki_subsystem_dict)
        config.pki_master_dict.update(__name__="PKI Master Dictionary")
        # IMPORTANT:  A "PKI instance" no longer corresponds to a single
        #             pki subystem, but rather to a unique
        #             "Tomcat web instance" or a unique "Apache web instance".
        #
        #             A "Tomcat web instance" consists of a single process
        #             which may itself contain zero or one unique
        #             "CA" and/or "KRA" and/or "OCSP" and/or "TKS"
        #             pki subystems.  Obviously, the "Tomcat web instance"
        #             must contain at least one of these four pki subystems.
        #
        #             Similarly, an "Apache web instance" consists of a single
        #             process which may itself contain zero or one unique
        #             "RA" and/or "TPS" pki subsystems.  Obviously, the
        #             "Apache web instance" must contain at least one of these
        #             two pki subystems.
        #
        #             Optionally, to more clearly distinguish a "PKI instance",
        #             a common PKI "Admin Domain" may be used as a suffix to
        #             either an "Apache web instance", or a
        #             "Tomcat web instance".
        #
        #             Thus, a specific "PKI instance" of a CA, KRA, OCSP,
        #             or TKS subystem must be referenced via the name of
        #             the particular PKI "Tomcat web instance" containing
        #             this PKI subsystem optionally followed by a
        #             specified PKI "Admin Domain" separated via a ".".
        #
        #             Likewise, a specific "PKI instance" of an RA, or TPS
        #             subystem must be referenced via the name of
        #             the particular PKI "Apache web instance" containing
        #             this PKI subsystem optionally followed by a
        #             specified PKI "Admin Domain" separated via a ".".
        #
        #             To emulate the original behavior of having a CA and
        #             KRA be unique PKI instances, each must be located
        #             within separately named "Tomcat web instances" if
        #             residing on the same host machine, or may be located
        #             within an identically named "PKI instance" when residing
        #             on two separate host machines.
        #
        # PKI INSTANCE NAMING CONVENTION:
        #
        #     OLD:  "pki-${pki_subsystem}"
        #           (e. g. Tomcat:  "pki-ca", "pki-kra", "pki-ocsp", "pki-tks")
        #           (e. g. Apache:  "pki-ra", "pki-tps")
        #     NEW:  "${pki_instance_name}[.${pki_admin_domain_name}]"
        #           (e. g. Tomcat:  "pki-tomcat", "pki-tomcat.example.com")
        #           (e. g. Apache:  "pki-apache", "pki-apache.example.com")
        #
        if len(config.pki_master_dict['pki_admin_domain_name']):
            config.pki_master_dict['pki_instance_id'] =\
                config.pki_master_dict['pki_instance_name'] + "." +\
                config.pki_master_dict['pki_admin_domain_name']
        else:
            config.pki_master_dict['pki_instance_id'] =\
                config.pki_master_dict['pki_instance_name']
        # PKI Source name/value pairs
        config.pki_master_dict['pki_source_conf_path'] =\
            os.path.join(config.PKI_DEPLOYMENT_SOURCE_ROOT,
                         config.pki_master_dict['pki_subsystem'].lower(),
                         "conf")
        config.pki_master_dict['pki_source_setup_path'] =\
            os.path.join(config.PKI_DEPLOYMENT_SOURCE_ROOT,
                         "setup")
        config.pki_master_dict['pki_source_shared_path'] =\
            os.path.join(config.PKI_DEPLOYMENT_SOURCE_ROOT,
                         "shared",
                         "conf")
        config.pki_master_dict['pki_source_cs_cfg'] =\
            os.path.join(config.pki_master_dict['pki_source_conf_path'],
                         "CS.cfg")
        config.pki_master_dict['pki_source_registry'] =\
            os.path.join(config.pki_master_dict['pki_source_setup_path'],
                         "pkidaemon_registry")
        if config.pki_master_dict['pki_subsystem'] in\
           config.PKI_APACHE_SUBSYSTEMS:
            config.pki_master_dict['pki_systemd_service'] =\
                config.PKI_DEPLOYMENT_SYSTEMD_ROOT + "/" +\
                "pki-apached" + "@" + ".service"
            config.pki_master_dict['pki_systemd_target'] =\
                config.PKI_DEPLOYMENT_SYSTEMD_ROOT + "/" +\
                "pki-apached.target"
            config.pki_master_dict['pki_systemd_target_wants'] =\
                config.PKI_DEPLOYMENT_SYSTEMD_CONFIGURATION_ROOT + "/" +\
                "pki-apached.target.wants"
            config.pki_master_dict['pki_systemd_service_link'] =\
                config.pki_master_dict['pki_systemd_target_wants'] + "/" +\
                "pki-apached" + "@" +\
                config.pki_master_dict['pki_instance_id'] + ".service"
        elif config.pki_master_dict['pki_subsystem'] in\
             config.PKI_TOMCAT_SUBSYSTEMS:
            config.pki_master_dict['pki_systemd_service'] =\
                config.PKI_DEPLOYMENT_SYSTEMD_ROOT + "/" +\
                "pki-tomcatd" + "@" + ".service"
            config.pki_master_dict['pki_systemd_target'] =\
                config.PKI_DEPLOYMENT_SYSTEMD_ROOT + "/" +\
                "pki-tomcatd.target"
            config.pki_master_dict['pki_systemd_target_wants'] =\
                config.PKI_DEPLOYMENT_SYSTEMD_CONFIGURATION_ROOT + "/" +\
                "pki-tomcatd.target.wants"
            config.pki_master_dict['pki_systemd_service_link'] =\
                config.pki_master_dict['pki_systemd_target_wants'] + "/" +\
                "pki-tomcatd" + "@" +\
                config.pki_master_dict['pki_instance_id'] + ".service"
            config.pki_master_dict['pki_tomcat_bin_path'] =\
                os.path.join(config.PKI_DEPLOYMENT_TOMCAT_ROOT,
                             "bin")
            config.pki_master_dict['pki_tomcat_lib_path'] =\
                os.path.join(config.PKI_DEPLOYMENT_TOMCAT_ROOT,
                             "lib")
            config.pki_master_dict['pki_tomcat_systemd'] =\
                config.PKI_DEPLOYMENT_TOMCAT_SYSTEMD
            config.pki_master_dict['pki_war_source_dir'] =\
                os.path.join(config.PKI_DEPLOYMENT_SOURCE_ROOT,
                             config.pki_master_dict['pki_subsystem'].lower(),
                             "war")
            config.pki_master_dict['pki_source_webapps_path'] =\
                os.path.join(config.PKI_DEPLOYMENT_SOURCE_ROOT,
                             config.pki_master_dict['pki_subsystem'].lower(),
                             "webapps")
            config.pki_master_dict['pki_war'] =\
                os.path.join(config.pki_master_dict['pki_war_source_dir'],
                             config.pki_master_dict['pki_war_file'])
            config.pki_master_dict['pki_source_catalina_properties'] =\
                os.path.join(config.pki_master_dict['pki_source_shared_path'],
                             "catalina.properties")
            config.pki_master_dict['pki_source_servercertnick_conf'] =\
                os.path.join(config.pki_master_dict['pki_source_shared_path'],
                             "serverCertNick.conf")
            config.pki_master_dict['pki_source_server_xml'] =\
                os.path.join(config.pki_master_dict['pki_source_shared_path'],
                             "server.xml")
            config.pki_master_dict['pki_source_context_xml'] =\
                os.path.join(config.pki_master_dict['pki_source_shared_path'],
                             "context.xml")
            config.pki_master_dict['pki_source_tomcat_conf'] =\
                os.path.join(config.pki_master_dict['pki_source_shared_path'],
                             "tomcat.conf")
            config.pki_master_dict['pki_source_index_jsp'] =\
                os.path.join(config.pki_master_dict['pki_source_webapps_path'],
                             "ROOT",
                             "index.jsp")
            config.pki_master_dict['pki_source_webapps_root_web_xml'] =\
                os.path.join(config.pki_master_dict['pki_source_webapps_path'],
                             "ROOT",
                             "WEB-INF",
                             "web.xml")
            if config.pki_master_dict['pki_subsystem'] == "CA":
                config.pki_master_dict['pki_source_emails'] =\
                    os.path.join(config.PKI_DEPLOYMENT_SOURCE_ROOT,
                                 "ca",
                                 "emails")
                config.pki_master_dict['pki_source_flatfile_txt'] =\
                    os.path.join(config.pki_master_dict['pki_source_conf_path'],
                                 "flatfile.txt")
                config.pki_master_dict['pki_source_profiles'] =\
                    os.path.join(config.PKI_DEPLOYMENT_SOURCE_ROOT,
                                 "ca",
                                 "profiles")
                config.pki_master_dict['pki_source_proxy_conf'] =\
                    os.path.join(config.pki_master_dict['pki_source_conf_path'],
                                 "proxy.conf")
                config.pki_master_dict['pki_source_registry_cfg'] =\
                    os.path.join(config.pki_master_dict['pki_source_conf_path'],
                                 "registry.cfg")
                # '*.profile'
                config.pki_master_dict['pki_source_admincert_profile'] =\
                    os.path.join(config.pki_master_dict['pki_source_conf_path'],
                                 "adminCert.profile")
                config.pki_master_dict['pki_source_caauditsigningcert_profile']\
                    = os.path.join(
                          config.pki_master_dict['pki_source_conf_path'],
                          "caAuditSigningCert.profile")
                config.pki_master_dict['pki_source_cacert_profile'] =\
                    os.path.join(config.pki_master_dict['pki_source_conf_path'],
                                 "caCert.profile")
                config.pki_master_dict['pki_source_caocspcert_profile'] =\
                    os.path.join(config.pki_master_dict['pki_source_conf_path'],
                                 "caOCSPCert.profile")
                config.pki_master_dict['pki_source_servercert_profile'] =\
                    os.path.join(config.pki_master_dict['pki_source_conf_path'],
                                 "serverCert.profile")
                config.pki_master_dict['pki_source_subsystemcert_profile'] =\
                    os.path.join(config.pki_master_dict['pki_source_conf_path'],
                                 "subsystemCert.profile")
            elif config.pki_master_dict['pki_subsystem'] == "KRA":
                # '*.profile'
                config.pki_master_dict['pki_source_servercert_profile'] =\
                    os.path.join(config.pki_master_dict['pki_source_conf_path'],
                                 "serverCert.profile")
                config.pki_master_dict['pki_source_storagecert_profile'] =\
                    os.path.join(config.pki_master_dict['pki_source_conf_path'],
                                 "storageCert.profile")
                config.pki_master_dict['pki_source_subsystemcert_profile'] =\
                    os.path.join(config.pki_master_dict['pki_source_conf_path'],
                                 "subsystemCert.profile")
                config.pki_master_dict['pki_source_transportcert_profile'] =\
                    os.path.join(config.pki_master_dict['pki_source_conf_path'],
                                 "transportCert.profile")
        config.pki_master_dict['pki_cgroup_systemd_service_path'] =\
            os.path.join("/sys/fs/cgroup/systemd/system",
                         config.pki_master_dict['pki_systemd_service'])
        config.pki_master_dict['pki_cgroup_systemd_service'] =\
            os.path.join(
                config.pki_master_dict['pki_cgroup_systemd_service_path'],
                config.pki_master_dict['pki_instance_id'])
        config.pki_master_dict['pki_cgroup_cpu_systemd_service_path'] =\
            os.path.join("/sys/fs/cgroup/cpu\,cpuacct/system",
                         config.pki_master_dict['pki_systemd_service'])
        config.pki_master_dict['pki_cgroup_cpu_systemd_service'] =\
            os.path.join(
                config.pki_master_dict['pki_cgroup_cpu_systemd_service_path'],
                config.pki_master_dict['pki_instance_id'])
        # PKI top-level file system layout name/value pairs
        # NOTE:  Never use 'os.path.join()' whenever 'pki_root_prefix'
        #        is being prepended!!!
        config.pki_master_dict['pki_root_prefix'] = config.pki_root_prefix
        config.pki_master_dict['pki_path'] =\
            config.pki_master_dict['pki_root_prefix'] +\
            config.PKI_DEPLOYMENT_BASE_ROOT
        config.pki_master_dict['pki_log_path'] =\
            config.pki_master_dict['pki_root_prefix'] +\
            config.PKI_DEPLOYMENT_LOG_ROOT
        config.pki_master_dict['pki_configuration_path'] =\
            config.pki_master_dict['pki_root_prefix'] +\
            config.PKI_DEPLOYMENT_CONFIGURATION_ROOT
        config.pki_master_dict['pki_registry_path'] =\
            config.pki_master_dict['pki_root_prefix'] +\
            config.PKI_DEPLOYMENT_REGISTRY_ROOT
        # Apache/Tomcat instance base name/value pairs
        config.pki_master_dict['pki_instance_path'] =\
            os.path.join(config.pki_master_dict['pki_path'],
                         config.pki_master_dict['pki_instance_id'])
        # Apache/Tomcat instance log name/value pairs
        config.pki_master_dict['pki_instance_log_path'] =\
            os.path.join(config.pki_master_dict['pki_log_path'],
                         config.pki_master_dict['pki_instance_id'])
        # Apache/Tomcat instance configuration name/value pairs
        config.pki_master_dict['pki_instance_configuration_path'] =\
            os.path.join(config.pki_master_dict['pki_configuration_path'],
                         config.pki_master_dict['pki_instance_id'])
        # Apache/Tomcat instance registry name/value pairs
        # Apache-specific instance name/value pairs
        if config.pki_master_dict['pki_subsystem'] in\
           config.PKI_APACHE_SUBSYSTEMS:
            # Apache instance base name/value pairs
            config.pki_master_dict['pki_instance_type'] = "Apache"
            # Apache instance log name/value pairs
            # Apache instance configuration name/value pairs
            # Apache instance registry name/value pairs
            config.pki_master_dict['pki_instance_type_registry_path'] =\
                os.path.join(
                    config.pki_master_dict['pki_registry_path'],
                    config.pki_master_dict['pki_instance_type'].lower())
            config.pki_master_dict['pki_instance_registry_path'] =\
                os.path.join(
                    config.pki_master_dict['pki_instance_type_registry_path'],
                    config.pki_master_dict['pki_instance_id'])
            # Apache instance convenience symbolic links
        # Tomcat-specific instance name/value pairs
        elif config.pki_master_dict['pki_subsystem'] in\
             config.PKI_TOMCAT_SUBSYSTEMS:
            # Tomcat instance base name/value pairs
            config.pki_master_dict['pki_instance_type'] = "Tomcat"
            config.pki_master_dict['pki_tomcat_common_path'] =\
                os.path.join(config.pki_master_dict['pki_instance_path'],
                             "common")
            config.pki_master_dict['pki_tomcat_common_lib_path'] =\
                os.path.join(config.pki_master_dict['pki_tomcat_common_path'],
                             "lib")
            config.pki_master_dict['pki_tomcat_tmpdir_path'] =\
                os.path.join(config.pki_master_dict['pki_instance_path'],
                             "temp")
            config.pki_master_dict['pki_tomcat_webapps_path'] =\
                os.path.join(config.pki_master_dict['pki_instance_path'],
                             "webapps")
            config.pki_master_dict['pki_tomcat_webapps_root_path'] =\
                os.path.join(config.pki_master_dict['pki_tomcat_webapps_path'],
                             "ROOT")
            config.pki_master_dict['pki_tomcat_webapps_root_webinf_path'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_webapps_root_path'],
                    "WEB-INF")
            config.pki_master_dict['pki_tomcat_webapps_root_webinf_web_xml'] =\
                os.path.join(
                    config.pki_master_dict\
                    ['pki_tomcat_webapps_root_webinf_path'],
                    "web.xml")
            config.pki_master_dict['pki_tomcat_work_path'] =\
                os.path.join(config.pki_master_dict['pki_instance_path'],
                             "work")
            config.pki_master_dict['pki_tomcat_work_catalina_path'] =\
                os.path.join(config.pki_master_dict['pki_tomcat_work_path'],
                             "Catalina")
            config.pki_master_dict['pki_tomcat_work_catalina_host_path'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_work_catalina_path'],
                    "localhost")
            config.pki_master_dict['pki_tomcat_work_catalina_host_run_path'] =\
                os.path.join(
                    config.pki_master_dict\
                    ['pki_tomcat_work_catalina_host_path'],
                    "_")
            config.pki_master_dict\
            ['pki_tomcat_work_catalina_host_subsystem_path'] =\
                os.path.join(
                    config.pki_master_dict\
                    ['pki_tomcat_work_catalina_host_path'],
                    config.pki_master_dict['pki_subsystem'].lower())
            # Tomcat instance log name/value pairs
            # Tomcat instance configuration name/value pairs
            config.pki_master_dict['pki_instance_log4j_properties'] =\
                os.path.join(
                    config.pki_master_dict['pki_instance_configuration_path'],
                    "log4j.properties")
            # Tomcat instance registry name/value pairs
            config.pki_master_dict['pki_instance_type_registry_path'] =\
                os.path.join(
                    config.pki_master_dict['pki_registry_path'],
                    config.pki_master_dict['pki_instance_type'].lower())
            config.pki_master_dict['pki_instance_registry_path'] =\
                os.path.join(
                    config.pki_master_dict['pki_instance_type_registry_path'],
                    config.pki_master_dict['pki_instance_id'])
            # Tomcat instance convenience symbolic links
            config.pki_master_dict['pki_tomcat_bin_link'] =\
                os.path.join(config.pki_master_dict['pki_instance_path'],
                             "bin")
            config.pki_master_dict['pki_tomcat_lib_link'] =\
                os.path.join(config.pki_master_dict['pki_instance_path'],
                             "lib")
            config.pki_master_dict['pki_tomcat_lib_log4j_properties_link'] =\
                os.path.join(config.pki_master_dict['pki_tomcat_lib_path'],
                             "log4j.properties")
            config.pki_master_dict['pki_instance_systemd_link'] =\
                os.path.join(config.pki_master_dict['pki_instance_path'],
                             config.pki_master_dict['pki_instance_id'])
            # Tomcat instance common lib jars
            if config.pki_master_dict['pki_architecture'] == 64:
                config.pki_master_dict['pki_jss_jar'] =\
                    os.path.join("/usr/lib64/java",
                                 "jss4.jar")
                config.pki_master_dict['pki_symkey_jar'] =\
                    os.path.join("/usr/lib64/java",
                                 "symkey.jar")
            else:
                config.pki_master_dict['pki_jss_jar'] =\
                    os.path.join("/usr/lib/java",
                                 "jss4.jar")
                config.pki_master_dict['pki_symkey_jar'] =\
                    os.path.join("/usr/lib/java",
                                 "symkey.jar")
            config.pki_master_dict['pki_apache_commons_collections_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_JAR_SOURCE_ROOT,
                             "apache-commons-collections.jar")
            config.pki_master_dict['pki_apache_commons_lang_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_JAR_SOURCE_ROOT,
                             "apache-commons-lang.jar")
            config.pki_master_dict['pki_apache_commons_logging_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_JAR_SOURCE_ROOT,
                             "apache-commons-logging.jar")
            config.pki_master_dict['pki_commons_codec_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_JAR_SOURCE_ROOT,
                             "commons-codec.jar")
            config.pki_master_dict['pki_httpclient_jar'] =\
                os.path.join(
                    config.PKI_DEPLOYMENT_HTTPCOMPONENTS_JAR_SOURCE_ROOT,
                    "httpclient.jar")
            config.pki_master_dict['pki_httpcore_jar'] =\
                os.path.join(
                    config.PKI_DEPLOYMENT_HTTPCOMPONENTS_JAR_SOURCE_ROOT,
                    "httpcore.jar")
            config.pki_master_dict['pki_javassist_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_JAR_SOURCE_ROOT,
                             "javassist.jar")
            config.pki_master_dict['pki_resteasy_jaxrs_api_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_RESTEASY_JAR_SOURCE_ROOT,
                             "jaxrs-api.jar")
            config.pki_master_dict['pki_jettison_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_JAR_SOURCE_ROOT,
                             "jettison.jar")
            config.pki_master_dict['pki_ldapjdk_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_JAR_SOURCE_ROOT,
                             "ldapjdk.jar")
            config.pki_master_dict['pki_certsrv_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_PKI_JAR_SOURCE_ROOT,
                             "pki-certsrv.jar")
            config.pki_master_dict['pki_cmsbundle'] =\
                os.path.join(config.PKI_DEPLOYMENT_PKI_JAR_SOURCE_ROOT,
                             "pki-cmsbundle.jar")
            config.pki_master_dict['pki_cmscore'] =\
                os.path.join(config.PKI_DEPLOYMENT_PKI_JAR_SOURCE_ROOT,
                             "pki-cmscore.jar")
            config.pki_master_dict['pki_cms'] =\
                os.path.join(config.PKI_DEPLOYMENT_PKI_JAR_SOURCE_ROOT,
                             "pki-cms.jar")
            config.pki_master_dict['pki_cmsutil'] =\
                os.path.join(config.PKI_DEPLOYMENT_PKI_JAR_SOURCE_ROOT,
                             "pki-cmsutil.jar")
            config.pki_master_dict['pki_nsutil'] =\
                os.path.join(config.PKI_DEPLOYMENT_PKI_JAR_SOURCE_ROOT,
                             "pki-nsutil.jar")
            config.pki_master_dict['pki_resteasy_atom_provider_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_RESTEASY_JAR_SOURCE_ROOT,
                             "resteasy-atom-provider.jar")
            config.pki_master_dict['pki_resteasy_jaxb_provider_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_RESTEASY_JAR_SOURCE_ROOT,
                             "resteasy-jaxb-provider.jar")
            config.pki_master_dict['pki_resteasy_jaxrs_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_RESTEASY_JAR_SOURCE_ROOT,
                             "resteasy-jaxrs.jar")
            config.pki_master_dict['pki_resteasy_jettison_provider_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_RESTEASY_JAR_SOURCE_ROOT,
                             "resteasy-jettison-provider.jar")
            config.pki_master_dict['pki_scannotation_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_JAR_SOURCE_ROOT,
                             "scannotation.jar")
            config.pki_master_dict['pki_tomcatjss_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_JAR_SOURCE_ROOT,
                             "tomcat7jss.jar")
            config.pki_master_dict['pki_velocity_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_JAR_SOURCE_ROOT,
                             "velocity.jar")
            config.pki_master_dict['pki_xerces_j2_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_JAR_SOURCE_ROOT,
                             "xerces-j2.jar")
            config.pki_master_dict['pki_xml_commons_apis_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_JAR_SOURCE_ROOT,
                             "xml-commons-apis.jar")
            config.pki_master_dict['pki_xml_commons_resolver_jar'] =\
                os.path.join(config.PKI_DEPLOYMENT_JAR_SOURCE_ROOT,
                             "xml-commons-resolver.jar")
            # Tomcat instance common lib jar symbolic links
            config.pki_master_dict['pki_jss_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "jss4.jar")
            config.pki_master_dict['pki_symkey_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "symkey.jar")
            config.pki_master_dict['pki_apache_commons_collections_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "apache-commons-collections.jar")
            config.pki_master_dict['pki_apache_commons_lang_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "apache-commons-lang.jar")
            config.pki_master_dict['pki_apache_commons_logging_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "apache-commons-logging.jar")
            config.pki_master_dict['pki_commons_codec_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "apache-commons-codec.jar")
            config.pki_master_dict['pki_httpclient_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "httpclient.jar")
            config.pki_master_dict['pki_httpcore_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "httpcore.jar")
            config.pki_master_dict['pki_javassist_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "javassist.jar")
            config.pki_master_dict['pki_resteasy_jaxrs_api_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "jaxrs-api.jar")
            config.pki_master_dict['pki_jettison_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "jettison.jar")
            config.pki_master_dict['pki_ldapjdk_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "ldapjdk.jar")
            config.pki_master_dict['pki_certsrv_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "pki-certsrv.jar")
            config.pki_master_dict['pki_cmsbundle_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "pki-cmsbundle.jar")
            config.pki_master_dict['pki_cmscore_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "pki-cmscore.jar")
            config.pki_master_dict['pki_cms_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "pki-cms.jar")
            config.pki_master_dict['pki_cmsutil_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "pki-cmsutil.jar")
            config.pki_master_dict['pki_nsutil_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "pki-nsutil.jar")
            config.pki_master_dict['pki_resteasy_atom_provider_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "resteasy-atom-provider.jar")
            config.pki_master_dict['pki_resteasy_jaxb_provider_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "resteasy-jaxb-provider.jar")
            config.pki_master_dict['pki_resteasy_jaxrs_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "resteasy-jaxrs.jar")
            config.pki_master_dict['pki_resteasy_jettison_provider_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "resteasy-jettison-provider.jar")
            config.pki_master_dict['pki_scannotation_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "scannotation.jar")
            config.pki_master_dict['pki_tomcatjss_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "tomcatjss.jar")
            config.pki_master_dict['pki_velocity_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "velocity.jar")
            config.pki_master_dict['pki_xerces_j2_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "xerces-j2.jar")
            config.pki_master_dict['pki_xml_commons_apis_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "xml-commons-apis.jar")
            config.pki_master_dict['pki_xml_commons_resolver_jar_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "xml-commons-resolver.jar")
        # Instance layout NSS security database name/value pairs
        config.pki_master_dict['pki_database_path'] =\
            os.path.join(
                config.pki_master_dict['pki_instance_configuration_path'],
                "alias")
        # Apache/Tomcat instance convenience symbolic links
        config.pki_master_dict['pki_instance_database_link'] =\
            os.path.join(config.pki_master_dict['pki_instance_path'],
                         "alias")
        config.pki_master_dict['pki_instance_conf_link'] =\
            os.path.join(config.pki_master_dict['pki_instance_path'],
                         "conf")
        config.pki_master_dict['pki_instance_logs_link'] =\
            os.path.join(config.pki_master_dict['pki_instance_path'],
                         "logs")
        # Instance-based PKI subsystem base name/value pairs
        config.pki_master_dict['pki_subsystem_path'] =\
            os.path.join(config.pki_master_dict['pki_instance_path'],
                         config.pki_master_dict['pki_subsystem'].lower())
        # Instance-based PKI subsystem log name/value pairs
        config.pki_master_dict['pki_subsystem_log_path'] =\
            os.path.join(config.pki_master_dict['pki_instance_log_path'],
                         config.pki_master_dict['pki_subsystem'].lower())
        config.pki_master_dict['pki_subsystem_archive_log_path'] =\
            os.path.join(config.pki_master_dict['pki_subsystem_log_path'],
                         "archive")
        # Instance-based PKI subsystem configuration name/value pairs
        config.pki_master_dict['pki_subsystem_configuration_path'] =\
            os.path.join(
                config.pki_master_dict['pki_instance_configuration_path'],
                config.pki_master_dict['pki_subsystem'].lower())
        # Instance-based PKI subsystem registry name/value pairs
        config.pki_master_dict['pki_subsystem_registry_path'] =\
            os.path.join(config.pki_master_dict['pki_instance_registry_path'],
                         config.pki_master_dict['pki_subsystem'].lower())
        # Instance-based Apache/Tomcat PKI subsystem name/value pairs
        if config.pki_master_dict['pki_subsystem'] in\
           config.PKI_APACHE_SUBSYSTEMS:
            # Instance-based Apache PKI subsystem base name/value pairs
            # Instance-based Apache PKI subsystem log name/value pairs
            if config.pki_master_dict['pki_subsystem'] == "TPS":
                config.pki_master_dict['pki_subsystem_signed_audit_log_path'] =\
                os.path.join(config.pki_master_dict['pki_subsystem_log_path'],
                             "signedAudit")
            # Instance-based Apache PKI subsystem configuration name/value pairs
            # Instance-based Apache PKI subsystem registry name/value pairs
            # Instance-based Apache PKI subsystem convenience symbolic links
        elif config.pki_master_dict['pki_subsystem'] in\
             config.PKI_TOMCAT_SUBSYSTEMS:
            # Instance-based Tomcat PKI subsystem base name/value pairs
            if config.pki_master_dict['pki_subsystem'] == "CA":
                config.pki_master_dict['pki_subsystem_emails_path'] =\
                os.path.join(config.pki_master_dict['pki_subsystem_path'],
                             "emails")
                config.pki_master_dict['pki_subsystem_profiles_path'] =\
                os.path.join(config.pki_master_dict['pki_subsystem_path'],
                             "profiles")
            # Instance-based Tomcat PKI subsystem log name/value pairs
            config.pki_master_dict['pki_subsystem_signed_audit_log_path'] =\
                os.path.join(config.pki_master_dict['pki_subsystem_log_path'],
                             "signedAudit")
            # Instance-based Tomcat PKI subsystem configuration name/value pairs
            # Instance-based Tomcat PKI subsystem registry name/value pairs
            # Instance-based Tomcat PKI subsystem convenience symbolic links
            config.pki_master_dict['pki_subsystem_tomcat_webapps_link'] =\
                os.path.join(config.pki_master_dict['pki_subsystem_path'],
                             "webapps")
        # Instance-based Apache/Tomcat PKI subsystem convenience symbolic links
        config.pki_master_dict['pki_subsystem_database_link'] =\
            os.path.join(config.pki_master_dict['pki_subsystem_path'],
                         "alias")
        config.pki_master_dict['pki_subsystem_conf_link'] =\
            os.path.join(config.pki_master_dict['pki_subsystem_path'],
                         "conf")
        config.pki_master_dict['pki_subsystem_logs_link'] =\
            os.path.join(config.pki_master_dict['pki_subsystem_path'],
                         "logs")
        config.pki_master_dict['pki_subsystem_registry_link'] =\
            os.path.join(config.pki_master_dict['pki_subsystem_path'],
                         "registry")
        # PKI Target (war file) name/value pairs
        if config.pki_master_dict['pki_subsystem'] in\
           config.PKI_TOMCAT_SUBSYSTEMS:
            # Tomcat PKI subsystem war file base name/value pairs
            config.pki_master_dict['pki_tomcat_webapps_subsystem_path'] =\
                os.path.join(config.pki_master_dict['pki_tomcat_webapps_path'],
                             config.pki_master_dict['pki_subsystem'].lower())
            config.pki_master_dict\
            ['pki_tomcat_webapps_subsystem_webinf_classes_path'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_webapps_subsystem_path'],
                    "WEB-INF",
                    "classes")
            config.pki_master_dict\
            ['pki_tomcat_webapps_subsystem_webinf_lib_path'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_webapps_subsystem_path'],
                    "WEB-INF",
                    "lib")
            # Tomcat PKI subsystem war file convenience symbolic links
            if config.pki_master_dict['pki_subsystem'] == "CA":
                config.pki_master_dict['pki_ca_jar'] =\
                    os.path.join(config.PKI_DEPLOYMENT_PKI_JAR_SOURCE_ROOT,
                                 "pki-ca.jar")
                # config.pki_master_dict['pki_ca_jar_link'] =\
                #     os.path.join(
                #         config.pki_master_dict\
                #         ['pki_tomcat_webapps_subsystem_webinf_lib_path'],
                #         "pki-ca.jar")
                config.pki_master_dict['pki_ca_jar_link'] =\
                    os.path.join(
                        config.pki_master_dict['pki_tomcat_common_lib_path'],
                        "pki-ca.jar")
            elif config.pki_master_dict['pki_subsystem'] == "KRA":
                config.pki_master_dict['pki_kra_jar'] =\
                    os.path.join(config.PKI_DEPLOYMENT_PKI_JAR_SOURCE_ROOT,
                                 "pki-kra.jar")
                # config.pki_master_dict['pki_kra_jar_link'] =\
                #     os.path.join(
                #         config.pki_master_dict\
                #         ['pki_tomcat_webapps_subsystem_webinf_lib_path'],
                #         "pki-kra.jar")
                config.pki_master_dict['pki_kra_jar_link'] =\
                    os.path.join(
                        config.pki_master_dict['pki_tomcat_common_lib_path'],
                        "pki-kra.jar")
            elif config.pki_master_dict['pki_subsystem'] == "OCSP":
                config.pki_master_dict['pki_ocsp_jar'] =\
                    os.path.join(config.PKI_DEPLOYMENT_PKI_JAR_SOURCE_ROOT,
                                 "pki-ocsp.jar")
                # config.pki_master_dict['pki_ocsp_jar_link'] =\
                #     os.path.join(
                #         config.pki_master_dict\
                #         ['pki_tomcat_webapps_subsystem_webinf_lib_path'],
                #         "pki-ocsp.jar")
                config.pki_master_dict['pki_ocsp_jar_link'] =\
                    os.path.join(
                        config.pki_master_dict['pki_tomcat_common_lib_path'],
                        "pki-ocsp.jar")
            elif config.pki_master_dict['pki_subsystem'] == "TKS":
                config.pki_master_dict['pki_tks_jar'] =\
                    os.path.join(config.PKI_DEPLOYMENT_PKI_JAR_SOURCE_ROOT,
                                 "pki-tks.jar")
                # config.pki_master_dict['pki_tks_jar_link'] =\
                #     os.path.join(
                #         config.pki_master_dict\
                #         ['pki_tomcat_webapps_subsystem_webinf_lib_path'],
                #         "pki-tks.jar")
                config.pki_master_dict['pki_tks_jar_link'] =\
                    os.path.join(
                        config.pki_master_dict['pki_tomcat_common_lib_path'],
                        "pki-tks.jar")
        # PKI Target (slot substitution) name/value pairs
        config.pki_master_dict['pki_target_cs_cfg'] =\
            os.path.join(
                config.pki_master_dict['pki_subsystem_configuration_path'],
                "CS.cfg")
        config.pki_master_dict['pki_target_registry'] =\
            os.path.join(config.pki_master_dict['pki_instance_registry_path'],
                         config.pki_master_dict['pki_instance_id'])
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
                config.pki_master_dict['pki_instance_id']
            config.pki_master_dict['pki_target_tomcat_conf'] =\
                os.path.join(
                    config.pki_master_dict['pki_instance_configuration_path'],
                    "tomcat.conf")
            config.pki_master_dict['pki_target_index_jsp'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_webapps_root_path'],
                    "index.jsp")
            # in-place slot substitution name/value pairs
            config.pki_master_dict['pki_target_auth_properties'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_webapps_subsystem_path'],
                    "WEB-INF",
                    "auth.properties")
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
            config.pki_master_dict['pki_instance_id']
        config.pki_master_dict['PKI_INSTANCE_INITSCRIPT_SLOT'] =\
            os.path.join(config.pki_master_dict['pki_instance_path'],
                         config.pki_master_dict['pki_instance_id'])
        config.pki_master_dict['PKI_REGISTRY_FILE_SLOT'] =\
            os.path.join(config.pki_master_dict['pki_subsystem_registry_path'],
                         config.pki_master_dict['pki_instance_id'])
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
                config.pki_sensitive_dict['pki_pin']
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
            config.pki_master_dict['PKI_RANDOM_NUMBER_SLOT'] =\
                config.pki_sensitive_dict['pki_one_time_pin']
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
                config.pki_master_dict['pki_instance_id'] + ".service"
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
                "/var/run/" + config.pki_master_dict['pki_instance_id'] + ".pid"
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
            "Server-Cert cert-" + config.pki_master_dict['pki_instance_id']
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
        # Client NSS security database name/value pairs
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and is NOT redefined below:
        #
        #         config.pki_sensitive_dict['pki_client_pkcs12_password']
        #         config.pki_master_dict['pki_client_database_purge']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and potentially overridden below:
        #
        #         config.pki_sensitive_dict['pki_client_database_password']
        #         config.pki_master_dict['pki_client_dir']
        #
        if not len(config.pki_sensitive_dict['pki_client_database_password']):
            # use randomly generated client 'pin'
            config.pki_sensitive_dict['pki_client_database_password'] =\
                str(config.pki_sensitive_dict['pki_client_pin'])
        if not len(config.pki_master_dict['pki_client_dir']):
            config.pki_master_dict['pki_client_dir'] =\
                os.path.join(
                    "/tmp",
                    config.pki_master_dict['pki_instance_id'] + "_" + "client")
        if not len(config.pki_master_dict['pki_client_database_dir']):
            config.pki_master_dict['pki_client_database_dir'] =\
                os.path.join(
                    config.pki_master_dict['pki_client_dir'],
                    "alias")
        config.pki_master_dict['pki_client_password_conf'] =\
            os.path.join(
                config.pki_master_dict['pki_client_dir'],
                "password.conf")
        config.pki_master_dict['pki_client_pkcs12_password_conf'] =\
            os.path.join(
                config.pki_master_dict['pki_client_dir'],
                "pkcs12_password.conf")
        config.pki_master_dict['pki_client_cert_database'] =\
            os.path.join(config.pki_master_dict['pki_client_database_dir'],
                         "cert8.db")
        config.pki_master_dict['pki_client_key_database'] =\
            os.path.join(config.pki_master_dict['pki_client_database_dir'],
                         "key3.db")
        config.pki_master_dict['pki_client_secmod_database'] =\
            os.path.join(config.pki_master_dict['pki_client_database_dir'],
                         "secmod.db")
        config.pki_master_dict['pki_client_admin_cert'] =\
            config.pki_master_dict['pki_subsystem'].lower() + "_" +\
            "admin" + "." + "cert"
        # NOTE:  ALWAYS store the PKCS #12 "client" Admin Cert file
        #        in with the NSS "server" security databases
        config.pki_master_dict['pki_client_admin_cert_p12'] =\
            config.pki_master_dict['pki_database_path'] + "/" +\
            config.pki_master_dict['pki_subsystem'].lower() + "_" +\
            "admin" + "_" + "cert" + "." + "p12"
        # Jython scriptlet name/value pairs
        config.pki_master_dict['pki_jython_configuration_scriptlet'] =\
            os.path.join(sys.prefix,
                         "lib",
                         "python" + str(sys.version_info[0]) + "." +
                         str(sys.version_info[1]),
                         "site-packages",
                         "pki",
                         "deployment",
                         "configuration.jy")
        config.pki_master_dict['pki_jython_base_uri'] =\
            "https" + "://" + config.pki_master_dict['pki_hostname'] + ":" +\
            config.pki_master_dict['pki_https_port'] + "/" +\
            config.pki_master_dict['pki_subsystem'].lower()
        # Jython scriptlet
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
        #         config.pki_sensitive_dict['pki_clone_pkcs12_password']
        #         config.pki_sensitive_dict['pki_security_domain_password']
        #         config.pki_sensitive_dict['pki_token_password']
        #         config.pki_master_dict['pki_clone_pkcs12_path']
        #         config.pki_master_dict['pki_clone_uri']
        #         config.pki_master_dict['pki_security_domain_https_port']
        #         config.pki_master_dict['pki_security_domain_user']
        #         config.pki_master_dict['pki_token_name']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and potentially overridden below:
        #
        #         config.pki_master_dict['pki_issuing_ca']
        #         config.pki_master_dict['pki_security_domain_hostname']
        #         config.pki_master_dict['pki_security_domain_name']
        #         config.pki_master_dict['pki_subsystem_name']
        #
        if not len(config.pki_master_dict['pki_subsystem_name']):
            config.pki_master_dict['pki_subsystem_name'] =\
                config.pki_subsystem + " " +\
                config.pki_master_dict['pki_hostname'] + " " +\
                config.pki_master_dict['pki_https_port']
        if config.pki_subsystem != "CA" or\
           config.str2bool(config.pki_master_dict['pki_clone']) or\
           config.str2bool(config.pki_master_dict['pki_subordinate']):
            # PKI KRA, PKI OCSP, PKI RA, PKI TKS, PKI TPS,
            # CA Clone, KRA Clone, OCSP Clone, TKS Clone, or
            # Subordinate CA
            config.pki_master_dict['pki_security_domain_type'] = "existing"
            if not len(config.pki_master_dict['pki_security_domain_name']):
                # Guess that the security domain resides on the local host
                config.pki_master_dict['pki_security_domain_name'] =\
                    config.pki_master_dict['pki_dns_domainname'] + " " +\
                    "Security Domain"
            if not\
               len(config.pki_master_dict['pki_security_domain_hostname']):
                # Guess that the security domain resides on the local host
                config.pki_master_dict['pki_security_domain_hostname'] =\
                    config.pki_master_dict['pki_hostname']
            config.pki_master_dict['pki_security_domain_uri'] =\
                "https" + "://" +\
                config.pki_master_dict['pki_security_domain_hostname'] + ":" +\
                config.pki_master_dict['pki_security_domain_https_port']
            if not len(config.pki_master_dict['pki_issuing_ca']):
                # Guess that it is the same as the
                # config.pki_master_dict['pki_security_domain_uri']
                config.pki_master_dict['pki_issuing_ca'] =\
                    config.pki_master_dict['pki_security_domain_uri']
        elif config.str2bool(config.pki_master_dict['pki_external']):
            # External CA
            #
            #     NOTE:  External CA's DO NOT require a security domain
            #
            if not len(config.pki_master_dict['pki_issuing_ca']):
                config.pki_master_dict['pki_issuing_ca'] = "External CA"
        else:
            # PKI CA
            config.pki_master_dict['pki_security_domain_type'] = "new"
            if not len(config.pki_master_dict['pki_security_domain_name']):
                # Guess that the security domain resides on the local host
                config.pki_master_dict['pki_security_domain_name'] =\
                    config.pki_master_dict['pki_dns_domainname'] + " " +\
                    "Security Domain"
        # Jython scriptlet
        # 'Directory Server' Configuration name/value pairs
        #
        #     Apache - [TPS]
        #     Tomcat - [CA], [KRA], [OCSP], [TKS]
        #            - [CA Clone], [KRA Clone], [OCSP Clone], [TKS Clone]
        #            - [External CA]
        #            - [Subordinate CA]
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and are NOT redefined below:
        #
        #         config.pki_sensitive_dict['pki_ds_password']
        #         config.pki_master_dict['pki_clone_replication_security']
        #         config.pki_master_dict['pki_ds_bind_dn']
        #         config.pki_master_dict['pki_ds_ldap_port']
        #         config.pki_master_dict['pki_ds_ldaps_port']
        #         config.pki_master_dict['pki_ds_remove_data']
        #         config.pki_master_dict['pki_ds_secure_connection']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and potentially overridden below:
        #
        #         config.pki_master_dict['pki_ds_base_dn']
        #         config.pki_master_dict['pki_ds_database']
        #         config.pki_master_dict['pki_ds_hostname']
        #
        if not config.str2bool(config.pki_master_dict['pki_clone']):
            if not len(config.pki_master_dict['pki_ds_base_dn']):
                # if the instance is NOT a clone, create a default BASE DN
                # of "o=${pki_instance_id}"; the reason that this default
                # CANNOT be created if the instance is a clone is due to the
                # fact that a master and clone MUST share the same BASE DN,
                # and creating this default would prevent the ability to
                # place a master and clone on the same machine (the method
                # most often used for testing purposes)
                config.pki_master_dict['pki_ds_base_dn'] =\
                    "o=" + config.pki_master_dict['pki_instance_id']
        if not len(config.pki_master_dict['pki_ds_database']):
            config.pki_master_dict['pki_ds_database'] =\
                config.pki_master_dict['pki_instance_id']
        if not len(config.pki_master_dict['pki_ds_hostname']):
            # Guess that the Directory Server resides on the local host
            config.pki_master_dict['pki_ds_hostname'] =\
                config.pki_master_dict['pki_hostname']
        # Jython scriptlet
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

        # Jython scriptlet
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
        #        config.pki_sensitive_dict['pki_backup_password']
        #        config.pki_master_dict['pki_backup_keys']
        #
        if config.str2bool(config.pki_master_dict['pki_backup_keys']):
            # NOTE:  ALWAYS store the PKCS #12 backup keys file
            #        in with the NSS "server" security databases
            config.pki_master_dict['pki_backup_keys_p12'] =\
                config.pki_master_dict['pki_database_path'] + "/" +\
                config.pki_master_dict['pki_subsystem'].lower() + "_" +\
                "backup" + "_" + "keys" + "." + "p12"
        # Jython scriptlet
        # 'Admin Certificate' Configuration name/value pairs
        #
        #     Apache - [RA], [TPS]
        #     Tomcat - [CA], [KRA], [OCSP], [TKS]
        #            - [External CA]
        #            - [Subordinate CA]
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and are NOT redefined below:
        #
        #         config.pki_sensitive_dict['pki_admin_password']
        #         config.pki_master_dict['pki_admin_cert_request_type']
        #         config.pki_master_dict['pki_admin_dualkey']
        #         config.pki_master_dict['pki_admin_keysize']
        #         config.pki_master_dict['pki_admin_name']
        #         config.pki_master_dict['pki_admin_uid']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and potentially overridden below:
        #
        #         config.pki_master_dict['pki_admin_email']
        #         config.pki_master_dict['pki_admin_nickname']
        #         config.pki_master_dict['pki_admin_subject_dn']
        #
        config.pki_master_dict['pki_admin_profile_id'] = "caAdminCert"
        if not len(config.pki_master_dict['pki_admin_email']):
            config.pki_master_dict['pki_admin_email'] =\
                config.pki_master_dict['pki_admin_name'] + "@" +\
                config.pki_master_dict['pki_dns_domainname']
        if not len(config.pki_master_dict['pki_admin_nickname']):
            if config.pki_subsystem in config.PKI_APACHE_SUBSYSTEMS:
                if config.pki_master_dict['pki_subsystem'] == "RA":
                    # PKI RA
                    config.pki_master_dict['pki_admin_nickname'] =\
                        "RA Administrator&#39;s" + " " +\
                        config.pki_master_dict['pki_security_domain_name'] +\
                        " " + "ID"
                elif config.pki_master_dict['pki_subsystem'] == "TPS":
                    # PKI TPS
                    config.pki_master_dict['pki_admin_nickname'] =\
                        "TPS Administrator&#39;s" + " " +\
                        config.pki_master_dict['pki_security_domain_name'] +\
                        " " + "ID"
            elif config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
                if not config.str2bool(config.pki_master_dict['pki_clone']):
                    if config.pki_master_dict['pki_subsystem'] == "CA":
                        if config.str2bool(
                            config.pki_master_dict['pki_external']):
                             # External CA
                             config.pki_master_dict['pki_admin_nickname'] =\
                                 "CA Administrator of Instance" + " " +\
                                 config.pki_master_dict['pki_instance_id'] +\
                                 "&#39;s" + " " +\
                                 "External CA ID"
                        else:
                            # PKI CA or Subordinate CA
                            config.pki_master_dict['pki_admin_nickname'] =\
                                "CA Administrator of Instance" + " " +\
                                config.pki_master_dict['pki_instance_id'] +\
                                "&#39;s" + " " +\
                                config.pki_master_dict\
                                ['pki_security_domain_name'] + " " + "ID"
                    elif config.pki_master_dict['pki_subsystem'] == "KRA":
                        # PKI KRA
                        config.pki_master_dict['pki_admin_nickname'] =\
                            "KRA Administrator of Instance" + " " +\
                            config.pki_master_dict['pki_instance_id'] +\
                            "&#39;s" + " " +\
                            config.pki_master_dict['pki_security_domain_name']\
                            + " " + "ID"
                    elif config.pki_master_dict['pki_subsystem'] == "OCSP":
                        # PKI OCSP
                        config.pki_master_dict['pki_admin_nickname'] =\
                            "OCSP Administrator of Instance" + " " +\
                            config.pki_master_dict['pki_instance_id'] +\
                            "&#39;s" + " " +\
                            config.pki_master_dict['pki_security_domain_name']\
                            + " " + "ID"
                    elif config.pki_master_dict['pki_subsystem'] == "TKS":
                        # PKI TKS
                        config.pki_master_dict['pki_admin_nickname'] =\
                            "TKS Administrator of Instance" + " " +\
                            config.pki_master_dict['pki_instance_id'] +\
                            "&#39;s" + " " +\
                            config.pki_master_dict['pki_security_domain_name']\
                            + " " + "ID"
        if not len(config.pki_master_dict['pki_admin_subject_dn']):
            if config.pki_subsystem in config.PKI_APACHE_SUBSYSTEMS:
                if config.pki_master_dict['pki_subsystem'] == "RA":
                    # PKI RA
                    config.pki_master_dict['pki_admin_subject_dn'] =\
                        "cn=" + "RA Administrator" + "," +\
                        "uid=" + config.pki_master_dict['pki_admin_uid'] +\
                        "," + "e=" +\
                        config.pki_master_dict['pki_admin_email'] +\
                        "," + "o=" +\
                        config.pki_master_dict['pki_security_domain_name']
                elif config.pki_master_dict['pki_subsystem'] == "TPS":
                    # PKI TPS
                    config.pki_master_dict['pki_admin_subject_dn'] =\
                        "cn=" + "TPS Administrator" + "," +\
                        "uid=" + config.pki_master_dict['pki_admin_uid'] +\
                        "," + "e=" +\
                        config.pki_master_dict['pki_admin_email'] +\
                        "," + "o=" +\
                        config.pki_master_dict['pki_security_domain_name']
            elif config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
                if not config.str2bool(config.pki_master_dict['pki_clone']):
                    if config.pki_master_dict['pki_subsystem'] == "CA":
                       if config.str2bool(
                           config.pki_master_dict['pki_external']):
                            # External CA
                            config.pki_master_dict['pki_admin_subject_dn'] =\
                                "cn=" + "CA Administrator of Instance" + " " +\
                                config.pki_master_dict['pki_instance_id'] +\
                                "," + "uid=" +\
                                config.pki_master_dict['pki_admin_uid']\
                                + "," + "e=" +\
                                config.pki_master_dict['pki_admin_email'] +\
                                "," + "o=" + "External CA"
                       else:
                            # PKI CA or Subordinate CA
                            config.pki_master_dict['pki_admin_subject_dn'] =\
                                "cn=" + "CA Administrator of Instance" + " " +\
                                config.pki_master_dict['pki_instance_id'] +\
                                "," + "uid=" +\
                                config.pki_master_dict['pki_admin_uid']\
                                + "," + "e=" +\
                                config.pki_master_dict['pki_admin_email'] +\
                                "," + "o=" +\
                                config.pki_master_dict\
                                ['pki_security_domain_name']
                    elif config.pki_master_dict['pki_subsystem'] == "KRA":
                        # PKI KRA
                        config.pki_master_dict['pki_admin_subject_dn'] =\
                            "cn=" + "KRA Administrator of Instance" + " " +\
                            config.pki_master_dict['pki_instance_id'] + "," +\
                            "uid=" + config.pki_master_dict['pki_admin_uid'] +\
                            "," + "e=" +\
                            config.pki_master_dict['pki_admin_email'] +\
                            "," + "o=" +\
                            config.pki_master_dict['pki_security_domain_name']
                    elif config.pki_master_dict['pki_subsystem'] == "OCSP":
                        # PKI OCSP
                        config.pki_master_dict['pki_admin_subject_dn'] =\
                            "cn=" + "OCSP Administrator of Instance" + " " +\
                            config.pki_master_dict['pki_instance_id'] + "," +\
                            "uid=" + config.pki_master_dict['pki_admin_uid'] +\
                            "," + "e=" +\
                            config.pki_master_dict['pki_admin_email'] +\
                            "," + "o=" +\
                            config.pki_master_dict['pki_security_domain_name']
                    elif config.pki_master_dict['pki_subsystem'] == "TKS":
                        # PKI TKS
                        config.pki_master_dict['pki_admin_subject_dn'] =\
                            "cn=" + "TKS Administrator of Instance" + " " +\
                            config.pki_master_dict['pki_instance_id'] + "," +\
                            "uid=" + config.pki_master_dict['pki_admin_uid'] +\
                            "," + "e=" +\
                            config.pki_master_dict['pki_admin_email'] +\
                            "," + "o=" +\
                            config.pki_master_dict['pki_security_domain_name']
        # Jython scriptlet
        # 'CA Signing Certificate' Configuration name/value pairs
        #
        #     Tomcat - [CA]
        #            - [External CA]
        #            - [Subordinate CA]
        #
        #     The following variables are defined below:
        #
        #         config.pki_master_dict['pki_ca_signing_tag']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and are NOT redefined below:
        #
        #         config.pki_master_dict['pki_ca_signing_key_algorithm']
        #         config.pki_master_dict['pki_ca_signing_key_size']
        #         config.pki_master_dict['pki_ca_signing_key_type']
        #         config.pki_master_dict['pki_ca_signing_signing_algorithm']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and potentially overridden below:
        #
        #         config.pki_master_dict['pki_ca_signing_nickname']
        #         config.pki_master_dict['pki_ca_signing_subject_dn']
        #         config.pki_master_dict['pki_ca_signing_token']
        #
        if config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
            if not config.str2bool(config.pki_master_dict['pki_clone']):
                if config.pki_master_dict['pki_subsystem'] == "CA":
                    # config.pki_master_dict['pki_ca_signing_nickname']
                    if not len(config.pki_master_dict\
                               ['pki_ca_signing_nickname']):
                        config.pki_master_dict['pki_ca_signing_nickname'] =\
                            "caSigningCert" + " " + "cert-" +\
                            config.pki_master_dict['pki_instance_id']
                    # config.pki_master_dict['pki_ca_signing_subject_dn']
                    if config.str2bool(config.pki_master_dict['pki_external']):
                        # External CA
                        if not len(config.pki_master_dict\
                                   ['pki_ca_signing_subject_dn']):
                            config.pki_master_dict['pki_ca_signing_subject_dn']\
                                =  "cn=" + "External CA Signing Certificate"
                    elif config.str2bool(
                             config.pki_master_dict['pki_subordinate']):
                        # Subordinate CA
                        if not len(config.pki_master_dict\
                                   ['pki_ca_signing_subject_dn']):
                            config.pki_master_dict['pki_ca_signing_subject_dn']\
                                =  "cn=" + "SubCA Signing Certificate" +\
                                   "," + "o=" +\
                                   config.pki_master_dict\
                                   ['pki_security_domain_name']
                    else:
                        # PKI CA
                        if not len(config.pki_master_dict\
                                   ['pki_ca_signing_subject_dn']):
                            config.pki_master_dict['pki_ca_signing_subject_dn']\
                                =  "cn=" + "CA Signing Certificate" +\
                                   "," + "o=" +\
                                   config.pki_master_dict\
                                   ['pki_security_domain_name']
                    # config.pki_master_dict['pki_ca_signing_tag']
                    config.pki_master_dict['pki_ca_signing_tag'] =\
                        "signing"
                    # config.pki_master_dict['pki_ca_signing_token']
                    if not len(config.pki_master_dict['pki_ca_signing_token']):
                        config.pki_master_dict['pki_ca_signing_token'] =\
                            "Internal Key Storage Token"
        # Jython scriptlet
        # 'OCSP Signing Certificate' Configuration name/value pairs
        #
        #     Tomcat - [CA], [OCSP]
        #            - [External CA]
        #            - [Subordinate CA]
        #
        #     The following variables are defined below:
        #
        #         config.pki_master_dict['pki_ocsp_signing_tag']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and are NOT redefined below:
        #
        #         config.pki_master_dict['pki_ocsp_signing_key_algorithm']
        #         config.pki_master_dict['pki_ocsp_signing_key_size']
        #         config.pki_master_dict['pki_ocsp_signing_key_type']
        #         config.pki_master_dict['pki_ocsp_signing_signing_algorithm']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and potentially overridden below:
        #
        #         config.pki_master_dict['pki_ocsp_signing_nickname']
        #         config.pki_master_dict['pki_ocsp_signing_subject_dn']
        #         config.pki_master_dict['pki_ocsp_signing_token']
        #
        if config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
            if not config.str2bool(config.pki_master_dict['pki_clone']):
                if config.pki_master_dict['pki_subsystem'] == "CA":
                    if not len(config.pki_master_dict\
                               ['pki_ocsp_signing_nickname']):
                        config.pki_master_dict['pki_ocsp_signing_nickname'] =\
                            "ocspSigningCert" + " " + "cert-" +\
                            config.pki_master_dict['pki_instance_id']
                    if config.str2bool(config.pki_master_dict['pki_external']):
                        # External CA
                        if not len(config.pki_master_dict\
                                   ['pki_ocsp_signing_subject_dn']):
                            config.pki_master_dict\
                            ['pki_ocsp_signing_subject_dn'] =\
                                "cn=" + "External CA OCSP Signing Certificate"
                    elif config.str2bool(
                             config.pki_master_dict['pki_subordinate']):
                        # Subordinate CA
                        if not len(config.pki_master_dict\
                                   ['pki_ocsp_signing_subject_dn']):
                            config.pki_master_dict\
                            ['pki_ocsp_signing_subject_dn'] =\
                                "cn=" + "SubCA OCSP Signing Certificate"\
                                + "," + "o=" +\
                                config.pki_master_dict\
                                ['pki_security_domain_name']
                    else:
                        # PKI CA
                        if not len(config.pki_master_dict\
                                   ['pki_ocsp_signing_subject_dn']):
                            config.pki_master_dict\
                            ['pki_ocsp_signing_subject_dn'] =\
                                "cn=" + "CA OCSP Signing Certificate"\
                                + "," + "o=" +\
                                config.pki_master_dict\
                                ['pki_security_domain_name']
                    config.pki_master_dict['pki_ocsp_signing_tag'] =\
                        "ocsp_signing"
                    if not len(config.pki_master_dict\
                               ['pki_ocsp_signing_token']):
                        config.pki_master_dict['pki_ocsp_signing_token'] =\
                            "Internal Key Storage Token"
                elif config.pki_master_dict['pki_subsystem'] == "OCSP":
                    # PKI OCSP
                    if not len(config.pki_master_dict\
                               ['pki_ocsp_signing_nickname']):
                        config.pki_master_dict['pki_ocsp_signing_nickname'] =\
                            "ocspSigningCert" + " " + "cert-" +\
                            config.pki_master_dict['pki_instance_id']
                    if not len(config.pki_master_dict\
                               ['pki_ocsp_signing_subject_dn']):
                        config.pki_master_dict['pki_ocsp_signing_subject_dn'] =\
                            "cn=" + "OCSP Signing Certificate" + "," + "o=" +\
                            config.pki_master_dict['pki_security_domain_name']
                    config.pki_master_dict['pki_ocsp_signing_tag'] =\
                        "signing"
                    if not len(config.pki_master_dict\
                               ['pki_ocsp_signing_token']):
                        config.pki_master_dict['pki_ocsp_signing_token'] =\
                            "Internal Key Storage Token"
        # Jython scriptlet
        # 'SSL Server Certificate' Configuration name/value pairs
        #
        #     Apache - [RA], [TPS]
        #     Tomcat - [CA], [KRA], [OCSP], [TKS]
        #            - [CA Clone], [KRA Clone], [OCSP Clone], [TKS Clone]
        #            - [External CA]
        #            - [Subordinate CA]
        #
        #     The following variables are defined below:
        #
        #         config.pki_master_dict['pki_ssl_server_tag']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and are NOT redefined below:
        #
        #         config.pki_master_dict['pki_ssl_server_key_algorithm']
        #         config.pki_master_dict['pki_ssl_server_key_size']
        #         config.pki_master_dict['pki_ssl_server_key_type']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and potentially overridden below:
        #
        #         config.pki_master_dict['pki_ssl_server_nickname']
        #         config.pki_master_dict['pki_ssl_server_subject_dn']
        #         config.pki_master_dict['pki_ssl_server_token']
        #
        if not len(config.pki_master_dict['pki_ssl_server_nickname']):
            config.pki_master_dict['pki_ssl_server_nickname'] =\
                "Server-Cert" + " " + "cert-" +\
                config.pki_master_dict['pki_instance_id']
        if not len(config.pki_master_dict['pki_ssl_server_subject_dn']):
            if config.pki_subsystem in config.PKI_APACHE_SUBSYSTEMS:
                config.pki_master_dict['pki_ssl_server_subject_dn'] =\
                    "cn=" + config.pki_master_dict['pki_hostname'] +\
                    "," + "ou=" + config.pki_master_dict['pki_instance_id'] +\
                    "," + "o=" +\
                    config.pki_master_dict['pki_security_domain_name']
            elif config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
                if config.pki_master_dict['pki_subsystem'] == "CA" and\
                   config.str2bool(config.pki_master_dict['pki_external']):
                    # External CA
                    config.pki_master_dict['pki_ssl_server_subject_dn'] =\
                        "cn=" + config.pki_master_dict['pki_hostname'] +\
                        "," + "o=" + "External CA"
                else:
                    # PKI or Cloned CA, KRA, OCSP, TKS, or Subordinate CA
                    config.pki_master_dict['pki_ssl_server_subject_dn'] =\
                        "cn=" + config.pki_master_dict['pki_hostname'] +\
                        "," + "o=" +\
                        config.pki_master_dict['pki_security_domain_name']
        config.pki_master_dict['pki_ssl_server_tag'] = "sslserver"
        if not len(config.pki_master_dict['pki_ssl_server_token']):
            config.pki_master_dict['pki_ssl_server_token'] =\
                "Internal Key Storage Token"
        # Jython scriptlet
        # 'Subsystem Certificate' Configuration name/value pairs
        #
        #     Apache - [RA], [TPS]
        #     Tomcat - [CA], [KRA], [OCSP], [TKS]
        #            - [External CA]
        #            - [Subordinate CA]
        #
        #     The following variables are defined below:
        #
        #         config.pki_master_dict['pki_subsystem_tag']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and are NOT redefined below:
        #
        #         config.pki_master_dict['pki_subsystem_key_algorithm']
        #         config.pki_master_dict['pki_subsystem_key_size']
        #         config.pki_master_dict['pki_subsystem_key_type']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and potentially overridden below:
        #
        #         config.pki_master_dict['pki_subsystem_nickname']
        #         config.pki_master_dict['pki_subsystem_subject_dn']
        #         config.pki_master_dict['pki_subsystem_token']
        #
        if config.pki_subsystem in config.PKI_APACHE_SUBSYSTEMS:
            if not len(config.pki_master_dict['pki_subsystem_nickname']):
                config.pki_master_dict['pki_subsystem_nickname'] =\
                    "subsystemCert" + " " + "cert-" +\
                    config.pki_master_dict['pki_instance_id']
            if not len(config.pki_master_dict['pki_subsystem_subject_dn']):
                if config.pki_master_dict['pki_subsystem'] == "RA":
                    # PKI RA
                    config.pki_master_dict['pki_subsystem_subject_dn'] =\
                        "cn=" + "RA Subsystem Certificate" +\
                        "," + "ou=" + config.pki_master_dict['pki_instance_id']\
                        + "," + "o=" +\
                        config.pki_master_dict['pki_security_domain_name']
                elif config.pki_master_dict['pki_subsystem'] == "TPS":
                    # PKI TPS
                    config.pki_master_dict['pki_subsystem_subject_dn'] =\
                        "cn=" + "TPS Subsystem Certificate" +\
                        "," + "ou=" + config.pki_master_dict['pki_instance_id']\
                        + "," + "o=" +\
                        config.pki_master_dict['pki_security_domain_name']
            config.pki_master_dict['pki_subsystem_tag'] = "subsystem"
            if not len(config.pki_master_dict['pki_subsystem_token']):
                config.pki_master_dict['pki_subsystem_token'] =\
                    "Internal Key Storage Token"
        elif config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
            if not config.str2bool(config.pki_master_dict['pki_clone']):
                if not len(config.pki_master_dict['pki_subsystem_nickname']):
                    config.pki_master_dict['pki_subsystem_nickname'] =\
                        "subsystemCert" + " " + "cert-" +\
                        config.pki_master_dict['pki_instance_id']
                if not len(config.pki_master_dict['pki_subsystem_subject_dn']):
                    if config.pki_master_dict['pki_subsystem'] == "CA":
                        if config.str2bool(
                               config.pki_master_dict['pki_external']):
                            # External CA
                            config.pki_master_dict['pki_subsystem_subject_dn']\
                                = "cn=" + "External CA Subsystem Certificate"
                        elif config.str2bool(
                                 config.pki_master_dict['pki_subordinate']):
                            # Subordinate CA
                            config.pki_master_dict['pki_subsystem_subject_dn']\
                                = "cn=" + "SubCA Subsystem Certificate" +\
                                  "," + "o=" +\
                                  config.pki_master_dict\
                                  ['pki_security_domain_name']
                        else:
                            # PKI CA
                            config.pki_master_dict['pki_subsystem_subject_dn']\
                                = "cn=" + "CA Subsystem Certificate" +\
                                  "," + "o=" +\
                                  config.pki_master_dict\
                                  ['pki_security_domain_name']
                    elif config.pki_master_dict['pki_subsystem'] == "KRA":
                        # PKI KRA
                        config.pki_master_dict['pki_subsystem_subject_dn'] =\
                            "cn=" + "DRM Subsystem Certificate" +\
                            "," + "o=" +\
                            config.pki_master_dict\
                            ['pki_security_domain_name']
                    elif config.pki_master_dict['pki_subsystem'] == "OCSP":
                        # PKI OCSP
                        config.pki_master_dict['pki_subsystem_subject_dn'] =\
                            "cn=" + "OCSP Subsystem Certificate" +\
                            "," + "o=" +\
                            config.pki_master_dict\
                            ['pki_security_domain_name']
                    elif config.pki_master_dict['pki_subsystem'] == "TKS":
                        # PKI TKS
                        config.pki_master_dict['pki_subsystem_subject_dn'] =\
                            "cn=" + "TKS Subsystem Certificate" +\
                            "," + "o=" +\
                            config.pki_master_dict\
                            ['pki_security_domain_name']
                config.pki_master_dict['pki_subsystem_tag'] = "subsystem"
                if not len(config.pki_master_dict['pki_subsystem_token']):
                    config.pki_master_dict['pki_subsystem_token'] =\
                        "Internal Key Storage Token"
        # Jython scriptlet
        # 'Audit Signing Certificate' Configuration name/value pairs
        #
        #     Apache - [TPS]
        #     Tomcat - [CA], [KRA], [OCSP], [TKS]
        #            - [External CA]
        #            - [Subordinate CA]
        #
        #     The following variables are defined below:
        #
        #         config.pki_master_dict['pki_audit_signing_tag']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and are NOT redefined below:
        #
        #         config.pki_master_dict['pki_audit_signing_key_algorithm']
        #         config.pki_master_dict['pki_audit_signing_key_size']
        #         config.pki_master_dict['pki_audit_signing_key_type']
        #         config.pki_master_dict['pki_audit_signing_signing_algorithm']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and potentially overridden below:
        #
        #         config.pki_master_dict['pki_audit_signing_nickname']
        #         config.pki_master_dict['pki_audit_signing_subject_dn']
        #         config.pki_master_dict['pki_audit_signing_token']
        #
        if config.pki_subsystem in config.PKI_APACHE_SUBSYSTEMS:
            if config.pki_master_dict['pki_subsystem'] != "RA":
                if not len(config.pki_master_dict\
                           ['pki_audit_signing_nickname']):
                    config.pki_master_dict['pki_audit_signing_nickname'] =\
                        "auditSigningCert" + " " + "cert-" +\
                        config.pki_master_dict['pki_instance_id']
                if not len(config.pki_master_dict\
                           ['pki_audit_signing_subject_dn']):
                    config.pki_master_dict['pki_audit_signing_subject_dn'] =\
                        "cn=" + "TPS Audit Signing Certificate" +\
                        "," + "ou=" + config.pki_master_dict['pki_instance_id']\
                        + "," + "o=" +\
                        config.pki_master_dict['pki_security_domain_name']
                config.pki_master_dict['pki_audit_signing_tag'] =\
                    "audit_signing"
                if not len(config.pki_master_dict['pki_audit_signing_token']):
                    config.pki_master_dict['pki_audit_signing_token'] =\
                        "Internal Key Storage Token"
        elif config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
            if not config.str2bool(config.pki_master_dict['pki_clone']):
                if not len(config.pki_master_dict\
                           ['pki_audit_signing_nickname']):
                    config.pki_master_dict['pki_audit_signing_nickname'] =\
                        "auditSigningCert" + " " + "cert-" +\
                        config.pki_master_dict['pki_instance_id']
                if not len(config.pki_master_dict\
                           ['pki_audit_signing_subject_dn']):
                    if config.pki_master_dict['pki_subsystem'] == "CA":
                        if config.str2bool(
                               config.pki_master_dict['pki_external']):
                            # External CA
                            config.pki_master_dict\
                            ['pki_audit_signing_subject_dn'] =\
                                "cn=" + "External CA Audit Signing Certificate"
                        elif config.str2bool(
                                 config.pki_master_dict['pki_subordinate']):
                            # Subordinate CA
                            config.pki_master_dict\
                            ['pki_audit_signing_subject_dn'] =\
                                "cn=" + "SubCA Audit Signing Certificate" +\
                                "," + "o=" +\
                                config.pki_master_dict\
                                ['pki_security_domain_name']
                        else:
                            # PKI CA
                            config.pki_master_dict\
                            ['pki_audit_signing_subject_dn'] =\
                                "cn=" + "CA Audit Signing Certificate" +\
                                "," + "o=" +\
                                config.pki_master_dict\
                                ['pki_security_domain_name']
                    elif config.pki_master_dict['pki_subsystem'] == "KRA":
                        # PKI KRA
                        config.pki_master_dict['pki_audit_signing_subject_dn']\
                            = "cn=" + "DRM Audit Signing Certificate" +\
                              "," + "o=" +\
                              config.pki_master_dict['pki_security_domain_name']
                    elif config.pki_master_dict['pki_subsystem'] == "OCSP":
                        # PKI OCSP
                        config.pki_master_dict['pki_audit_signing_subject_dn']\
                            = "cn=" + "OCSP Audit Signing Certificate" +\
                              "," + "o=" +\
                              config.pki_master_dict['pki_security_domain_name']
                    elif config.pki_master_dict['pki_subsystem'] == "TKS":
                        # PKI TKS
                        config.pki_master_dict['pki_audit_signing_subject_dn']\
                            = "cn=" + "TKS Audit Signing Certificate" +\
                              "," + "o=" +\
                              config.pki_master_dict['pki_security_domain_name']
                config.pki_master_dict['pki_audit_signing_tag'] =\
                    "audit_signing"
                if not len(config.pki_master_dict['pki_audit_signing_token']):
                    config.pki_master_dict['pki_audit_signing_token'] =\
                        "Internal Key Storage Token"
        # Jython scriptlet
        # 'DRM Transport Certificate' Configuration name/value pairs
        #
        #     Tomcat - [KRA]
        #
        #     The following variables are defined below:
        #
        #         config.pki_master_dict['pki_transport_tag']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and are NOT redefined below:
        #
        #         config.pki_master_dict['pki_transport_key_algorithm']
        #         config.pki_master_dict['pki_transport_key_size']
        #         config.pki_master_dict['pki_transport_key_type']
        #         config.pki_master_dict['pki_transport_signing_algorithm']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and potentially overridden below:
        #
        #         config.pki_master_dict['pki_transport_nickname']
        #         config.pki_master_dict['pki_transport_subject_dn']
        #         config.pki_master_dict['pki_transport_token']
        #
        if config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
            if not config.str2bool(config.pki_master_dict['pki_clone']):
                if config.pki_master_dict['pki_subsystem'] == "KRA":
                    # PKI KRA
                    if not len(config.pki_master_dict\
                               ['pki_transport_nickname']):
                        config.pki_master_dict['pki_transport_nickname'] =\
                            "transportCert" + " " + "cert-" +\
                            config.pki_master_dict['pki_instance_id']
                    if not len(config.pki_master_dict\
                               ['pki_transport_subject_dn']):
                        config.pki_master_dict['pki_transport_subject_dn']\
                            = "cn=" + "DRM Transport Certificate" +\
                              "," + "o=" +\
                              config.pki_master_dict['pki_security_domain_name']
                    config.pki_master_dict['pki_transport_tag'] =\
                        "transport"
                    if not len(config.pki_master_dict['pki_transport_token']):
                        config.pki_master_dict['pki_transport_token'] =\
                            "Internal Key Storage Token"
        # Jython scriptlet
        # 'DRM Storage Certificate' Configuration name/value pairs
        #
        #     Tomcat - [KRA]
        #
        #     The following variables are defined below:
        #
        #         config.pki_master_dict['pki_storage_tag']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and are NOT redefined below:
        #
        #         config.pki_master_dict['pki_storage_key_algorithm']
        #         config.pki_master_dict['pki_storage_key_size']
        #         config.pki_master_dict['pki_storage_key_type']
        #         config.pki_master_dict['pki_storage_signing_algorithm']
        #
        #     The following variables are established via the specified PKI
        #     deployment configuration file and potentially overridden below:
        #
        #         config.pki_master_dict['pki_storage_nickname']
        #         config.pki_master_dict['pki_storage_subject_dn']
        #         config.pki_master_dict['pki_storage_token']
        #
        if config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
            if not config.str2bool(config.pki_master_dict['pki_clone']):
                if config.pki_master_dict['pki_subsystem'] == "KRA":
                    # PKI KRA
                    if not len(config.pki_master_dict['pki_storage_nickname']):
                        config.pki_master_dict['pki_storage_nickname'] =\
                            "storageCert" + " " + "cert-" +\
                            config.pki_master_dict['pki_instance_id']
                    if not len(config.pki_master_dict\
                               ['pki_storage_subject_dn']):
                        config.pki_master_dict['pki_storage_subject_dn']\
                            = "cn=" + "DRM Storage Certificate" +\
                              "," + "o=" +\
                              config.pki_master_dict['pki_security_domain_name']
                    config.pki_master_dict['pki_storage_tag'] =\
                        "storage"
                    if not len(config.pki_master_dict['pki_storage_token']):
                        config.pki_master_dict['pki_storage_token'] =\
                            "Internal Key Storage Token"
        # Finalization name/value pairs
        config.pki_master_dict['pki_deployment_cfg_replica'] =\
            os.path.join(config.pki_master_dict['pki_subsystem_registry_path'],
                         config.PKI_DEPLOYMENT_DEFAULT_CONFIGURATION_FILE)
        config.pki_master_dict['pki_deployment_cfg_spawn_archive'] =\
            config.pki_master_dict['pki_subsystem_archive_log_path'] + "/" +\
            "spawn" + "_" +\
            config.PKI_DEPLOYMENT_DEFAULT_CONFIGURATION_FILE + "." +\
            config.pki_master_dict['pki_timestamp']
        config.pki_master_dict['pki_deployment_cfg_respawn_archive'] =\
            config.pki_master_dict['pki_subsystem_archive_log_path'] + "/" +\
            "respawn" + "_" +\
            config.PKI_DEPLOYMENT_DEFAULT_CONFIGURATION_FILE + "." +\
            config.pki_master_dict['pki_timestamp']
        config.pki_master_dict['pki_manifest'] =\
            config.pki_master_dict['pki_subsystem_registry_path'] + "/" +\
            "manifest"
        config.pki_master_dict['pki_manifest_spawn_archive'] =\
            config.pki_master_dict['pki_subsystem_archive_log_path'] + "/" +\
            "spawn" + "_" + "manifest" + "." +\
            config.pki_master_dict['pki_timestamp']
        config.pki_master_dict['pki_manifest_respawn_archive'] =\
            config.pki_master_dict['pki_subsystem_archive_log_path'] + "/" +\
            "respawn" + "_" + "manifest" + "." +\
            config.pki_master_dict['pki_timestamp']
    except OSError as exc:
        config.pki_log.error(log.PKI_OSERROR_1, exc,
                             extra=config.PKI_INDENTATION_LEVEL_2)
        sys.exit(1)
    except KeyError as err:
        config.pki_log.error(log.PKIHELPER_DICTIONARY_MASTER_MISSING_KEY_1,
                             err, extra=config.PKI_INDENTATION_LEVEL_2)
        sys.exit(1)
    return


def compose_pki_slots_dictionary():
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
