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
import time


# PKI Deployment Imports
import pkiconfig as config
import pkimessages as log


# PKI Deployment Helper Functions
def process_command_line_arguments(argv):
    "Read and process command-line options"
    description = None
    if os.path.basename(argv[0]) == 'pkispawn':
        description = 'PKI Instance Installation and Configuration'
    elif os.path.basename(argv[0]) == 'pkidestroy':
        description = 'PKI Instance Removal'
    parser = argparse.ArgumentParser(
                 description=description,
                 add_help=False,
                 formatter_class=argparse.RawDescriptionHelpFormatter,
                 epilog=log.PKI_VERBOSITY)
    mandatory = parser.add_argument_group('mandatory arguments')
    mandatory.add_argument('-s',
                           dest='pki_subsystem', action='store',
                           nargs=1, choices=config.PKI_SUBSYSTEMS,
                           required=True, metavar='<subsystem>',
                           help='where <subsystem> is '
                                'CA, KRA, OCSP, RA, TKS, or TPS')
    optional = parser.add_argument_group('optional arguments')
    optional.add_argument('--dry_run',
                          dest='pki_dry_run_flag', action='store_true',
                          help='do not actually perform any actions')
    optional.add_argument('-f',
                          dest='pkideployment_cfg', action='store',
                          nargs=1, metavar='<file>',
                          help='overrides default configuration filename')
    optional.add_argument('-h', '--help',
                          dest='help', action='help',
                          help='show this help message and exit')
    optional.add_argument('-p',
                          dest='pki_root_prefix', action='store',
                          nargs=1, metavar='<prefix>',
                          help='directory prefix to specify local directory')
    if os.path.basename(argv[0]) == 'pkispawn':
        optional.add_argument('-u',
                              dest='pki_update_flag', action='store_true',
                              help='update instance of specified subsystem')
    optional.add_argument('-v',
                          dest='pki_verbosity', action='count',
                          help='display verbose information (details below)')
    custom = parser.add_argument_group('custom arguments '
                                       '(OVERRIDES configuration file values)')
    custom.add_argument('-i',
                        dest='pki_instance_name', action='store',
                        nargs=1, metavar='<instance>',
                        help='PKI instance name (MUST specify REQUIRED ports)')
    custom.add_argument('--http_port',
                        dest='pki_http_port', action='store',
                        nargs=1, metavar='<port>',
                        help='HTTP port (CA, KRA, OCSP, RA, TKS, TPS)')
    custom.add_argument('--https_port',
                        dest='pki_https_port', action='store',
                        nargs=1, metavar='<port>',
                        help='HTTPS port (CA, KRA, OCSP, RA, TKS, TPS)')
    custom.add_argument('--ajp_port',
                        dest='pki_ajp_port', action='store',
                        nargs=1, metavar='<port>',
                        help='AJP port (CA, KRA, OCSP, TKS)')
    args = parser.parse_args()

    config.pki_subsystem = str(args.pki_subsystem).strip('[\']')
    if args.pki_dry_run_flag:
        config.pki_dry_run_flag = args.pki_dry_run_flag
    if not args.pki_root_prefix is None:
        config.pki_root_prefix = str(args.pki_root_prefix).strip('[\']')
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
    if os.path.basename(argv[0]) == 'pkispawn':
        if args.pki_update_flag:
            config.pki_update_flag = args.pki_update_flag
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
        parser.print_help()
        parser.exit(-1);
    if not args.pki_instance_name is None:
        config.pki_instance_name = str(args.pki_instance_name).strip('[\']')
    if not args.pki_http_port is None:
        config.pki_http_port = str(args.pki_http_port).strip('[\']')
    if not args.pki_https_port is None:
        config.pki_https_port = str(args.pki_https_port).strip('[\']')
    if not args.pki_ajp_port is None:
        if config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
            config.pki_ajp_port = str(args.pki_ajp_port).strip('[\']')
        else:
            print "ERROR:  " +\
                  log.PKI_CUSTOM_TOMCAT_AJP_PORT_1 %\
                  config.pki_subsystem
            print
            parser.print_help()
            parser.exit(-1);
    if not args.pki_instance_name is None or\
       not args.pki_http_port is None or\
       not args.pki_https_port is None or\
       not args.pki_ajp_port is None:
        if config.pki_subsystem in config.PKI_APACHE_SUBSYSTEMS:
            if args.pki_instance_name is None or\
               args.pki_http_port is None or\
               args.pki_https_port is None:
                print "ERROR:  " + log.PKI_CUSTOM_APACHE_INSTANCE_1 %\
                      config.pki_subsystem
                print
                parser.print_help()
                parser.exit(-1);
        elif config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
            if args.pki_instance_name is None or\
               args.pki_http_port is None or\
               args.pki_https_port is None or\
               args.pki_ajp_port is None:
                print "ERROR:  " + log.PKI_CUSTOM_TOMCAT_INSTANCE_1 %\
                      config.pki_subsystem
                print
                parser.print_help()
                parser.exit(-1);
    if not args.pkideployment_cfg is None:
        config.pkideployment_cfg = str(args.pkideployment_cfg).strip('[\']')
    elif os.path.basename(argv[0]) == 'pkidestroy':
        # NOTE:  When performing 'pkidestroy', a configuration file must be
        #        explicitly specified if it does not use the default location
        #        and/or default configuration file name.
        if config.pki_subsystem in config.PKI_APACHE_SUBSYSTEMS:
            pki_web_server = "Apache"
        elif config.pki_subsystem in config.PKI_TOMCAT_SUBSYSTEMS:
            pki_web_server = "Tomcat"
        config.pkideployment_cfg = config.pki_root_prefix +\
            config.PKI_DEPLOYMENT_REGISTRY_ROOT + "/" +\
            config.PKI_DEPLOYMENT_DEFAULT_INSTANCE_NAME + "/" +\
            pki_web_server.lower() +"/" +\
            config.pki_subsystem.lower() +"/" +\
            config.PKI_DEPLOYMENT_DEFAULT_CONFIGURATION_FILE
    if not os.path.exists(config.pkideployment_cfg) or\
       not os.path.isfile(config.pkideployment_cfg):
        print "ERROR:  " +\
              log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %\
              config.pkideployment_cfg
        print
        parser.print_help()
        parser.exit(-1);
    return


def read_pki_configuration_file():
    "Read configuration file sections into dictionaries"
    rv = 0
    try:
        parser = ConfigParser.ConfigParser()
        # Make keys case-sensitive!
        parser.optionxform = str
        parser.read(config.pkideployment_cfg)
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
        config.pki_master_dict['pki_install_time'] = config.pki_install_time
        config.pki_master_dict['pki_timestamp'] = config.pki_timestamp
        config.pki_master_dict['pki_certificate_timestamp'] =\
            config.pki_certificate_timestamp
        config.pki_master_dict['pki_hostname'] = config.pki_hostname
        config.pki_master_dict['pki_pin'] = config.pki_pin
        config.pki_master_dict['pki_one_time_pin'] = config.pki_one_time_pin
        # Configuration file name/value pairs
        config.pki_master_dict.update(config.pki_common_dict)
        config.pki_master_dict.update(config.pki_web_server_dict)
        config.pki_master_dict.update(config.pki_subsystem_dict)
        config.pki_master_dict.update(__name__="PKI Master Dictionary")
        # IMPORTANT:  A "PKI instance" no longer corresponds to a single
        #             pki subystem, but rather to zero or one unique
        #             "Tomcat web instance" AND/OR zero or one unique
        #             "Apache web instance".  Obviously, each
        #             "PKI instance" must contain at least one of these
        #             two web instances.  The name of the default
        #             "PKI instance" is called "default" and may be
        #             changed in the PKI deployment configuration file,
        #             and/or overridden via the command-line interface.
        #
        #             A "Tomcat instance" consists of a single process
        #             which may itself contain zero or one unique
        #             "CA" and/or "KRA" and/or "OCSP" and/or "TKS"
        #             pki subystems.  Obviously, the "Tomcat instance" must
        #             contain at least one of these four pki subystems.
        #
        #             Similarly, an "Apache instance" consists of a single
        #             process which may itself contain zero or one unique
        #             "RA" and/or "TPS" pki subsystems.  Obviously, the
        #             "Apache instance" must contain at least one of these
        #             two pki subystems.
        #
        #             To emulate the original behavior of having a CA and
        #             KRA be unique PKI instances, each must be located
        #             within a separately named "PKI instance" if residing
        #             on the same host machine, or may be located within
        #             an identically named "PKI instance" when residing on
        #             two separate host machines.
        #
        # PKI INSTANCE NAMING CONVENTION:
        #
        #     OLD:  "pki-${pki_subsystem}"
        #           (e. g. Tomcat - "pki-ca", "pki-kra", "pki-ocsp", "pki-tks")
        #           (e. g. Apache - "pki-ra", "pki-tps")
        #     NEW:  "pki-${pki_instance_name}-${pki_web_server}"
        #           (e. g. Tomcat:  "pki-default-tomcat")
        #           (e. g. Apache:  "pki-default-apache")
        #
        config.pki_master_dict['pki_instance_id'] =\
            "pki" + "-" + config.pki_master_dict['pki_instance_name'] + "-" +\
            config.pki_master_dict['pki_web_server'].lower()
        # PKI Source name/value pairs
        config.pki_master_dict['pki_source_conf_path'] =\
            os.path.join(config.pki_master_dict['pki_source_root'],
                         config.pki_master_dict['pki_subsystem'].lower(),
                         "conf")
        config.pki_master_dict['pki_source_setup_path'] =\
            os.path.join(config.pki_master_dict['pki_source_root'],
                         config.pki_master_dict['pki_subsystem'].lower(),
                         "setup")
        config.pki_master_dict['pki_source_cs_cfg'] =\
            os.path.join(config.pki_master_dict['pki_source_conf_path'],
                         "CS.cfg")
        config.pki_master_dict['pki_source_registry'] =\
            os.path.join(config.pki_master_dict['pki_source_setup_path'],
                         "registry_instance")
        if config.pki_master_dict['pki_subsystem'] in\
           config.PKI_TOMCAT_SUBSYSTEMS:
            config.pki_master_dict['pki_tomcat_bin_path'] =\
                os.path.join(config.pki_master_dict['pki_tomcat_root'],
                             "bin")
            config.pki_master_dict['pki_tomcat_lib_path'] =\
                os.path.join(config.pki_master_dict['pki_tomcat_root'],
                             "lib")
            config.pki_master_dict['pki_war_path'] =\
                os.path.join(config.pki_master_dict['pki_source_root'],
                             config.pki_master_dict['pki_subsystem'].lower(),
                             "war")
            config.pki_master_dict['pki_source_webapps_path'] =\
                os.path.join(config.pki_master_dict['pki_source_root'],
                             config.pki_master_dict['pki_subsystem'].lower(),
                             "webapps")
            config.pki_master_dict['pki_war'] =\
                os.path.join(config.pki_master_dict['pki_war_path'],
                             config.pki_master_dict['pki_war_name'])
            config.pki_master_dict['pki_source_catalina_properties'] =\
                os.path.join(config.pki_master_dict['pki_source_conf_path'],
                             "catalina.properties")
            config.pki_master_dict['pki_source_servercertnick_conf'] =\
                os.path.join(config.pki_master_dict['pki_source_conf_path'],
                             "serverCertNick.conf")
            config.pki_master_dict['pki_source_server_xml'] =\
                os.path.join(config.pki_master_dict['pki_source_conf_path'],
                             "server.xml")
            config.pki_master_dict['pki_source_tomcat_conf'] =\
                os.path.join(config.pki_master_dict['pki_source_conf_path'],
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
                    os.path.join(config.pki_master_dict['pki_source_root'],
                                 "ca",
                                 "emails")
                config.pki_master_dict['pki_source_profiles'] =\
                    os.path.join(config.pki_master_dict['pki_source_root'],
                                 "ca",
                                 "profiles")
                config.pki_master_dict['pki_source_proxy_conf'] =\
                    os.path.join(config.pki_master_dict['pki_source_conf_path'],
                                 "proxy.conf")
        # Instance layout base name/value pairs
        # NOTE:  Never use 'os.path.join()' whenever 'pki_root_prefix'
        #        is being prepended!!!
        config.pki_master_dict['pki_root_prefix'] = config.pki_root_prefix
        config.pki_master_dict['pki_path'] =\
            config.pki_master_dict['pki_root_prefix'] +\
            config.pki_master_dict['pki_instance_root']
        config.pki_master_dict['pki_instance_path'] =\
            os.path.join(config.pki_master_dict['pki_path'],
                         config.pki_master_dict['pki_instance_name'])
        # Instance layout log name/value pairs
        config.pki_master_dict['pki_log_path'] =\
            config.pki_master_dict['pki_root_prefix'] +\
            config.pki_master_dict['pki_instance_log_root']
        config.pki_master_dict['pki_instance_log_path'] =\
            os.path.join(config.pki_master_dict['pki_log_path'],
                         config.pki_master_dict['pki_instance_name'])
        # Instance layout configuration name/value pairs
        config.pki_master_dict['pki_configuration_path'] =\
            config.pki_master_dict['pki_root_prefix'] +\
            config.pki_master_dict['pki_instance_configuration_root']
        config.pki_master_dict['pki_instance_configuration_path'] =\
            os.path.join(config.pki_master_dict['pki_configuration_path'],
                         config.pki_master_dict['pki_instance_name'])
        # Instance layout registry name/value pairs
        config.pki_master_dict['pki_registry_path'] =\
            config.pki_master_dict['pki_root_prefix'] +\
            config.PKI_DEPLOYMENT_REGISTRY_ROOT
        config.pki_master_dict['pki_instance_registry_path'] =\
            os.path.join(config.pki_master_dict['pki_registry_path'],
                         config.pki_master_dict['pki_instance_name'])
        # Instance layout NSS security database name/value pairs
        config.pki_master_dict['pki_database_path'] =\
            os.path.join(
                config.pki_master_dict['pki_instance_configuration_path'],
                "alias")
        # Instance layout convenience symbolic links
        config.pki_master_dict['pki_instance_database_link'] =\
            os.path.join(config.pki_master_dict['pki_instance_path'],
                         "alias")
        # Instance-based Apache/Tomcat webserver base name/value pairs
        config.pki_master_dict['pki_webserver_path'] =\
            os.path.join(config.pki_master_dict['pki_instance_path'],
                         config.pki_master_dict['pki_web_server'].lower())
        # Instance-based Apache/Tomcat webserver log name/value pairs
        config.pki_master_dict['pki_webserver_log_path'] =\
            os.path.join(config.pki_master_dict['pki_instance_log_path'],
                         config.pki_master_dict['pki_web_server'].lower())
        # Instance-based Apache/Tomcat webserver configuration name/value pairs
        config.pki_master_dict['pki_webserver_configuration_path'] =\
            os.path.join(
                config.pki_master_dict['pki_instance_configuration_path'],
                config.pki_master_dict['pki_web_server'].lower())
        # Instance-based Apache/Tomcat webserver registry name/value pairs
        config.pki_master_dict['pki_webserver_registry_path'] =\
            os.path.join(config.pki_master_dict['pki_instance_registry_path'],
                         config.pki_master_dict['pki_web_server'].lower())
        # Instance-based Tomcat-specific webserver name/value pairs
        if config.pki_master_dict['pki_subsystem'] in\
           config.PKI_TOMCAT_SUBSYSTEMS:
            # Instance-based Tomcat webserver base name/value pairs
            config.pki_master_dict['pki_tomcat_common_path'] =\
                os.path.join(config.pki_master_dict['pki_webserver_path'],
                             "common")
            config.pki_master_dict['pki_tomcat_common_lib_path'] =\
                os.path.join(config.pki_master_dict['pki_tomcat_common_path'],
                             "lib")
            config.pki_master_dict['pki_tomcat_webapps_path'] =\
                os.path.join(config.pki_master_dict['pki_webserver_path'],
                             "webapps")
            config.pki_master_dict['pki_tomcat_webapps_root_path'] =\
                os.path.join(config.pki_master_dict['pki_tomcat_webapps_path'],
                             "ROOT")
            config.pki_master_dict['pki_tomcat_webapps_root_webinf_path'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_webapps_root_path'],
                    "WEB-INF")
            config.pki_master_dict['pki_tomcat_webapps_webinf_path'] =\
                os.path.join(config.pki_master_dict['pki_tomcat_webapps_path'],
                             "WEB-INF")
            config.pki_master_dict['pki_tomcat_webapps_webinf_classes_path'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_webapps_webinf_path'],
                    "classes")
            config.pki_master_dict['pki_tomcat_webapps_webinf_lib_path'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_webapps_webinf_path'],
                    "lib")
            config.pki_master_dict['pki_tomcat_webapps_root_webinf_web_xml'] =\
                os.path.join(
                    config.pki_master_dict\
                    ['pki_tomcat_webapps_root_webinf_path'],
                    "web.xml")
            # Instance-based Tomcat webserver log name/value pairs
            # Instance-based Tomcat webserver configuration name/value pairs
            # Instance-based Tomcat webserver registry name/value pairs
            # Instance-based Tomcat webserver convenience symbolic links
            config.pki_master_dict['pki_tomcat_bin_link'] =\
                os.path.join(config.pki_master_dict['pki_webserver_path'],
                             "bin")
            config.pki_master_dict['pki_tomcat_lib_link'] =\
                os.path.join(config.pki_master_dict['pki_webserver_path'],
                             "lib")
            config.pki_master_dict['pki_webserver_systemd_link'] =\
                os.path.join(config.pki_master_dict['pki_webserver_path'],
                             config.pki_master_dict['pki_instance_id'])
        # Instance-based Apache/Tomcat webserver convenience symbolic links
        config.pki_master_dict['pki_webserver_database_link'] =\
            os.path.join(config.pki_master_dict['pki_webserver_path'],
                         "alias")
        config.pki_master_dict['pki_webserver_conf_link'] =\
            os.path.join(config.pki_master_dict['pki_webserver_path'],
                         "conf")
        config.pki_master_dict['pki_webserver_logs_link'] =\
            os.path.join(config.pki_master_dict['pki_webserver_path'],
                         "logs")
        # Instance-based PKI subsystem base name/value pairs
        config.pki_master_dict['pki_subsystem_path'] =\
            os.path.join(config.pki_master_dict['pki_webserver_path'],
                         config.pki_master_dict['pki_subsystem'].lower())
        # Instance-based PKI subsystem log name/value pairs
        config.pki_master_dict['pki_subsystem_log_path'] =\
            os.path.join(config.pki_master_dict['pki_webserver_log_path'],
                         config.pki_master_dict['pki_subsystem'].lower())
        # Instance-based PKI subsystem configuration name/value pairs
        config.pki_master_dict['pki_subsystem_configuration_path'] =\
            os.path.join(
                config.pki_master_dict['pki_webserver_configuration_path'],
                config.pki_master_dict['pki_subsystem'].lower())
        # Instance-based PKI subsystem registry name/value pairs
        config.pki_master_dict['pki_subsystem_registry_path'] =\
            os.path.join(config.pki_master_dict['pki_webserver_registry_path'],
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
            config.pki_master_dict['pki_tomcat_webapps_subsystem_path'] =\
                os.path.join(config.pki_master_dict['pki_tomcat_webapps_path'],
                             config.pki_master_dict['pki_subsystem'].lower())
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
            config.pki_master_dict\
            ['pki_tomcat_webapps_subsystem_webinf_classes_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_webapps_subsystem_path'],
                    "WEB-INF",
                    "classes")
            config.pki_master_dict\
            ['pki_tomcat_webapps_subsystem_webinf_lib_link'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_webapps_subsystem_path'],
                    "WEB-INF",
                    "lib")
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
        # PKI Target (slot substitution) name/value pairs
        config.pki_master_dict['pki_target_cs_cfg'] =\
            os.path.join(
                config.pki_master_dict['pki_subsystem_configuration_path'],
                "CS.cfg")
        config.pki_master_dict['pki_target_registry'] =\
            os.path.join(config.pki_master_dict['pki_subsystem_registry_path'],
                         config.pki_master_dict['pki_instance_id'])
        if config.pki_master_dict['pki_subsystem'] in\
           config.PKI_TOMCAT_SUBSYSTEMS:
            config.pki_master_dict['pki_target_catalina_properties'] =\
                os.path.join(
                    config.pki_master_dict['pki_subsystem_configuration_path'],
                    "catalina.properties")
            config.pki_master_dict['pki_target_servercertnick_conf'] =\
                os.path.join(
                    config.pki_master_dict['pki_subsystem_configuration_path'],
                    "serverCertNick.conf")
            config.pki_master_dict['pki_target_server_xml'] =\
                os.path.join(
                    config.pki_master_dict['pki_subsystem_configuration_path'],
                    "server.xml")
            config.pki_master_dict['pki_target_tomcat_conf'] =\
                config.pki_master_dict['pki_root_prefix'] +\
                "/etc/sysconfig/" +\
                config.pki_master_dict['pki_instance_id']
            config.pki_master_dict['pki_target_index_jsp'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_webapps_root_path'],
                    "index.jsp")
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
            # subystem-specific slot substitution name/value pairs
            if config.pki_master_dict['pki_subsystem'] == "CA":
                config.pki_master_dict['pki_target_proxy_conf'] =\
                    os.path.join(config.pki_master_dict\
                                 ['pki_subsystem_configuration_path'],
                                 "proxy.conf")
                # in-place slot substitution name/value pairs
                config.pki_master_dict['pki_target_profileselect_template'] =\
                    os.path.join(
                        config.pki_master_dict\
                        ['pki_tomcat_webapps_subsystem_path'],
                        "ee",
                        config.pki_master_dict['pki_subsystem'].lower(),
                        "ProfileSelect.template")
        # Slot assignment name/value pairs
        #     NOTE:  Master key == Slots key; Master value ==> Slots value
        config.pki_master_dict['PKI_INSTANCE_ID_SLOT'] =\
            config.pki_master_dict['pki_instance_id']
        config.pki_master_dict['PKI_INSTANCE_INITSCRIPT_SLOT'] =\
            os.path.join(config.pki_master_dict['pki_subsystem_path'],
                         config.pki_master_dict['pki_instance_id'])
        config.pki_master_dict['PKI_LOCKDIR_SLOT'] =\
            os.path.join("/var/lock/pki",
                         config.pki_master_dict['pki_subsystem'].lower())
        config.pki_master_dict['PKI_PIDDIR_SLOT'] =\
            os.path.join("/var/run/pki",
                         config.pki_master_dict['pki_subsystem'].lower())
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
                "agent"
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
            config.pki_master_dict['PKI_CLOSE_AJP_PORT_COMMENT_SLOT'] =\
                "-->"
            config.pki_master_dict['PKI_CLOSE_ENABLE_PROXY_COMMENT_SLOT'] =\
                "-->"
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
            config.pki_master_dict['PKI_FLAVOR_SLOT'] =\
                "pki"
            config.pki_master_dict['PKI_GROUP_SLOT'] =\
                config.pki_master_dict['pki_group']
            config.pki_master_dict['PKI_INSTANCE_PATH_SLOT'] =\
                config.pki_master_dict['pki_subsystem_path']
            config.pki_master_dict['PKI_INSTANCE_ROOT_SLOT'] =\
                config.pki_master_dict['pki_webserver_path']
            config.pki_master_dict['PKI_MACHINE_NAME_SLOT'] =\
                config.pki_master_dict['pki_hostname']
            config.pki_master_dict['PKI_OPEN_AJP_PORT_COMMENT_SLOT'] =\
                "<!--"
            config.pki_master_dict['PKI_OPEN_ENABLE_PROXY_COMMENT_SLOT'] =\
                "<!--"
            config.pki_master_dict\
            ['PKI_OPEN_SEPARATE_PORTS_SERVER_COMMENT_SLOT'] =\
                "<!--"
            config.pki_master_dict\
            ['PKI_OPEN_SEPARATE_PORTS_WEB_COMMENT_SLOT'] =\
                "<!--"
            config.pki_master_dict['PKI_PROXY_SECURE_PORT_SLOT'] =\
                config.pki_master_dict['pki_proxy_https_port']
            config.pki_master_dict['PKI_PROXY_UNSECURE_PORT_SLOT'] =\
                config.pki_master_dict['pki_proxy_http_port']
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
            config.pki_master_dict['PKI_SUBSYSTEM_TYPE_SLOT'] =\
                config.pki_master_dict['pki_subsystem'].lower()
            config.pki_master_dict['PKI_SYSTEMD_SERVICENAME_SLOT'] =\
                "pki-" + config.pki_master_dict['pki_subsystem'].lower() +\
                "d" + "@" + "pki-" +\
                config.pki_master_dict['pki_subsystem'].lower() + ".service"
            config.pki_master_dict['PKI_UNSECURE_PORT_SLOT'] =\
                config.pki_master_dict['pki_http_port']
            config.pki_master_dict['PKI_UNSECURE_PORT_CONNECTOR_NAME_SLOT'] =\
                "Unsecure"
            config.pki_master_dict['PKI_UNSECURE_PORT_SERVER_COMMENT_SLOT'] =\
                "<!-- Shared Ports:  Unsecure Port Connector -->"
            config.pki_master_dict['PKI_USER_SLOT'] =\
                config.pki_master_dict['pki_user']
            config.pki_master_dict['PKI_WEBAPPS_NAME_SLOT'] =\
                "webapps"
            config.pki_master_dict['TOMCAT_CFG_SLOT'] =\
                config.pki_master_dict['pki_target_tomcat_conf']
            config.pki_master_dict['TOMCAT_INSTANCE_COMMON_LIB_SLOT'] =\
                os.path.join(
                    config.pki_master_dict['pki_tomcat_common_lib_path'],
                    "*.jar")
            config.pki_master_dict['TOMCAT_LOG_DIR_SLOT'] =\
                config.pki_master_dict['pki_subsystem_log_path']
            config.pki_master_dict['TOMCAT_PIDFILE_SLOT'] =\
                "/var/run/" + config.pki_master_dict['pki_instance_id'] + ".pid"
            config.pki_master_dict['TOMCAT_SERVER_PORT_SLOT'] =\
                config.pki_master_dict['tomcat_server_port']
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
            "CN=" + config.pki_master_dict['pki_hostname'] + "," +\
            "O=" + config.pki_master_dict['pki_certificate_timestamp']
        config.pki_master_dict['pki_self_signed_serial_number'] = 0
        config.pki_master_dict['pki_self_signed_validity_period'] = 12
        config.pki_master_dict['pki_self_signed_issuer_name'] =\
            "CN=" + config.pki_master_dict['pki_hostname'] + "," +\
            "O=" + config.pki_master_dict['pki_certificate_timestamp']
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
    except OSError as exc:
        config.pki_log.error(log.PKI_OSERROR_1, exc,
                             extra=config.PKI_INDENTATION_LEVEL_2)
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
