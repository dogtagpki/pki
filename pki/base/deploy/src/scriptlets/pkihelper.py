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
# Copyright (C) 2011 Red Hat, Inc.
# All rights reserved.
#

# System Imports
import ConfigParser
import argparse
import logging
import os


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
                 epilog=config.PKI_DEPLOYMENT_VERBOSITY)
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
    if not args.pkideployment_cfg is None:
        config.pkideployment_cfg = str(args.pkideployment_cfg).strip('[\']')
    if not os.path.exists(config.pkideployment_cfg) or\
       not os.path.isfile(config.pkideployment_cfg):
        print "ERROR:  " +\
              log.PKI_FILE_MISSING_OR_NOT_A_FILE_1 %\
              config.pkideployment_cfg
        print
        parser.print_help()
        parser.exit(-1);
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


def read_pki_configuration_file():
    "Read configuration file sections into dictionaries"
    rv = 0
    try:
        parser = ConfigParser.ConfigParser()
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


def create_pki_master_dictionary():
    "Create a single master PKI dictionary from the sectional dictionaries"
    config.pki_master_dict = dict()
    config.pki_master_dict.update(config.pki_common_dict)
    config.pki_master_dict.update(config.pki_web_server_dict)
    config.pki_master_dict.update(config.pki_subsystem_dict)
    config.pki_master_dict.update(__name__="PKI Master Dictionary")
    return

