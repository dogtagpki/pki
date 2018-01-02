#!/usr/bin/python -tu
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
from __future__ import absolute_import
from __future__ import print_function
import sys
import signal

if not hasattr(sys, "hexversion") or sys.hexversion < 0x020700f0:
    print("Python version %s.%s.%s is too old." % sys.version_info[:3])
    print("Please upgrade to at least Python 2.7.0.")
    sys.exit(1)
try:
    import os
    import traceback
    import pki
    from pki.server.deployment import pkiconfig as config
    from pki.server.deployment.pkiparser import PKIConfigParser
    from pki.server.deployment import pkilogging
    from pki.server.deployment import pkimessages as log
except ImportError:
    print("""\
There was a problem importing one of the required Python modules. The
error was:

    %s
""" % sys.exc_info()[1], file=sys.stderr)
    sys.exit(1)


deployer = pki.server.deployment.PKIDeployer()


# Handle the Keyboard Interrupt
# pylint: disable=W0613
def interrupt_handler(event, frame):
    print()
    print('\nUninstallation canceled.')
    sys.exit(1)


# PKI Deployment Functions
def main(argv):
    """main entry point"""

    config.pki_deployment_executable = os.path.basename(argv[0])

    # Set the umask
    os.umask(config.PKI_DEPLOYMENT_DEFAULT_UMASK)

    # Read and process command-line arguments.
    parser = PKIConfigParser(
        'PKI Instance Removal',
        log.PKIDESTROY_EPILOG,
        deployer=deployer)

    parser.optional.add_argument(
        '-i',
        dest='pki_deployed_instance_name',
        action='store',
        nargs=1, metavar='<instance>',
        help='FORMAT:  ${pki_instance_name}')

    parser.optional.add_argument(
        '-u',
        dest='pki_secdomain_user',
        action='store',
        nargs=1, metavar='<security domain user>',
        help='security domain user')

    parser.optional.add_argument(
        '-W',
        dest='pki_secdomain_pass_file',
        action='store',
        nargs=1, metavar='<security domain password file>',
        help='security domain password file path')

    args = parser.process_command_line_arguments()

    interactive = False

    # Only run this program as "root".
    if not os.geteuid() == 0:
        sys.exit("'%s' must be run as root!" % argv[0])

    while True:

        # -s <subsystem>
        if args.pki_subsystem is None:
            interactive = True
            deployer.subsystem_name = parser.read_text(
                'Subsystem (CA/KRA/OCSP/TKS/TPS)',
                options=['CA', 'KRA', 'OCSP', 'TKS', 'TPS'],
                default='CA', case_sensitive=False).upper()
        else:
            deployer.subsystem_name = str(args.pki_subsystem).strip('[\']')

        # -i <instance name>
        if args.pki_deployed_instance_name is None:
            interactive = True
            config.pki_deployed_instance_name = \
                parser.read_text('Instance', default='pki-tomcat')
        else:
            config.pki_deployed_instance_name = \
                str(args.pki_deployed_instance_name).strip('[\']')

        if interactive:
            print()
            parser.indent = 0

            begin = parser.read_text(
                'Begin uninstallation (Yes/No/Quit)',
                options=['Yes', 'Y', 'No', 'N', 'Quit', 'Q'],
                sign='?', allow_empty=False, case_sensitive=False).lower()

            print()

            if begin == 'q' or begin == 'quit':
                print("Uninstallation canceled.")
                sys.exit(0)

            elif begin == 'y' or begin == 'yes':
                break

        else:
            break

    #    '-u'
    if args.pki_secdomain_user:
        config.pki_secdomain_user = str(args.pki_secdomain_user).strip('[\']')

    #    '-W' password file
    if args.pki_secdomain_pass_file:
        with open(str(args.pki_secdomain_pass_file).strip('[\']'), 'r') as \
                pwd_file:
            config.pki_secdomain_pass = pwd_file.readline().strip('\n')

    # verify that previously deployed instance exists
    deployed_pki_instance_path = \
        config.pki_root_prefix + config.PKI_DEPLOYMENT_BASE_ROOT + "/" + \
        config.pki_deployed_instance_name
    if not os.path.exists(deployed_pki_instance_path):
        print("ERROR:  " + log.PKI_INSTANCE_DOES_NOT_EXIST_1 %
              deployed_pki_instance_path)
        print()
        parser.arg_parser.exit(-1)

    # verify that previously deployed subsystem for this instance exists
    deployed_pki_subsystem_path = \
        deployed_pki_instance_path + "/" + deployer.subsystem_name.lower()
    if not os.path.exists(deployed_pki_subsystem_path):
        print("ERROR:  " + log.PKI_SUBSYSTEM_DOES_NOT_EXIST_2 %
              (deployer.subsystem_name, deployed_pki_instance_path))
        print()
        parser.arg_parser.exit(-1)

    config.default_deployment_cfg = \
        config.PKI_DEPLOYMENT_DEFAULT_CONFIGURATION_FILE

    # establish complete path to previously deployed configuration file
    config.user_deployment_cfg =\
        deployed_pki_subsystem_path + "/" +\
        "registry" + "/" +\
        deployer.subsystem_name.lower() + "/" +\
        config.USER_DEPLOYMENT_CONFIGURATION

    parser.validate()
    parser.init_config()

    # Enable 'pkidestroy' logging.
    config.pki_log_dir = \
        config.pki_root_prefix + config.PKI_DEPLOYMENT_LOG_ROOT
    config.pki_log_name = "pki" + "-" +\
                          deployer.subsystem_name.lower() +\
                          "-" + "destroy" + "." +\
                          deployer.log_timestamp + "." + "log"
    print('Log file: %s/%s' % (config.pki_log_dir, config.pki_log_name))

    rv = pkilogging.enable_pki_logger(config.pki_log_dir,
                                      config.pki_log_name,
                                      config.pki_log_level,
                                      config.pki_console_log_level,
                                      "pkidestroy")
    if rv != OSError:
        config.pki_log = rv
    else:
        print(log.PKI_UNABLE_TO_CREATE_LOG_DIRECTORY_1 % config.pki_log_dir)
        sys.exit(1)

    # Read the specified PKI configuration file.
    rv = parser.read_pki_configuration_file()
    if rv != 0:
        config.pki_log.error(log.PKI_UNABLE_TO_PARSE_1, rv,
                             extra=config.PKI_INDENTATION_LEVEL_0)
        sys.exit(1)

    # Combine the various sectional dictionaries into a PKI master dictionary
    parser.compose_pki_master_dictionary()
    parser.mdict['pki_destroy_log'] = \
        config.pki_log_dir + "/" + config.pki_log_name
    config.pki_log.debug(log.PKI_DICTIONARY_MASTER,
                         extra=config.PKI_INDENTATION_LEVEL_0)
    config.pki_log.debug(pkilogging.log_format(parser.mdict),
                         extra=config.PKI_INDENTATION_LEVEL_0)

    print("Uninstalling " + deployer.subsystem_name + " from " +
          deployed_pki_instance_path + ".")

    # Process the various "scriptlets" to remove the specified PKI subsystem.
    pki_subsystem_scriptlets = parser.mdict['destroy_scriplets'].split()
    deployer.init(parser)

    try:
        for scriptlet_name in pki_subsystem_scriptlets:

            scriptlet_module = __import__(
                "pki.server.deployment.scriptlets." + scriptlet_name,
                fromlist=[scriptlet_name])

            scriptlet = scriptlet_module.PkiScriptlet()

            scriptlet.destroy(deployer)

    # pylint: disable=W0703
    except Exception as e:
        log_error_details()
        print()
        print("Uninstallation failed: %s" % e)
        print()
        sys.exit(1)

    print()
    print("Uninstallation complete.")


def log_error_details():
    e_type, e_value, e_stacktrace = sys.exc_info()
    config.pki_log.debug(
        "Error Type: %s", e_type.__name__, extra=config.PKI_INDENTATION_LEVEL_2)
    config.pki_log.debug(
        "Error Message: %s", str(e_value), extra=config.PKI_INDENTATION_LEVEL_2)
    stacktrace_list = traceback.format_list(traceback.extract_tb(e_stacktrace))
    e_stacktrace = ""
    for l in stacktrace_list:
        e_stacktrace += l
    config.pki_log.debug(e_stacktrace, extra=config.PKI_INDENTATION_LEVEL_2)
    del e_type, e_value, e_stacktrace


# PKI Deployment Entry Point
if __name__ == "__main__":
    signal.signal(signal.SIGINT, interrupt_handler)
    main(sys.argv)
