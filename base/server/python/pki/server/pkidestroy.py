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

from __future__ import absolute_import
from __future__ import print_function
import logging
import os
import sys
import signal
import subprocess
import traceback

import pki.server.deployment

from pki.server.deployment import pkiconfig as config
from pki.server.deployment.pkiparser import PKIConfigParser
from pki.server.deployment import pkilogging
from pki.server.deployment import pkimessages as log

logger = logging.getLogger(__name__)

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
        help='FORMAT:  ${pki_instance_name}',
        default='pki-tomcat')

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

    parser.optional.add_argument(
        '--force',
        dest='force',
        action='store_true',
        help='force removal of subsystem'
    )

    parser.optional.add_argument(
        '--remove-conf',
        dest='remove_conf',
        action='store_true',
        help='Remove config folder'
    )

    parser.optional.add_argument(
        '--remove-logs',
        dest='remove_logs',
        action='store_true',
        help='Remove logs folder'
    )

    parser.optional.add_argument(
        '--log-file',
        dest='log_file',
        action='store',
        help='Log file')

    args = parser.process_command_line_arguments()

    interactive = False

    while True:

        # -s <subsystem>
        if args.pki_subsystem is None:
            interactive = True
            deployer.subsystem_type = parser.read_text(
                'Subsystem (CA/KRA/OCSP/TKS/TPS/EST)',
                options=['CA', 'KRA', 'OCSP', 'TKS', 'TPS', 'EST'],
                default='CA', case_sensitive=False).upper()
        else:
            deployer.subsystem_type = str(args.pki_subsystem).strip('[\']')

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
        with open(str(args.pki_secdomain_pass_file).strip('[\']'), 'r', encoding='utf-8') as \
                pwd_file:
            config.pki_secdomain_pass = pwd_file.readline().strip('\n')

    # --force
    deployer.force = args.force

    # --remove-conf
    deployer.remove_conf = args.remove_conf

    # --remove-logs
    deployer.remove_logs = args.remove_logs

    instance_name = config.pki_deployed_instance_name
    deployer.instance = pki.server.PKIServerFactory.create(instance_name)

    if not deployer.instance.exists():
        logger.error('No such instance: %s', instance_name)
        sys.exit(1)

    deployer.instance.load()

    subsystem_name = deployer.subsystem_type.lower()
    subsystem = deployer.instance.get_subsystem(subsystem_name)

    if not subsystem:
        logger.error('No %s subsystem in %s instance',
                     deployer.subsystem_type, instance_name)
        sys.exit(1)

    # establish complete path to previously deployed configuration file
    config.user_deployment_cfg = os.path.join(
        subsystem.base_dir,
        "registry",
        deployer.subsystem_type.lower(),
        config.USER_DEPLOYMENT_CONFIGURATION
    )

    if not os.path.exists(config.user_deployment_cfg):
        # if file doesn't exist, we ignore it
        config.user_deployment_cfg = None

    if config.user_deployment_cfg:
        parser.validate(config.user_deployment_cfg)

    parser.init_config(pki_instance_name=config.pki_deployed_instance_name)

    if args.pki_verbosity > 1:
        logger.warning('The -%s option has been deprecated. Use --debug instead.',
                       'v' * args.pki_verbosity)

    # Read the specified PKI configuration file.
    if config.user_deployment_cfg:
        rv = parser.read_pki_configuration_file(config.user_deployment_cfg)
        if rv != 0:
            sys.exit(1)

    # Combine the various sectional dictionaries into a PKI master dictionary
    parser.compose_pki_master_dictionary(config.user_deployment_cfg)

    deployer.init()

    if args.log_file:
        print('Uninstallation log: %s' % args.log_file)

    if args.log_file:
        deployer.init_logger(args.log_file)

    logger.debug(log.PKI_DICTIONARY_MASTER)
    logger.debug(pkilogging.log_format(parser.mdict))

    try:
        deployer.destroy()

    except subprocess.CalledProcessError as e:
        log_error_details()
        print()
        print("Uninstallation failed: Command failed: %s" % ' '.join(e.cmd))
        if e.output:
            print(e.output)
        print()
        sys.exit(1)

    except pki.cli.CLIException as e:
        print()
        print('Uninstallation failed: %s' % str(e))
        print()
        sys.exit(1)

    except Exception as e:  # pylint: disable=broad-except
        log_error_details()
        print()
        print("Uninstallation failed: %s" % e)
        print()
        sys.exit(1)

    print()
    print("Uninstallation complete.")


def log_error_details():
    e_type, e_value, e_stacktrace = sys.exc_info()
    stacktrace_list = traceback.format_list(traceback.extract_tb(e_stacktrace))
    e_stacktrace = "%s: %s\n" % (e_type.__name__, e_value)
    for trace in stacktrace_list:
        e_stacktrace += trace
    logger.error(e_stacktrace)
    del e_type, e_value, e_stacktrace


# PKI Deployment Entry Point
if __name__ == "__main__":
    logging.basicConfig(format='%(levelname)s: %(message)s')
    signal.signal(signal.SIGINT, interrupt_handler)
    main(sys.argv)
