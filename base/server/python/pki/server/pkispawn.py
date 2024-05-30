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
import fileinput
import ldap
import logging
import os
import requests
import sys
import signal
import subprocess
import traceback

import pki
import pki.server

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
    print('\nInstallation canceled.')
    sys.exit(1)


def verify_ds_configuration():
    try:
        deployer.ds_init()
        deployer.ds_connect()
        deployer.ds_bind()
        deployer.ds_search()
    finally:
        deployer.ds_close()


def base_dn_exists():
    try:
        deployer.ds_connect()
        deployer.ds_bind()
        deployer.ds_search()

        try:
            results = deployer.ds_search(deployer.mdict['pki_ds_base_dn'])

            if results is None or len(results) == 0:
                return False

        except ldap.NO_SUCH_OBJECT:
            return False

    finally:
        deployer.ds_close()

    return True


# PKI Deployment Functions
def main(argv):
    """main entry point"""

    config.pki_deployment_executable = os.path.basename(argv[0])

    # Set the umask
    os.umask(config.PKI_DEPLOYMENT_DEFAULT_UMASK)

    # Read and process command-line arguments.
    parser = PKIConfigParser(
        'PKI Instance Installation and Configuration',
        log.PKISPAWN_EPILOG,
        deployer=deployer)

    parser.optional.add_argument(
        '--conf',
        dest='conf_dir',
        action='store',
        help='Config folder')

    parser.optional.add_argument(
        '--logs',
        dest='logs_dir',
        action='store',
        help='Logs folder')

    parser.optional.add_argument(
        '-f',
        dest='user_deployment_cfg', action='store',
        nargs=1, metavar='<file>',
        help='configuration filename '
        '(MUST specify complete path)')

    parser.optional.add_argument(
        '-D',
        dest='params', action='append',
        metavar='<name>=<value>',
        help='configuration parameter name and value')

    parser.optional.add_argument(
        '--precheck',
        dest='precheck', action='store_true',
        help='Execute pre-checks and exit')

    parser.optional.add_argument(
        '--skip-configuration',
        dest='skip_configuration',
        action='store_true',
        help='skip configuration step')

    parser.optional.add_argument(
        '--skip-installation',
        dest='skip_installation',
        action='store_true',
        help='skip installation step')

    parser.optional.add_argument(
        '--enforce-hostname',
        dest='enforce_hostname',
        action='store_true',
        help='enforce strict hostname/FQDN checks')

    parser.optional.add_argument(
        '--with-maven-deps',
        dest='with_maven_deps',
        action='store_true',
        help='Install Maven dependencies')

    parser.optional.add_argument(
        '--log-file',
        dest='log_file',
        action='store',
        help='Log file')

    args = parser.process_command_line_arguments()

    config.default_deployment_cfg = \
        config.PKI_DEPLOYMENT_DEFAULT_CONFIGURATION_FILE

    # -f <user deployment config>
    if args.user_deployment_cfg is not None:
        config.user_deployment_cfg = str(
            args.user_deployment_cfg).strip('[\']')

    parser.validate(config.user_deployment_cfg)

    # Currently the only logic in deployer's validation is the
    # hostname check; at some point this might need to be updated.
    if args.enforce_hostname:
        deployer.validate()

    interactive = False

    if config.user_deployment_cfg is None:
        interactive = True
        parser.indent = 0
        print(log.PKISPAWN_INTERACTIVE_INSTALLATION)
    else:
        validate_user_deployment_cfg(config.user_deployment_cfg)

    # Only run this program as "root".
    if not os.geteuid() == 0:
        sys.exit("'%s' must be run as root!" % argv[0])

    while True:
        # -s <subsystem>
        if args.pki_subsystem is None:
            interactive = True
            parser.indent = 0

            deployer.subsystem_type = parser.read_text(
                'Subsystem (CA/KRA/OCSP/TKS/TPS)',
                options=['CA', 'KRA', 'OCSP', 'TKS', 'TPS'],
                default='CA', case_sensitive=False).upper()
            print()
        else:
            deployer.subsystem_type = str(args.pki_subsystem).strip('[\']')

        parser.init_config()

        if config.user_deployment_cfg is None:
            if args.precheck:
                sys.exit(
                    'precheck mode is only valid for non-interactive installs')
            interactive = True
            parser.indent = 2

            print("Tomcat:")
            instance_name = parser.read_text(
                'Instance', 'DEFAULT', 'pki_instance_name')
            existing_data = parser.read_existing_deployment_data(instance_name)

            set_port(parser,
                     'pki_http_port',
                     'HTTP port',
                     existing_data)

            set_port(parser,
                     'pki_https_port',
                     'Secure HTTP port',
                     existing_data)

            set_port(parser,
                     'pki_ajp_port',
                     'AJP port',
                     existing_data)

            set_port(parser,
                     'pki_tomcat_server_port',
                     'Management port',
                     existing_data)

            print()

            print("Administrator:")
            parser.read_text('Username', deployer.subsystem_type, 'pki_admin_uid')

            admin_password = parser.read_password(
                'Password', deployer.subsystem_type, 'pki_admin_password',
                verifyMessage='Verify password')

            deployer.set_property('pki_backup_password', admin_password)
            deployer.set_property('pki_client_database_password', admin_password)
            deployer.set_property('pki_client_pkcs12_password', admin_password)

            if parser.mdict['pki_import_admin_cert'] == 'True':
                import_cert = 'Y'
            else:
                import_cert = 'N'

            import_cert = parser.read_text(
                'Import certificate (Yes/No)',
                default=import_cert, options=['Yes', 'Y', 'No', 'N'],
                sign='?', case_sensitive=False).lower()

            if import_cert == 'y' or import_cert == 'yes':
                deployer.set_property('pki_import_admin_cert', 'True')
                parser.read_text('Import certificate from',
                                 deployer.subsystem_type,
                                 'pki_admin_cert_file')
            else:
                deployer.set_property('pki_import_admin_cert', 'False')

                parser.read_text('Export certificate to',
                                 deployer.subsystem_type,
                                 'pki_client_admin_cert')

            # if parser.mdict['pki_hsm_enable'] == 'True':
            #     use_hsm = 'Y'
            # else:
            #     use_hsm = 'N'

            # use_hsm = parser.read_text(
            #     'Using hardware security module (HSM) (Yes/No)',
            #     default=use_hsm, options=['Yes', 'Y', 'No', 'N'],
            #     sign='?', case_sensitive=False).lower()

            # if use_hsm == 'y' or use_hsm == 'yes':
            #     # XXX:  Suppress interactive HSM installation
            #     print "Interactive HSM installation is currently unsupported."
            #     sys.exit(0)

            # TBD:  Interactive HSM installation
            # deployer.set_property('pki_hsm_enable', 'True')
            # modulename = parser.read_text(
            #     'HSM Module Name (e. g. - nethsm)', allow_empty=False)
            # deployer.set_property('pki_hsm_modulename', modulename)
            # libfile = parser.read_text(
            #     'HSM Lib File ' +
            #     '(e. g. - /opt/nfast/toolkits/pkcs11/libcknfast.so)',
            #     allow_empty=False)
            # deployer.set_property('pki_hsm_libfile', libfile)
            print()

            print("Directory Server:")
            while True:
                parser.read_text('Hostname',
                                 deployer.subsystem_type,
                                 'pki_ds_hostname')

                if parser.mdict['pki_ds_secure_connection'] == 'True':
                    secure = 'Y'
                else:
                    secure = 'N'

                secure = parser.read_text(
                    'Use a secure LDAPS connection (Yes/No/Quit)',
                    default=secure,
                    options=['Yes', 'Y', 'No', 'N', 'Quit', 'Q'],
                    sign='?', case_sensitive=False).lower()

                if secure == 'q' or secure == 'quit':
                    print("Installation canceled.")
                    sys.exit(0)

                if secure == 'y' or secure == 'yes':
                    # Set secure DS connection to true
                    deployer.set_property('pki_ds_secure_connection', 'True')
                    # Prompt for secure 'ldaps' port
                    parser.read_text('Secure LDAPS Port',
                                     deployer.subsystem_type,
                                     'pki_ds_ldaps_port')
                    # Specify complete path to a directory server
                    # CA certificate pem file
                    pem_file = parser.read_text(
                        'Directory Server CA certificate pem file',
                        allow_empty=False)
                    deployer.set_property('pki_ds_secure_connection_ca_pem_file', pem_file)
                else:
                    parser.read_text('LDAP Port',
                                     deployer.subsystem_type,
                                     'pki_ds_ldap_port')

                parser.read_text('Bind DN',
                                 deployer.subsystem_type,
                                 'pki_ds_bind_dn')
                parser.read_password('Password',
                                     deployer.subsystem_type,
                                     'pki_ds_password')

                try:
                    verify_ds_configuration()

                except ldap.LDAPError as e:
                    parser.print_text('ERROR: ' + e.args[0]['desc'])

                    # Force deployer to re-initialize the DS connection string
                    # next time, as we're in interactive mode here.
                    deployer.ds_url = None
                    continue

                parser.read_text('Base DN',
                                 deployer.subsystem_type,
                                 'pki_ds_base_dn')
                try:
                    if not base_dn_exists():
                        break

                except ldap.LDAPError as e:
                    parser.print_text('ERROR: ' + e.args[0]['desc'])
                    continue

                remove = parser.read_text(
                    'Base DN already exists. Overwrite (Yes/No/Quit)',
                    options=['Yes', 'Y', 'No', 'N', 'Quit', 'Q'],
                    sign='?', allow_empty=False, case_sensitive=False).lower()

                if remove == 'q' or remove == 'quit':
                    print("Installation canceled.")
                    sys.exit(0)

                if remove == 'y' or remove == 'yes':
                    break

            print()

            print("Security Domain:")

            if deployer.subsystem_type == "CA":
                parser.read_text('Name',
                                 deployer.subsystem_type,
                                 'pki_security_domain_name')

            else:
                while True:
                    conf_dir = os.path.join(pki.server.PKIServer.CONFIG_DIR, instance_name)
                    nssdb_dir = os.path.join(conf_dir, 'alias')
                    ca_cert = os.path.join(nssdb_dir, "ca.crt")
                    if not os.path.exists(ca_cert):
                        parser.read_text('Security Domain CA Root Certificate',
                                         deployer.subsystem_type,
                                         'pki_cert_chain_path')

                    parser.read_text('Hostname',
                                     deployer.subsystem_type,
                                     'pki_security_domain_hostname')

                    parser.read_text('Secure HTTP port',
                                     deployer.subsystem_type,
                                     'pki_security_domain_https_port')

                    try:
                        deployer.sd_connect()
                        deployer.domain_info = deployer.get_domain_info()
                        parser.print_text('Name: ' + deployer.domain_info.id)
                        deployer.set_property('pki_security_domain_name', deployer.domain_info.id)
                        break
                    except pki.RETRYABLE_EXCEPTIONS as e:
                        parser.print_text('ERROR: ' + str(e))

                while True:
                    parser.read_text('Username',
                                     deployer.subsystem_type,
                                     'pki_security_domain_user')
                    parser.read_password('Password',
                                         deployer.subsystem_type,
                                         'pki_security_domain_password')

                    try:
                        deployer.sd_login()
                        deployer.sd_logout()
                        break
                    except requests.exceptions.HTTPError as e:
                        parser.print_text('ERROR: ' + str(e))

            print()

            if deployer.subsystem_type == "TPS":
                print("External Servers:")

                while True:
                    parser.read_text('CA URL',
                                     deployer.subsystem_type,
                                     'pki_ca_uri')
                    try:
                        status = parser.get_server_status('ca', 'pki_ca_uri')
                        if status == 'running':
                            break
                        parser.print_text('ERROR: CA is not running')
                    except pki.RETRYABLE_EXCEPTIONS as e:
                        parser.print_text('ERROR: ' + str(e))

                while True:
                    parser.read_text('TKS URL',
                                     deployer.subsystem_type,
                                     'pki_tks_uri')
                    try:
                        status = parser.get_server_status('tks', 'pki_tks_uri')
                        if status == 'running':
                            break
                        parser.print_text('ERROR: TKS is not running')
                    except pki.RETRYABLE_EXCEPTIONS as e:
                        parser.print_text('ERROR: ' + str(e))

                while True:
                    keygen = parser.read_text(
                        'Enable server side key generation (Yes/No)',
                        options=['Yes', 'Y', 'No', 'N'], default='N',
                        sign='?', case_sensitive=False).lower()

                    if keygen == 'y' or keygen == 'yes':
                        deployer.set_property('pki_enable_server_side_keygen', 'True')

                        parser.read_text('KRA URL',
                                         deployer.subsystem_type,
                                         'pki_kra_uri')
                        try:
                            status = parser.get_server_status(
                                'kra', 'pki_kra_uri')
                            if status == 'running':
                                break
                            parser.print_text('ERROR: KRA is not running')
                        except pki.RETRYABLE_EXCEPTIONS as e:
                            parser.print_text('ERROR: ' + str(e))
                    else:
                        deployer.set_property('pki_enable_server_side_keygen', 'False')
                        break

                print()

                print("Authentication Database:")

                while True:
                    parser.read_text('Hostname',
                                     deployer.subsystem_type,
                                     'pki_authdb_hostname')
                    parser.read_text('Port',
                                     deployer.subsystem_type,
                                     'pki_authdb_port')
                    basedn = parser.read_text('Base DN', allow_empty=False)
                    deployer.set_property('pki_authdb_basedn', basedn)

                    try:
                        parser.authdb_connect()
                        if parser.authdb_base_dn_exists():
                            break
                        else:
                            parser.print_text('ERROR: base DN does not exist')

                    except ldap.LDAPError as e:
                        parser.print_text('ERROR: ' + e.args[0]['desc'])

                print()

        if interactive:
            parser.indent = 0

            begin = parser.read_text(
                'Begin installation (Yes/No/Quit)',
                options=['Yes', 'Y', 'No', 'N', 'Quit', 'Q'],
                sign='?', allow_empty=False, case_sensitive=False).lower()
            print()

            if begin == 'q' or begin == 'quit':
                print("Installation canceled.")
                sys.exit(0)

            if begin == 'y' or begin == 'yes':
                break

        else:
            break

    if args.pki_verbosity > 1:
        logger.warning('The -%s option has been deprecated. Use --debug instead.',
                       'v' * args.pki_verbosity)

    # Read the specified PKI configuration file.
    rv = parser.read_pki_configuration_file(config.user_deployment_cfg)
    if rv != 0:
        sys.exit(1)

    # --skip-configuration
    if args.skip_configuration:
        deployer.set_property('pki_skip_configuration', 'True')

    # --skip-installation
    if args.skip_installation:
        deployer.set_property('pki_skip_installation', 'True')

    if args.params:
        for param in args.params:
            i = param.index('=')
            name = param[0:i]
            value = param[i + 1:]
            deployer.set_property(name, value)

    create_master_dictionary(parser)
    deployer.with_maven_deps = args.with_maven_deps
    deployer.init()

    instance_name = deployer.mdict['pki_instance_name']
    deployer.instance = pki.server.PKIServerFactory.create(instance_name)
    deployer.instance.user = deployer.mdict['pki_user']
    deployer.instance.group = deployer.mdict['pki_group']

    if args.conf_dir:
        # Use --conf <dir> if specified.
        conf_dir = args.conf_dir

    else:
        # Otherwise, use pki_instance_configuration_path param (default: None).
        # This param is used by IPA to support containers. See:
        # https://github.com/freeipa/freeipa/blob/master/install/share/ipaca_default.ini
        conf_dir = deployer.mdict.get('pki_instance_configuration_path')

    if conf_dir:
        # If conf_dir is specified, the config files will be stored in the
        # specified folder, and the <instance>/conf will link to that folder.
        # Otherwise, config files will be stored in <instance>/conf directly.
        deployer.instance.actual_conf_dir = conf_dir

    if args.logs_dir:
        deployer.instance.actual_logs_dir = args.logs_dir

    deployer.instance.load()

    if args.log_file:
        print('Installation log: %s' % args.log_file)

    if args.log_file:
        deployer.init_logger(args.log_file)

    if not interactive and \
            not config.str2bool(parser.mdict['pki_skip_configuration']):
        check_ds()
        if config.str2bool(parser.mdict['pki_security_domain_setup']):
            check_security_domain()

    if args.precheck:
        print('pre-checks completed successfully.')
        sys.exit(0)

    try:
        deployer.spawn()

    except subprocess.CalledProcessError as e:
        log_error_details()
        print()
        print("Installation failed: Command failed: %s" % ' '.join(e.cmd))
        if e.output:
            print(e.output)

        if args.log_file:
            print()
            print('Please check pkispawn logs in %s' % args.log_file)

        sys.exit(1)

    except requests.HTTPError as e:
        r = e.response
        print()

        print('Installation failed:')
        if r.headers['content-type'] == 'application/json':
            data = r.json()
            print('%s: %s' % (data['ClassName'], data['Message']))
        else:
            print(r.text)

        print()

        subsystem_logs_dir = os.path.join(
            deployer.instance.logs_dir,
            deployer.mdict['pki_subsystem_type'])

        print('Please check the %s logs in %s.' %
              (deployer.subsystem_type, subsystem_logs_dir))

        sys.exit(1)

    except Exception as e:  # pylint: disable=broad-except
        log_error_details()
        print()
        print("Installation failed: %s" % e)
        print()
        sys.exit(1)

    if config.str2bool(deployer.mdict['pki_registry_enable']):

        # Store user config and installation manifest into
        # /etc/sysconfig/pki/tomcat/<instance>/<subsystem>
        deployer.store_config()
        deployer.store_manifest()

    external = deployer.configuration_file.external
    standalone = deployer.configuration_file.standalone
    step_one = deployer.configuration_file.external_step_one
    skip_configuration = deployer.configuration_file.skip_configuration

    if skip_configuration:
        print_skip_configuration_information(parser.mdict, deployer.instance)

    elif (external or standalone) and step_one:
        if deployer.subsystem_type == 'CA':
            print_external_ca_step_one_information(parser.mdict, deployer.instance)

        elif deployer.subsystem_type == 'KRA':
            print_kra_step_one_information(parser.mdict, deployer.instance)

        elif deployer.subsystem_type == 'OCSP':
            print_ocsp_step_one_information(parser.mdict, deployer.instance)

        elif deployer.subsystem_type == 'TKS':
            print_tks_step_one_information(parser.mdict, deployer.instance)

        elif deployer.subsystem_type == 'TPS':
            print_tps_step_one_information(parser.mdict, deployer.instance)

    else:
        print_final_install_information(parser.mdict, deployer.instance)


def validate_user_deployment_cfg(user_deployment_cfg):
    '''
    Validate section headings in user configuration file.
    '''

    for line in fileinput.FileInput(user_deployment_cfg):
        line = line.strip()
        if not line.startswith('['):
            continue
        if line not in ['[DEFAULT]', '[Tomcat]', '[CA]', '[KRA]', '[OCSP]', '[TKS]', '[TPS]']:
            raise Exception('Invalid deployment configuration section: %s' % line)


def create_master_dictionary(parser):

    # Combine the various sectional dictionaries into a PKI master dictionary
    parser.compose_pki_master_dictionary(config.user_deployment_cfg)

    logger.debug(log.PKI_DICTIONARY_MASTER)
    logger.debug(pkilogging.log_format(parser.mdict))


def check_security_domain():

    # If the subsystem being installed is joining an existing security domain,
    # or it is a subordinate CA (either joining the security domain or creating
    # a new one), connect to and authenticate against the security domain.

    if deployer.mdict['pki_security_domain_type'] == 'existing' \
            or config.str2bool(deployer.mdict['pki_subordinate']):

        if 'pki_security_domain_password' not in deployer.mdict or \
                not len(deployer.mdict['pki_security_domain_password']):
            raise Exception('Missing security domain password')

        deployer.sd_connect()

        deployer.domain_info = deployer.get_domain_info()
        deployer.set_property('pki_security_domain_name', deployer.domain_info.id)

        logger.info('Logging into security domain %s', deployer.domain_info.id)

        deployer.sd_login()


def check_ds():
    try:
        # Verify existence of Directory Server Password
        if 'pki_ds_password' not in deployer.mdict or \
                not len(deployer.mdict['pki_ds_password']):
            logger.error(
                log.PKIHELPER_UNDEFINED_CONFIGURATION_FILE_ENTRY_2,
                "pki_ds_password",
                deployer.mdict['pki_user_deployment_cfg'])
            sys.exit(1)

        if not config.str2bool(deployer.mdict['pki_skip_ds_verify']):
            verify_ds_configuration()

            if base_dn_exists() and not \
                    config.str2bool(deployer.mdict['pki_ds_remove_data']):
                print('ERROR:  Base DN already exists.')
                sys.exit(1)

    except ldap.LDAPError:
        logger.error('Unable to access LDAP server: %s', deployer.ds_url.geturl())
        raise


def set_port(parser, tag, prompt, existing_data):
    if tag in existing_data:
        deployer.set_property(tag, existing_data[tag])
    else:
        parser.read_text(prompt, deployer.subsystem_type, tag)


def print_external_ca_step_one_information(mdict, instance):

    print(log.PKI_SPAWN_INFORMATION_HEADER)
    print("      The %s subsystem of the '%s' instance is still incomplete." %
          (deployer.subsystem_type, instance.name))
    print()
    print("      NSS database: %s" % instance.nssdb_dir)
    print()

    signing_csr = mdict['pki_ca_signing_csr_path']

    if signing_csr:
        print("      A CSR for the CA signing certificate has been generated in:")
        print("            %s" % mdict['pki_ca_signing_csr_path'])
    else:
        print("      No CSR has been generated for CA signing certificate.")

    print(log.PKI_RUN_INSTALLATION_STEP_TWO)
    print(log.PKI_SPAWN_INFORMATION_FOOTER)


def print_kra_step_one_information(mdict, instance):

    print(log.PKI_SPAWN_INFORMATION_HEADER)
    print("      The %s subsystem of the '%s' instance is still incomplete." %
          (deployer.subsystem_type, instance.name))
    print()
    print("      NSS database: %s" % instance.nssdb_dir)
    print()

    storage_csr = mdict['pki_storage_csr_path']
    transport_csr = mdict['pki_transport_csr_path']
    subsystem_csr = mdict['pki_subsystem_csr_path']
    sslserver_csr = mdict['pki_sslserver_csr_path']
    audit_csr = mdict['pki_audit_signing_csr_path']
    admin_csr = mdict['pki_admin_csr_path']

    if storage_csr or transport_csr or subsystem_csr or sslserver_csr \
            or audit_csr or admin_csr:
        print("      The CSRs for KRA certificates have been generated in:")
    else:
        print("      No CSRs have been generated for KRA certificates.")

    if storage_csr:
        print("          storage:       %s" % storage_csr)
    if transport_csr:
        print("          transport:     %s" % transport_csr)
    if subsystem_csr:
        print("          subsystem:     %s" % subsystem_csr)
    if sslserver_csr:
        print("          SSL server:    %s" % sslserver_csr)
    if audit_csr:
        print("          audit signing: %s" % audit_csr)
    if admin_csr:
        print("          admin:         %s" % admin_csr)

    print(log.PKI_RUN_INSTALLATION_STEP_TWO)
    print(log.PKI_SPAWN_INFORMATION_FOOTER)


def print_ocsp_step_one_information(mdict, instance):

    print(log.PKI_SPAWN_INFORMATION_HEADER)
    print("      The %s subsystem of the '%s' instance is still incomplete." %
          (deployer.subsystem_type, instance.name))
    print()
    print("      NSS database: %s" % instance.nssdb_dir)
    print()

    signing_csr = mdict['pki_ocsp_signing_csr_path']
    subsystem_csr = mdict['pki_subsystem_csr_path']
    sslserver_csr = mdict['pki_sslserver_csr_path']
    audit_csr = mdict['pki_audit_signing_csr_path']
    admin_csr = mdict['pki_admin_csr_path']

    if signing_csr or subsystem_csr or sslserver_csr or audit_csr or admin_csr:
        print("      The CSRs for OCSP certificates have been generated in:")
    else:
        print("      No CSRs have been generated for OCSP certificates.")

    if signing_csr:
        print("          OCSP signing:  %s" % signing_csr)
    if subsystem_csr:
        print("          subsystem:     %s" % subsystem_csr)
    if sslserver_csr:
        print("          SSL server:    %s" % sslserver_csr)
    if audit_csr:
        print("          audit signing: %s" % audit_csr)
    if admin_csr:
        print("          admin:         %s" % admin_csr)

    print(log.PKI_RUN_INSTALLATION_STEP_TWO)
    print(log.PKI_SPAWN_INFORMATION_FOOTER)


def print_tks_step_one_information(mdict, instance):

    print(log.PKI_SPAWN_INFORMATION_HEADER)
    print("      The %s subsystem of the '%s' instance is still incomplete." %
          (deployer.subsystem_type, instance.name))
    print()
    print("      NSS database: %s" % instance.nssdb_dir)
    print()

    subsystem_csr = mdict['pki_subsystem_csr_path']
    sslserver_csr = mdict['pki_sslserver_csr_path']
    audit_csr = mdict['pki_audit_signing_csr_path']
    admin_csr = mdict['pki_admin_csr_path']

    if subsystem_csr or sslserver_csr or audit_csr or admin_csr:
        print("      The CSRs for TKS certificates have been generated in:")
    else:
        print("      No CSRs have been generated for TKS certificates.")

    if subsystem_csr:
        print("          subsystem:     %s" % subsystem_csr)
    if sslserver_csr:
        print("          SSL server:    %s" % sslserver_csr)
    if audit_csr:
        print("          audit signing: %s" % audit_csr)
    if admin_csr:
        print("          admin:         %s" % admin_csr)

    print(log.PKI_RUN_INSTALLATION_STEP_TWO)
    print(log.PKI_SPAWN_INFORMATION_FOOTER)


def print_tps_step_one_information(mdict, instance):

    print(log.PKI_SPAWN_INFORMATION_HEADER)
    print("      The %s subsystem of the '%s' instance is still incomplete." %
          (deployer.subsystem_type, instance.name))
    print()
    print("      NSS database: %s" % instance.nssdb_dir)
    print()

    subsystem_csr = mdict['pki_subsystem_csr_path']
    sslserver_csr = mdict['pki_sslserver_csr_path']
    audit_csr = mdict['pki_audit_signing_csr_path']
    admin_csr = mdict['pki_admin_csr_path']

    if subsystem_csr or sslserver_csr or audit_csr or admin_csr:
        print("      The CSRs for TPS certificates have been generated in:")
    else:
        print("      No CSRs have been generated for TpS certificates.")

    if subsystem_csr:
        print("          subsystem:     %s" % subsystem_csr)
    if sslserver_csr:
        print("          SSL server:    %s" % sslserver_csr)
    if audit_csr:
        print("          audit signing: %s" % audit_csr)
    if admin_csr:
        print("          admin:         %s" % admin_csr)

    print(log.PKI_RUN_INSTALLATION_STEP_TWO)
    print(log.PKI_SPAWN_INFORMATION_FOOTER)


def print_skip_configuration_information(mdict, instance):

    print(log.PKI_SPAWN_INFORMATION_HEADER)
    print("      The %s subsystem of the '%s' instance\n"
          "      must still be configured!" %
          (deployer.subsystem_type, instance.name))

    if config.str2bool(mdict['pki_systemd_service_create']):
        print(log.PKI_CHECK_STATUS_MESSAGE % instance.name)
        print(log.PKI_INSTANCE_RESTART_MESSAGE % instance.name)

    print(log.PKI_ACCESS_URL % (mdict['pki_hostname'],
                                mdict['pki_https_port'],
                                deployer.subsystem_type.lower()))
    if not config.str2bool(mdict['pki_enable_on_system_boot']):
        print(log.PKI_SYSTEM_BOOT_STATUS_MESSAGE % "disabled")
    else:
        print(log.PKI_SYSTEM_BOOT_STATUS_MESSAGE % "enabled")
    print(log.PKI_SPAWN_INFORMATION_FOOTER)


def print_final_install_information(mdict, instance):

    print(log.PKI_SPAWN_INFORMATION_HEADER)

    if config.str2bool(deployer.mdict['pki_admin_setup']):

        print("      Administrator's username:             %s" %
              mdict['pki_admin_uid'])

        if os.path.isfile(mdict['pki_client_admin_cert_p12']):
            print("      Administrator's PKCS #12 file:\n            %s" %
                  mdict['pki_client_admin_cert_p12'])

        if not config.str2bool(mdict['pki_client_database_purge']) and \
                not config.str2bool(mdict['pki_clone']):
            print()
            print("      Administrator's certificate nickname:\n            %s"
                  % mdict['pki_admin_nickname'])
            print("      Administrator's certificate database:\n            %s"
                  % mdict['pki_client_database_dir'])

    if config.str2bool(mdict['pki_clone']):
        print()
        print("      This %s subsystem of the '%s' instance\n"
              "      is a clone." %
              (deployer.subsystem_type, instance.name))

    if pki.FIPS.is_enabled():
        print()
        print("      This %s subsystem of the '%s' instance\n"
              "      has FIPS mode enabled on this operating system." %
              (deployer.subsystem_type, instance.name))
        print()
        print("      REMINDER:  Don't forget to update the appropriate FIPS\n"
              "                 algorithms in server.xml in the '%s' instance."
              % instance.name)

    if config.str2bool(mdict['pki_systemd_service_create']):
        print(log.PKI_CHECK_STATUS_MESSAGE % instance.name)
        print(log.PKI_INSTANCE_RESTART_MESSAGE % instance.name)

    print(log.PKI_ACCESS_URL % (mdict['pki_hostname'],
                                mdict['pki_https_port'],
                                deployer.subsystem_type.lower()))
    if not config.str2bool(mdict['pki_enable_on_system_boot']):
        print(log.PKI_SYSTEM_BOOT_STATUS_MESSAGE % "disabled")
    else:
        print(log.PKI_SYSTEM_BOOT_STATUS_MESSAGE % "enabled")

    print(log.PKI_SPAWN_INFORMATION_FOOTER)


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
