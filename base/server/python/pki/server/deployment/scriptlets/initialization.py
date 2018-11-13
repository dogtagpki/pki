# Authors:
# Matthew Harmsen <mharmsen@redhat.com>
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

from __future__ import absolute_import
import pki

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet


# PKI Deployment Initialization Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        # begin official logging
        config.pki_log.info(log.PKISPAWN_BEGIN_MESSAGE_2,
                            deployer.mdict['pki_subsystem'],
                            deployer.mdict['pki_instance_name'],
                            extra=config.PKI_INDENTATION_LEVEL_0)

        instance = pki.server.PKIInstance(deployer.mdict['pki_instance_name'])
        instance.load()

        internal_token = deployer.mdict['pki_self_signed_token']

        # if instance already exists and has password, reuse the password
        if internal_token in instance.passwords:
            deployer.mdict['pki_server_database_password'] = instance.passwords.get(internal_token)

        # otherwise, use user-provided password if specified
        elif deployer.mdict['pki_server_database_password']:
            pass

        # otherwise, use user-provided pin if specified
        elif deployer.mdict['pki_pin']:
            deployer.mdict['pki_server_database_password'] = deployer.mdict['pki_pin']

        # otherwise, generate a random password
        else:
            deployer.mdict['pki_server_database_password'] = pki.generate_password()

        # generate random password for client database if not specified
        if not deployer.mdict['pki_client_database_password']:
            deployer.mdict['pki_client_database_password'] = pki.generate_password()

        # ALWAYS initialize 'uid' and 'gid'
        deployer.identity.add_uid_and_gid(deployer.mdict['pki_user'],
                                          deployer.mdict['pki_group'])
        # ALWAYS establish 'uid' and 'gid'
        deployer.identity.set_uid(deployer.mdict['pki_user'])
        deployer.identity.set_gid(deployer.mdict['pki_group'])
        # ALWAYS check FIPS mode
        deployer.fips.is_fips_enabled()
        # ALWAYS initialize HSMs (when and if present)
        deployer.hsm.initialize()
        if config.str2bool(deployer.mdict['pki_skip_installation']):
            config.pki_log.info(log.SKIP_INITIALIZATION_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return

        else:
            config.pki_log.info(log.INITIALIZATION_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)

            # Verify that the subsystem already exists for the following cases:
            # - External CA/KRA/OCSP (Step 2)
            # - Stand-alone PKI (Step 2)
            # - Two-step installation (Step 2)

            if (deployer.subsystem_name in ['CA', 'KRA', 'OCSP'] or
                config.str2bool(deployer.mdict['pki_standalone'])) and \
                    config.str2bool(deployer.mdict['pki_external_step_two']) or \
               config.str2bool(deployer.mdict['pki_skip_installation']):
                deployer.instance.verify_subsystem_exists()
                deployer.mdict['pki_skip_installation'] = "True"

            else:
                # verify that this type of "subsystem" does NOT yet
                # exist for this "instance"
                deployer.instance.verify_subsystem_does_not_exist()
                # detect and avoid any namespace collisions
                deployer.namespace.collision_detection()
        # verify existence of SENSITIVE configuration file data
        deployer.configuration_file.verify_sensitive_data()
        # verify existence of MUTUALLY EXCLUSIVE configuration file data
        deployer.configuration_file.verify_mutually_exclusive_data()
        # verify existence of PREDEFINED configuration file data
        deployer.configuration_file.verify_predefined_configuration_file_data()
        # verify selinux context of selected ports
        deployer.configuration_file.populate_non_default_ports()
        deployer.configuration_file.verify_selinux_ports()
        # If secure DS connection is required, verify parameters
        deployer.configuration_file.verify_ds_secure_connection_data()

    def destroy(self, deployer):
        try:
            # begin official logging
            config.pki_log.info(log.PKIDESTROY_BEGIN_MESSAGE_2,
                                deployer.mdict['pki_subsystem'],
                                deployer.mdict['pki_instance_name'],
                                extra=config.PKI_INDENTATION_LEVEL_0)
            config.pki_log.info(log.INITIALIZATION_DESTROY_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            # verify that this type of "subsystem" currently EXISTS
            # for this "instance"
            deployer.instance.verify_subsystem_exists()
            # verify that the command-line parameters match the values
            # that are present in the corresponding configuration file
            deployer.configuration_file.verify_command_matches_configuration_file()
            # establish 'uid' and 'gid'
            deployer.identity.set_uid(deployer.mdict['pki_user'])
            deployer.identity.set_gid(deployer.mdict['pki_group'])
            # get ports to remove selinux context
            deployer.configuration_file.populate_non_default_ports()

            # remove kra connector from CA if this is a KRA
            deployer.kra_connector.deregister()

            # remove tps connector from TKS if this is a TPS
            deployer.tps_connector.deregister()

            # de-register instance from its Security Domain
            #
            #     NOTE:  Since the security domain of an instance must be up
            #            and running in order to be de-registered, this step
            #            must be done PRIOR to instance shutdown because this
            #            instance's security domain may be a part of a
            #            tightly-coupled shared instance.
            #

            # Previously we obtained the token through a command line interface
            # no longer supported. Thus we assume no token and the deregister op will
            # take place without the token using an alternate method.

            deployer.security_domain.deregister(None)

        except Exception as e:  # pylint: disable=broad-except
            config.pki_log.error(log.PKI_OSERROR_1, e,
                                 extra=config.PKI_INDENTATION_LEVEL_0)
            # If it is a normal destroy, pass any exception
            if not deployer.mdict['pki_force_destroy']:
                raise

        finally:
            # ALWAYS Stop this Tomcat PKI Process
            deployer.systemd.stop()
