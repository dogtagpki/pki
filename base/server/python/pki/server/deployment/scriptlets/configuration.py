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

from __future__ import absolute_import
import logging

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkiscriptlet

import pki.nssdb

logger = logging.getLogger(__name__)


# PKI Deployment Configuration Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        external = deployer.configuration_file.external
        standalone = deployer.configuration_file.standalone
        clone = deployer.configuration_file.clone
        step_one = deployer.configuration_file.external_step_one
        skip_configuration = deployer.configuration_file.skip_configuration

        if (external or standalone) and step_one or skip_configuration:
            logger.info('Skipping configuration')
            return

        logger.info('Configuring subsystem')

        instance = self.instance
        instance.load()

        subsystem = instance.get_subsystem(deployer.subsystem_type.lower())

        if deployer.ds_url:
            deployer.configure_internal_database(subsystem)

        deployer.configure_subsystem(subsystem)
        subsystem.save()

        deployer.import_system_cert_requests(subsystem)

        nssdb = instance.open_nssdb()
        try:
            deployer.import_system_certs(nssdb, subsystem)

        finally:
            nssdb.close()

        deployer.update_system_certs(subsystem)
        subsystem.save()

        deployer.update_sslserver_cert_nickname(subsystem)

        if config.str2bool(deployer.mdict['pki_security_domain_setup']):
            deployer.setup_security_domain(subsystem)

        subsystem.save()

        if clone:
            master_config = deployer.import_master_config(subsystem)
        else:
            master_config = None

        if config.str2bool(deployer.mdict['pki_ds_setup']):

            if clone:
                deployer.request_ranges(subsystem)

            deployer.setup_database(subsystem, master_config)

            if not clone and subsystem.type == 'CA':
                subsystem.import_profiles(
                    input_folder='/usr/share/pki/ca/profiles/ca')

        subsystem.load()

        # Check whether the subsystem uses a legacy ID generator.
        using_legacy_id_generator = deployer.is_using_legacy_id_generator(subsystem)

        # Optionally prepare to enable a java debugger
        # (e. g. - 'eclipse'):
        if config.str2bool(deployer.mdict['pki_enable_java_debugger']):
            config.prepare_for_an_external_java_debugger(instance.service_conf)

        # Start/Restart this Tomcat PKI Process
        if len(instance.get_subsystems()) == 1:

            logger.info('Enabling %s subsystem', subsystem.type)
            subsystem.enable()

            if using_legacy_id_generator:
                logger.info('Creating temporary SSL server cert')
                deployer.create_temp_sslserver_cert()

                logger.info('Starting PKI server')
                instance.start(
                    wait=True,
                    max_wait=deployer.startup_timeout,
                    timeout=deployer.request_timeout)

                logger.info('Waiting for %s subsystem', subsystem.type)
                subsystem.wait_for_startup(deployer.startup_timeout, deployer.request_timeout)

        # Optionally wait for debugger to attach (e. g. - 'eclipse'):
        if config.str2bool(deployer.mdict['pki_enable_java_debugger']):
            config.wait_to_attach_an_external_java_debugger()

        deployer.pki_connect()

        # If pki_one_time_pin is not already defined, load from CS.cfg
        if 'pki_one_time_pin' not in deployer.mdict:
            deployer.mdict['pki_one_time_pin'] = subsystem.config['preop.pin']

        nssdb = subsystem.instance.open_nssdb()

        try:
            system_certs = deployer.setup_system_certs(nssdb, subsystem)
            subsystem.save()

            deployer.validate_system_certs(subsystem)

        finally:
            nssdb.close()

        if config.str2bool(deployer.mdict['pki_security_domain_setup']) and \
                subsystem.type == 'CA':
            logger.info('Setting up subsystem user')
            deployer.setup_subsystem_user(subsystem, system_certs['subsystem'])

        if config.str2bool(deployer.mdict['pki_security_domain_setup']):
            deployer.setup_security_domain_manager(subsystem)

        if config.str2bool(deployer.mdict['pki_admin_setup']) and not clone:

            logger.info('Setting up admin cert')
            admin_cert = deployer.setup_admin_cert(subsystem)

            logger.info('Setting up admin user')
            deployer.setup_admin_user(subsystem, admin_cert)

        # For security a subsystem can be configured to use a database user that
        # only has a limited access to the database (instead of using cn=Directory
        # Manager that has a full access to the database).
        #
        # If the database user DN is specified (pki_share_dbuser_dn), and the
        # subsystem needs a database setup (pki_ds_setup=True), then the user will
        # be set up (if needed) and granted access to the database.

        dbuser_dn = deployer.mdict.get('pki_share_dbuser_dn')
        if dbuser_dn and config.str2bool(deployer.mdict['pki_ds_setup']):

            # If the subsystem doesn't use a shared database (pki_share_db=False)
            # and it's not a clone (pki_clone=False), that means it's the first
            # subsystem to be installed, so it will set up the database user.

            if not config.str2bool(deployer.mdict['pki_share_db']) and not clone:
                logger.info('Setting up database user: %s', dbuser_dn)
                deployer.setup_database_user(subsystem, dbuser_dn)

            # Database access needs to be granted on each replica.

            logger.info('Granting database access to %s', dbuser_dn)
            subsystem.grant_database_access(dbuser_dn)

        deployer.finalize_subsystem(subsystem)

        logger.info('%s configuration complete', subsystem.type)

        if len(instance.get_subsystems()) == 1:

            if using_legacy_id_generator:
                logger.info('Stopping PKI server')
                instance.stop(
                    wait=True,
                    max_wait=deployer.startup_timeout,
                    timeout=deployer.request_timeout)

                # Remove temp SSL server cert.
                deployer.remove_temp_sslserver_cert()

            # Store perm SSL server cert nickname and token
            if 'sslserver' in system_certs:
                nickname = system_certs['sslserver']['nickname']
                token = pki.nssdb.normalize_token(system_certs['sslserver']['token'])
                if not token:
                    token = deployer.mdict.get('pki_sslserver_token')
                instance.set_sslserver_cert_nickname(nickname, token)

        else:
            if config.str2bool(deployer.mdict['pki_hsm_enable']):
                logger.info('Stopping PKI server')
                instance.stop(
                    wait=True,
                    max_wait=deployer.startup_timeout,
                    timeout=deployer.request_timeout)
            else:
                logger.info('Starting %s subsystem', subsystem.type)
                subsystem.enable(
                    wait=True,
                    max_wait=deployer.startup_timeout,
                    timeout=deployer.request_timeout)

                logger.info('Waiting for %s subsystem', subsystem.type)
                subsystem.wait_for_startup(deployer.startup_timeout, deployer.request_timeout)

    def destroy(self, deployer):
        pass
