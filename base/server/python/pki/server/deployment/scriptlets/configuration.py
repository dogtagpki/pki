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
import urllib.parse

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
        step_one = deployer.configuration_file.external_step_one
        skip_configuration = deployer.configuration_file.skip_configuration

        if (external or standalone) and step_one or skip_configuration:
            logger.info('Skipping configuration')
            return

        logger.info('Configuring subsystem')

        instance = self.instance
        instance.load()

        subsystems = instance.get_subsystems()
        subsystem = instance.get_subsystem(deployer.mdict['pki_subsystem'].lower())

        deployer.configure_subsystem(subsystem)
        subsystem.save()

        token = pki.nssdb.normalize_token(deployer.mdict['pki_token_name'])
        nssdb = instance.open_nssdb(
            user=deployer.mdict['pki_user'],
            group=deployer.mdict['pki_group'])

        existing = deployer.configuration_file.existing
        step_two = deployer.configuration_file.external_step_two
        clone = deployer.configuration_file.clone
        master_url = deployer.mdict['pki_clone_uri']

        try:
            if existing or (external or standalone) and step_two:

                deployer.import_system_cert_requests(subsystem)
                deployer.import_system_certs(nssdb, subsystem)

                deployer.configure_system_certs(subsystem)

                deployer.update_system_certs(nssdb, subsystem)
                subsystem.save()

            elif len(subsystems) > 1:

                for s in subsystems:

                    # find a subsystem that is already installed
                    if s.name == subsystem.name:
                        continue

                    # import cert/request data from the existing subsystem
                    # into the new subsystem being installed

                    logger.info('Importing sslserver cert data from %s', s.type)
                    subsystem.config['%s.sslserver.cert' % subsystem.name] = \
                        s.config['%s.sslserver.cert' % s.name]

                    logger.info('Importing subsystem cert data from %s', s.type)
                    subsystem.config['%s.subsystem.cert' % subsystem.name] = \
                        s.config['%s.subsystem.cert' % s.name]

                    logger.info('Importing sslserver request data from %s', s.type)
                    subsystem.config['%s.sslserver.certreq' % subsystem.name] = \
                        s.config['%s.sslserver.certreq' % s.name]

                    logger.info('Importing subsystem request data from %s', s.type)
                    subsystem.config['%s.subsystem.certreq' % subsystem.name] = \
                        s.config['%s.subsystem.certreq' % s.name]

                    break

            else:  # self-signed CA

                # To be implemented in ticket #1692.

                # Generate CA cert request.
                # Self sign CA cert.
                # Import self-signed CA cert into NSS database.

                pass

        finally:
            nssdb.close()

        if config.str2bool(deployer.mdict['pki_security_domain_setup']):
            deployer.setup_security_domain(instance, subsystem)

        hierarchy = subsystem.config.get('hierarchy.select')
        issuing_ca = deployer.mdict['pki_issuing_ca']

        if external and subsystem.type == 'CA':
            # No need to use issuing CA during CA installation
            # with external certs since the certs will be provided.
            pass

        elif standalone and subsystem.type in ['KRA', 'OCSP']:
            # No need to use issuing CA during standalone KRA/OCSP
            # installation since the certs will be provided.
            pass

        else:
            # For other cases, use issuing CA to issue certs during installation.
            # KRA will also configure a connector in the issuing CA, and OCSP will
            # configure a publisher in the issuing CA.

            logger.info('Using CA at %s', issuing_ca)
            url = urllib.parse.urlparse(issuing_ca)

            subsystem.config['preop.ca.url'] = issuing_ca
            subsystem.config['preop.ca.hostname'] = url.hostname
            subsystem.config['preop.ca.httpsport'] = str(url.port)
            subsystem.config['preop.ca.httpsadminport'] = str(url.port)

        system_certs_imported = \
            deployer.mdict['pki_server_pkcs12_path'] != '' or \
            deployer.mdict['pki_clone_pkcs12_path'] != ''

        if not (subsystem.type == 'CA' and hierarchy == 'Root'):

            if external and subsystem.type == 'CA' or \
                    standalone and subsystem.type in ['KRA', 'OCSP']:
                subsystem.config['preop.ca.pkcs7'] = ''

            elif not clone and not system_certs_imported:

                logger.info('Retrieving CA certificate chain from %s', issuing_ca)

                pem_chain = deployer.get_ca_signing_cert(instance, issuing_ca)
                base64_chain = pki.nssdb.convert_pkcs7(pem_chain, 'pem', 'base64')
                subsystem.config['preop.ca.pkcs7'] = base64_chain

                logger.info('Importing CA certificate chain')

                nssdb = instance.open_nssdb()
                try:
                    nssdb.import_pkcs7(pkcs7_data=pem_chain, trust_attributes='CT,C,C')
                finally:
                    nssdb.close()

        if subsystem.type == 'CA' and clone and not system_certs_imported:

            logger.info('Retrieving CA certificate chain from %s', master_url)

            pem_chain = deployer.get_ca_signing_cert(instance, master_url)
            base64_chain = pki.nssdb.convert_pkcs7(pem_chain, 'pem', 'base64')
            subsystem.config['preop.clone.pkcs7'] = base64_chain

            logger.info('Importing CA certificate chain')

            nssdb = instance.open_nssdb()
            try:
                nssdb.import_pkcs7(pkcs7_data=pem_chain, trust_attributes='CT,C,C')
            finally:
                nssdb.close()

        subsystem.save()

        if config.str2bool(deployer.mdict['pki_ds_setup']):
            deployer.setup_database(subsystem)

        subsystem.load()

        if not clone and subsystem.type == 'CA':
            subsystem.import_profiles(
                input_folder='/usr/share/pki/ca/profiles/ca')

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
                deployer.create_temp_sslserver_cert(instance)

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

        deployer.pki_connect(subsystem)

        # If pki_one_time_pin is not already defined, load from CS.cfg
        if 'pki_one_time_pin' not in deployer.mdict:
            deployer.mdict['pki_one_time_pin'] = subsystem.config['preop.pin']

        nssdb = subsystem.instance.open_nssdb(
            user=deployer.mdict['pki_user'],
            group=deployer.mdict['pki_group'])

        try:
            system_certs = deployer.setup_system_certs(nssdb, subsystem)
            subsystem.save()

            deployer.validate_system_certs(subsystem)

        finally:
            nssdb.close()

        if config.str2bool(deployer.mdict['pki_security_domain_setup']) and \
                subsystem.type == 'CA':
            logger.info('Setting up subsystem user')
            deployer.setup_subsystem_user(instance, subsystem, system_certs['subsystem'])

        if config.str2bool(deployer.mdict['pki_admin_setup']) and not clone:
            logger.info('Setting up admin cert')
            admin_cert = deployer.setup_admin_cert(subsystem)

            logger.info('Setting up admin user')
            deployer.setup_admin_user(subsystem, admin_cert)

        if config.str2bool(deployer.mdict['pki_security_domain_setup']):
            deployer.setup_security_domain_manager(instance, subsystem)

        if not config.str2bool(deployer.mdict['pki_share_db']) and not clone:
            logger.info('Setting up database user')
            deployer.setup_database_user(instance, subsystem)

        deployer.finalize_subsystem(instance, subsystem)

        logger.info('%s configuration complete', subsystem.type)

        if len(instance.get_subsystems()) == 1:

            if using_legacy_id_generator:
                logger.info('Stopping PKI server')
                instance.stop(
                    wait=True,
                    max_wait=deployer.startup_timeout,
                    timeout=deployer.request_timeout)

                # Remove temp SSL server cert.
                deployer.remove_temp_sslserver_cert(instance)

            # Store perm SSL server cert nickname and token
            nickname = system_certs['sslserver']['nickname']
            token = pki.nssdb.normalize_token(system_certs['sslserver']['token'])

            if not token:
                token = deployer.mdict.get('pki_sslserver_token')
                if not token:
                    token = deployer.mdict['pki_token_name']

            instance.set_sslserver_cert_nickname(nickname, token)

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
