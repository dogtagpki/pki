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

                deployer.validate_system_certs(nssdb, subsystem)

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

        server_config = instance.get_server_config()
        unsecurePort = server_config.get_unsecure_port()
        securePort = server_config.get_secure_port()

        proxyUnsecurePort = subsystem.config.get('proxy.unsecurePort')
        if not proxyUnsecurePort:
            proxyUnsecurePort = unsecurePort

        proxySecurePort = subsystem.config.get('proxy.securePort')
        if not proxySecurePort:
            proxySecurePort = securePort

        if deployer.mdict['pki_security_domain_type'] == 'existing':

            logger.info('Joining existing domain')

            deployer.join_security_domain()

            subsystem.configure_security_domain(
                'existing',
                deployer.domain_info.id,
                deployer.sd_host.Hostname,
                deployer.sd_host.Port,
                deployer.sd_host.SecurePort)

        elif config.str2bool(deployer.mdict['pki_subordinate']) and \
                config.str2bool(deployer.mdict['pki_subordinate_create_new_security_domain']):

            logger.info('Creating new subordinate security domain')

            deployer.join_security_domain()

            subsystem.configure_security_domain(
                'new',
                deployer.mdict['pki_subordinate_security_domain_name'],
                deployer.mdict['pki_hostname'],
                unsecurePort,
                securePort)

        else:

            logger.info('Creating new security domain')

            subsystem.configure_security_domain(
                'new',
                deployer.mdict['pki_security_domain_name'],
                deployer.mdict['pki_hostname'],
                unsecurePort,
                securePort)

        subsystem.config['service.securityDomainPort'] = securePort

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

        if clone:

            if subsystem.type in ['CA', 'KRA']:

                logger.info('Requesting ranges from %s master', subsystem.type)
                subsystem.request_ranges(master_url, session_id=deployer.install_token.token)

            logger.info('Retrieving config params from %s master', subsystem.type)

            names = [
                'internaldb.ldapauth.password',
                'internaldb.replication.password'
            ]

            substores = [
                'internaldb',
                'internaldb.ldapauth',
                'internaldb.ldapconn'
            ]

            tags = subsystem.config['preop.cert.list'].split(',')
            for tag in tags:
                if tag == 'sslserver':
                    continue
                substores.append(subsystem.name + '.' + tag)

            if subsystem.name == 'ca':
                substores.append('ca.connector.KRA')
            else:
                names.append('cloning.ca.type')

            master_config = subsystem.retrieve_config(
                master_url,
                names,
                substores,
                session_id=deployer.install_token.token)

            logger.info('Validating %s master config params', subsystem.type)

            master_properties = master_config['properties']

            master_hostname = master_properties['internaldb.ldapconn.host']
            master_port = master_properties['internaldb.ldapconn.port']

            replica_hostname = subsystem.config['internaldb.ldapconn.host']
            replica_port = subsystem.config['internaldb.ldapconn.port']

            if master_hostname == replica_hostname and master_port == replica_port:
                raise Exception('Master and replica must not share LDAP database')

            logger.info('Importing %s master config params', subsystem.type)

            subsystem.import_master_config(master_properties)

        if config.str2bool(deployer.mdict['pki_ds_remove_data']):

            if config.str2bool(deployer.mdict['pki_ds_create_new_db']):
                logger.info('Removing existing database')
                subsystem.remove_database(force=True)

            elif not config.str2bool(deployer.mdict['pki_clone']) or \
                    config.str2bool(deployer.mdict['pki_clone_setup_replication']):
                logger.info('Emptying existing database')
                subsystem.empty_database(force=True)

            else:
                logger.info('Reusing replicated database')

        logger.info('Initializing database')

        # In most cases, we want to replicate the schema and therefore not add it here.
        # We provide this option though in case the clone already has schema
        # and we want to replicate back to the master.

        # On the other hand, if we are not setting up replication,
        # then we are assuming that replication is already taken care of,
        # and schema has already been replicated.

        setup_schema = not config.str2bool(deployer.mdict['pki_clone']) or \
            not config.str2bool(deployer.mdict['pki_clone_setup_replication']) or \
            not config.str2bool(deployer.mdict['pki_clone_replicate_schema'])

        create_database = config.str2bool(deployer.mdict['pki_ds_create_new_db'])

        # When cloning a subsystem without setting up the replication agreements,
        # the database is a subtree of an existing tree and is already replicated,
        # so there is no need to set up the base entry.

        create_base = config.str2bool(deployer.mdict['pki_ds_create_new_db']) or \
            not config.str2bool(deployer.mdict['pki_clone']) or \
            config.str2bool(deployer.mdict['pki_clone_setup_replication'])

        create_containers = not config.str2bool(deployer.mdict['pki_clone'])

        ds_port = subsystem.config['internaldb.ldapconn.port']
        logger.info('- internaldb.ldapconn.port: %s', ds_port)

        secure_conn = subsystem.config['internaldb.ldapconn.secureConn']
        logger.info('- internaldb.ldapconn.secureConn: %s', secure_conn)

        # If the database is already replicated but not yet indexed, rebuild the indexes.

        rebuild_indexes = config.str2bool(deployer.mdict['pki_clone']) and \
            not config.str2bool(deployer.mdict['pki_clone_setup_replication']) and \
            config.str2bool(deployer.mdict['pki_clone_reindex_data'])

        subsystem.init_database(
            setup_schema=setup_schema,
            create_database=create_database,
            create_base=create_base,
            create_containers=create_containers,
            rebuild_indexes=rebuild_indexes)

        if config.str2bool(deployer.mdict['pki_clone']) and \
                config.str2bool(deployer.mdict['pki_clone_setup_replication']):

            logger.info('Setting up replication')

            master_replication_port = deployer.mdict['pki_clone_replication_master_port']
            logger.info('- master replication port: %s', master_replication_port)

            replica_replication_port = deployer.mdict['pki_clone_replication_clone_port']
            logger.info('- replica replication port: %s', replica_replication_port)

            if replica_replication_port == ds_port and secure_conn == 'true':
                replication_security = 'SSL'

            else:
                replication_security = deployer.mdict['pki_clone_replication_security']
                if not replication_security:
                    replication_security = 'None'

            logger.info('- replication security: %s', replication_security)

            subsystem.setup_replication(
                master_properties,
                master_replication_port=master_replication_port,
                replica_replication_port=replica_replication_port,
                replication_security=replication_security)

        # For security a PKI subsystem can be configured to use a database user
        # that only has a limited access to the database (instead of cn=Directory
        # Manager that has a full access to the database).
        #
        # The default database user is uid=pkidbuser,ou=people,<subsystem base DN>.
        # However, if the subsystem is configured to share the database with another
        # subsystem (pki_share_db=True), it can also be configured to use the same
        # database user (pki_share_dbuser_dn).

        if config.str2bool(deployer.mdict['pki_share_db']):
            dbuser = deployer.mdict['pki_share_dbuser_dn']
        else:
            dbuser = 'uid=pkidbuser,ou=people,' + deployer.mdict['pki_ds_base_dn']

        subsystem.grant_database_access(dbuser)

        subsystem.add_vlv()
        subsystem.reindex_vlv()

        subsystem.load()

        if not clone and subsystem.type == 'CA':
            subsystem.import_profiles(
                input_folder='/usr/share/pki/ca/profiles/ca')

        # Check whether the subsystem uses a legacy ID generator.
        using_legacy_id_generator = deployer.is_using_legacy_id_generator(subsystem)

        # Optionally prepare to enable a java debugger
        # (e. g. - 'eclipse'):
        if config.str2bool(deployer.mdict['pki_enable_java_debugger']):
            config.prepare_for_an_external_java_debugger(
                deployer.mdict['pki_target_tomcat_conf_instance_id'])

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

        finally:
            nssdb.close()

        subsystem.save()

        if subsystem.type == 'CA':
            logger.info('Setting up subsystem user')
            deployer.setup_subsystem_user(instance, subsystem, system_certs['subsystem'])

        if not clone:
            logger.info('Setting up admin cert')
            admin_cert = deployer.setup_admin_cert(subsystem)

            logger.info('Setting up admin user')
            deployer.setup_admin_user(subsystem, admin_cert)

        domain_manager = False

        if subsystem.type == 'CA':
            if clone:
                sd_hostname = subsystem.config['securitydomain.host']
                sd_port = subsystem.config['securitydomain.httpsadminport']

                sd_subsystem = deployer.domain_info.subsystems['CA']
                sd_host = sd_subsystem.get_host(sd_hostname, sd_port)

                if sd_host.DomainManager and sd_host.DomainManager.lower() == 'true':
                    domain_manager = True

        if deployer.mdict['pki_security_domain_type'] == 'existing':

            sd_url = deployer.mdict['pki_security_domain_uri']
            logger.info('Joining security domain at %s', sd_url)
            subsystem.join_security_domain(
                sd_url,
                deployer.mdict['pki_subsystem_name'],
                deployer.mdict['pki_hostname'],
                unsecure_port=proxyUnsecurePort,
                secure_port=proxySecurePort,
                domain_manager=domain_manager,
                clone=clone,
                session_id=deployer.install_token.token)

        else:
            logger.info('Creating security domain')
            subsystem.create_security_domain()

            logger.info('Adding security domain manager')
            subsystem.add_security_domain_host(
                deployer.mdict['pki_subsystem_name'],
                deployer.mdict['pki_hostname'],
                unsecure_port=proxyUnsecurePort,
                secure_port=proxySecurePort,
                domain_manager=True)

        if not config.str2bool(deployer.mdict['pki_share_db']) and not clone:
            logger.info('Setting up database user')
            deployer.setup_database_user(instance, subsystem)

        if subsystem.type == 'CA':

            if clone:
                if sd_host.DomainManager and sd_host.DomainManager.lower() == 'true':

                    logger.info('Cloning security domain master')

                    subsystem.config['securitydomain.select'] = 'new'
                    subsystem.config['securitydomain.host'] = deployer.mdict['pki_hostname']
                    subsystem.config['securitydomain.httpport'] = unsecurePort
                    subsystem.config['securitydomain.httpsadminport'] = securePort
                    subsystem.config['securitydomain.httpsagentport'] = securePort
                    subsystem.config['securitydomain.httpseeport'] = securePort

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
                deployer.remove_temp_sslserver_cert(instance, system_certs['sslserver'])

            # Store perm SSL server cert nickname and token
            nickname = system_certs['sslserver']['nickname']
            token = pki.nssdb.normalize_token(system_certs['sslserver']['token'])

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
