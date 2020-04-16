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

import pki.server
import pki.server.instance
import pki.util

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkiscriptlet

logger = logging.getLogger('subsystem')


# PKI Deployment Subsystem Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping subsystem creation')
            return

        logger.info('Creating %s subsystem', deployer.mdict['pki_subsystem'])

        # establish instance-based subsystem logs
        deployer.directory.create(deployer.mdict['pki_subsystem_log_path'])
        deployer.directory.create(
            deployer.mdict['pki_subsystem_archive_log_path'])
        deployer.directory.create(
            deployer.mdict['pki_subsystem_signed_audit_log_path'])

        # create /var/lib/pki/<instance>/<subsystem>/conf
        logger.info('Creating %s', deployer.mdict['pki_subsystem_configuration_path'])
        deployer.directory.create(
            deployer.mdict['pki_subsystem_configuration_path'])

        # deployer.directory.copy(
        #   deployer.mdict['pki_source_conf_path'],
        #   deployer.mdict['pki_subsystem_configuration_path'])

        # create /var/lib/pki/<instance>/<subsystem>/conf/CS.cfg
        logger.info('Creating %s', deployer.mdict['pki_target_cs_cfg'])
        deployer.file.copy_with_slot_substitution(
            deployer.mdict['pki_source_cs_cfg'],
            deployer.mdict['pki_target_cs_cfg'])

        # establish instance-based Tomcat specific subsystems

        # establish instance-based Tomcat PKI subsystem base
        if deployer.mdict['pki_subsystem'] == "CA":

            logger.info('Creating %s', deployer.mdict['pki_subsystem_emails_path'])
            deployer.directory.copy(
                deployer.mdict['pki_source_emails'],
                deployer.mdict['pki_subsystem_emails_path'])

            logger.info('Creating %s', deployer.mdict['pki_subsystem_profiles_path'])
            deployer.directory.copy(
                deployer.mdict['pki_source_profiles'],
                deployer.mdict['pki_subsystem_profiles_path'])

            logger.info('Creating %s', deployer.mdict['pki_target_flatfile_txt'])
            deployer.file.copy(
                deployer.mdict['pki_source_flatfile_txt'],
                deployer.mdict['pki_target_flatfile_txt'])

            logger.info('Creating %s', deployer.mdict['pki_target_registry_cfg'])
            deployer.file.copy(
                deployer.mdict['pki_source_registry_cfg'],
                deployer.mdict['pki_target_registry_cfg'])

            logger.info('Creating bootstrap profiles')
            deployer.file.copy(
                deployer.mdict['pki_source_admincert_profile'],
                deployer.mdict['pki_target_admincert_profile'])
            deployer.file.copy(
                deployer.mdict['pki_source_caauditsigningcert_profile'],
                deployer.mdict['pki_target_caauditsigningcert_profile'])
            deployer.file.copy(
                deployer.mdict['pki_source_cacert_profile'],
                deployer.mdict['pki_target_cacert_profile'])
            deployer.file.copy(
                deployer.mdict['pki_source_caocspcert_profile'],
                deployer.mdict['pki_target_caocspcert_profile'])
            deployer.file.copy(
                deployer.mdict['pki_source_servercert_profile'],
                deployer.mdict['pki_target_servercert_profile'])
            deployer.file.copy(
                deployer.mdict['pki_source_subsystemcert_profile'],
                deployer.mdict['pki_target_subsystemcert_profile'])
            deployer.file.copy_with_slot_substitution(
                deployer.mdict['pki_source_proxy_conf'],
                deployer.mdict['pki_target_proxy_conf'])

        elif deployer.mdict['pki_subsystem'] == "TPS":
            deployer.file.copy_with_slot_substitution(
                deployer.mdict['pki_source_registry_cfg'],
                deployer.mdict['pki_target_registry_cfg'])
            deployer.file.copy_with_slot_substitution(
                deployer.mdict['pki_source_phone_home_xml'],
                deployer.mdict['pki_target_phone_home_xml'])

        # establish instance-based subsystem convenience symbolic links
        deployer.symlink.create(
            deployer.mdict['pki_subsystem_configuration_path'],
            deployer.mdict['pki_subsystem_conf_link'])
        deployer.symlink.create(
            deployer.mdict['pki_subsystem_log_path'],
            deployer.mdict['pki_subsystem_logs_link'])
        deployer.symlink.create(
            deployer.mdict['pki_instance_registry_path'],
            deployer.mdict['pki_subsystem_registry_link'])

        instance = pki.server.instance.PKIInstance(deployer.mdict['pki_instance_name'])
        instance.load()

        subsystem = instance.get_subsystem(deployer.mdict['pki_subsystem'].lower())

        subsystem.config['preop.subsystem.name'] = deployer.mdict['pki_subsystem_name']

        # configure security domain
        if deployer.mdict['pki_security_domain_type'] == 'new':

            subsystem.config['preop.cert.subsystem.type'] = 'local'
            subsystem.config['preop.cert.subsystem.profile'] = 'subsystemCert.profile'

        else:  # deployer.mdict['pki_security_domain_type'] == 'existing':

            subsystem.config['preop.cert.subsystem.type'] = 'remote'

        if subsystem.type == 'CA' and not config.str2bool(deployer.mdict['pki_clone']):

            if config.str2bool(deployer.mdict['pki_external']) or \
                    config.str2bool(deployer.mdict['pki_subordinate']):
                subsystem.config['preop.cert.signing.type'] = 'remote'

            else:
                subsystem.config['preop.ca.type'] = 'sdca'

        # configure cloning
        if config.str2bool(deployer.mdict['pki_clone']):
            subsystem.config['subsystem.select'] = 'Clone'
        else:
            subsystem.config['subsystem.select'] = 'New'

        # configure CA hierarchy
        if subsystem.type == 'CA':

            if config.str2bool(deployer.mdict['pki_external']) or \
                    config.str2bool(deployer.mdict['pki_subordinate']):
                subsystem.config['hierarchy.select'] = 'Subordinate'

            else:
                subsystem.config['hierarchy.select'] = 'Root'

        # configure TPS
        if subsystem.type == 'TPS':
            subsystem.config['auths.instance.ldap1.ldap.basedn'] = \
                deployer.mdict['pki_authdb_basedn']
            subsystem.config['auths.instance.ldap1.ldap.ldapconn.host'] = \
                deployer.mdict['pki_authdb_hostname']
            subsystem.config['auths.instance.ldap1.ldap.ldapconn.port'] = \
                deployer.mdict['pki_authdb_port']
            subsystem.config['auths.instance.ldap1.ldap.ldapconn.secureConn'] = \
                deployer.mdict['pki_authdb_secure_conn']

        subsystem.save()

    def destroy(self, deployer):

        logger.info('Removing %s subsystem', deployer.mdict['pki_subsystem'])

        if deployer.mdict['pki_subsystem'] == "CA":

            logger.info('Removing %s', deployer.mdict['pki_subsystem_emails_path'])
            pki.util.rmtree(
                path=deployer.mdict['pki_subsystem_emails_path'],
                force=deployer.mdict['pki_force_destroy']
            )

            logger.info('Removing %s', deployer.mdict['pki_subsystem_profiles_path'])
            pki.util.rmtree(
                path=deployer.mdict['pki_subsystem_profiles_path'],
                force=deployer.mdict['pki_force_destroy']
            )

        logger.info('Removing %s', deployer.mdict['pki_subsystem_path'])
        pki.util.rmtree(path=deployer.mdict['pki_subsystem_path'],
                        force=deployer.mdict['pki_force_destroy'])

        # remove instance-based subsystem logs only if --remove-logs flag is specified
        if deployer.mdict['pki_remove_logs']:

            logger.info('Removing %s', deployer.mdict['pki_subsystem_signed_audit_log_path'])
            pki.util.rmtree(
                path=deployer.mdict['pki_subsystem_signed_audit_log_path'],
                force=deployer.mdict['pki_force_destroy']
            )

            logger.info('Removing %s', deployer.mdict['pki_subsystem_archive_log_path'])
            pki.util.rmtree(
                path=deployer.mdict['pki_subsystem_archive_log_path'],
                force=deployer.mdict['pki_force_destroy']
            )

            logger.info('Removing %s', deployer.mdict['pki_subsystem_log_path'])
            pki.util.rmtree(
                path=deployer.mdict['pki_subsystem_log_path'],
                force=deployer.mdict['pki_force_destroy']
            )

        logger.info('Removing %s', deployer.mdict['pki_subsystem_configuration_path'])
        pki.util.rmtree(
            path=deployer.mdict['pki_subsystem_configuration_path'],
            force=deployer.mdict['pki_force_destroy']
        )

        logger.info('Removing %s', deployer.mdict['pki_subsystem_registry_path'])
        pki.util.rmtree(
            path=deployer.mdict['pki_subsystem_registry_path'],
            force=deployer.mdict['pki_force_destroy']
        )
