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
import random
import string

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

        external = deployer.configuration_file.external
        standalone = deployer.configuration_file.standalone
        subordinate = deployer.configuration_file.subordinate

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping subsystem creation')
            return

        logger.info('Creating %s subsystem', deployer.mdict['pki_subsystem'])

        # If pki_one_time_pin is not specified, generate a new one
        if 'pki_one_time_pin' not in deployer.mdict:
            pin = ''.join(random.choice(string.ascii_letters + string.digits)
                          for x in range(20))
            deployer.mdict['pki_one_time_pin'] = pin
            deployer.mdict['PKI_RANDOM_NUMBER_SLOT'] = pin

        instance = self.instance

        # Create /var/log/pki/<instance>/<subsystem>
        logger.info('Creating %s', deployer.mdict['pki_subsystem_log_path'])
        instance.makedirs(
            deployer.mdict['pki_subsystem_log_path'],
            exist_ok=True)

        # Create /var/log/pki/<instance>/<subsystem>/archive
        logger.info('Creating %s', deployer.mdict['pki_subsystem_archive_log_path'])
        instance.makedirs(
            deployer.mdict['pki_subsystem_archive_log_path'],
            exist_ok=True)

        # Create /var/log/pki/<instance>/<subsystem>/signedAudit
        logger.info('Creating %s', deployer.mdict['pki_subsystem_signed_audit_log_path'])
        instance.makedirs(
            deployer.mdict['pki_subsystem_signed_audit_log_path'],
            exist_ok=True)

        # Create /etc/pki/<instance>/<subsystem>
        logger.info('Creating %s', deployer.mdict['pki_subsystem_configuration_path'])
        instance.makedirs(
            deployer.mdict['pki_subsystem_configuration_path'],
            exist_ok=True)

        # Copy /usr/share/pki/<subsystem_type>/conf
        # to /etc/pki/<instance>/<subsystem>
        # logger.info('Creating %s', deployer.mdict['pki_subsystem_configuration_path'])
        # instance.copy(
        #   deployer.mdict['pki_source_conf_path'],
        #   deployer.mdict['pki_subsystem_configuration_path'])

        # Copy /usr/share/pki/<subsystem>/conf/CS.cfg
        # to /etc/pki/<instance>/<subsystem>/CS.cfg
        logger.info('Creating %s', deployer.mdict['pki_target_cs_cfg'])
        instance.copyfile(
            deployer.mdict['pki_source_cs_cfg'],
            deployer.mdict['pki_target_cs_cfg'],
            slots=deployer.slots,
            params=deployer.mdict)

        # Copy /usr/share/pki/<subsystem>/conf/registry.cfg
        # to /etc/pki/<instance>/<subsystem>/registry.cfg
        logger.info('Creating %s', deployer.mdict['pki_target_registry_cfg'])
        instance.copy(
            deployer.mdict['pki_source_registry_cfg'],
            deployer.mdict['pki_target_registry_cfg'])

        if deployer.mdict['pki_subsystem'] == "CA":

            # Copy /usr/share/pki/ca/emails
            # to /var/lib/pki/<instance>/<subsystem>/emails
            logger.info('Creating %s', deployer.mdict['pki_subsystem_emails_path'])
            instance.copy(
                deployer.mdict['pki_source_emails'],
                deployer.mdict['pki_subsystem_emails_path'])

            # Copy /usr/share/pki/ca/profiles/ca
            # to /var/lib/pki/<instance>/<subsystem>/profiles/ca
            logger.info('Creating %s', deployer.mdict['pki_subsystem_profiles_path'])
            instance.copy(
                deployer.mdict['pki_source_profiles'],
                deployer.mdict['pki_subsystem_profiles_path'])

            # Copy /usr/share/pki/<subsystem>/conf/flatfile.txt
            # to /etc/pki/<instance>/<subsystem>/flatfile.txt
            logger.info('Creating %s', deployer.mdict['pki_target_flatfile_txt'])
            instance.copy(
                deployer.mdict['pki_source_flatfile_txt'],
                deployer.mdict['pki_target_flatfile_txt'])

            # Copy /usr/share/pki/<subsystem>/conf/<type>AdminCert.profile
            # to /etc/pki/<instance>/<subsystem>/adminCert.profile
            logger.info('Creating %s', deployer.mdict['pki_target_admincert_profile'])
            instance.copy(
                deployer.mdict['pki_source_admincert_profile'],
                deployer.mdict['pki_target_admincert_profile'])

            # Copy /usr/share/pki/<subsystem>/conf/caAuditSigningCert.profile
            # to /etc/pki/<instance>/<subsystem>/caAuditSigningCert.profile
            logger.info('Creating %s', deployer.mdict['pki_target_caauditsigningcert_profile'])
            instance.copy(
                deployer.mdict['pki_source_caauditsigningcert_profile'],
                deployer.mdict['pki_target_caauditsigningcert_profile'])

            # Copy /usr/share/pki/<subsystem>/conf/caCert.profile
            # to /etc/pki/<instance>/<subsystem>/caCert.profile
            logger.info('Creating %s', deployer.mdict['pki_target_cacert_profile'])
            instance.copy(
                deployer.mdict['pki_source_cacert_profile'],
                deployer.mdict['pki_target_cacert_profile'])

            # Copy /usr/share/pki/<subsystem>/conf/caOCSPCert.profile
            # to /etc/pki/<instance>/<subsystem>/caOCSPCert.profile
            logger.info('Creating %s', deployer.mdict['pki_target_caocspcert_profile'])
            instance.copy(
                deployer.mdict['pki_source_caocspcert_profile'],
                deployer.mdict['pki_target_caocspcert_profile'])

            # Copy /usr/share/pki/<subsystem>/conf/<type>ServerCert.profile
            # to /etc/pki/<instance>/<subsystem>/serverCert.profile
            logger.info('Creating %s', deployer.mdict['pki_target_servercert_profile'])
            instance.copy(
                deployer.mdict['pki_source_servercert_profile'],
                deployer.mdict['pki_target_servercert_profile'])

            # Copy /usr/share/pki/<subsystem>/conf/<type>SubsystemCert.profile
            # to /etc/pki/<instance>/<subsystem>/subsystemCert.profile
            logger.info('Creating %s', deployer.mdict['pki_target_subsystemcert_profile'])
            instance.copy(
                deployer.mdict['pki_source_subsystemcert_profile'],
                deployer.mdict['pki_target_subsystemcert_profile'])

            # Copy /usr/share/pki/<subsystem>/conf/proxy.conf
            # to /etc/pki/<instance>/<subsystem>/proxy.conf
            logger.info('Creating %s', deployer.mdict['pki_target_proxy_conf'])
            instance.copyfile(
                deployer.mdict['pki_source_proxy_conf'],
                deployer.mdict['pki_target_proxy_conf'],
                slots=deployer.slots,
                params=deployer.mdict)

        elif deployer.mdict['pki_subsystem'] == "TPS":

            # Copy /usr/share/pki/<subsystem>/conf/registry.cfg
            # to /etc/pki/<instance>/<subsystem>/registry.cfg
            logger.info('Creating %s', deployer.mdict['pki_target_registry_cfg'])
            instance.copy(
                deployer.mdict['pki_source_registry_cfg'],
                deployer.mdict['pki_target_registry_cfg'])

            # Copy /usr/share/pki/<subsystem>/conf/phoneHome.xml
            # to /etc/pki/<instance>/<subsystem>/phoneHome.xml
            logger.info('Creating %s', deployer.mdict['pki_target_phone_home_xml'])
            instance.copyfile(
                deployer.mdict['pki_source_phone_home_xml'],
                deployer.mdict['pki_target_phone_home_xml'],
                slots=deployer.slots,
                params=deployer.mdict)

        # Link /var/lib/pki/<instance>/<subsystem>/conf
        # to /etc/pki/<instance>/<subsystem>
        logger.info('Creating %s', deployer.mdict['pki_subsystem_conf_link'])
        instance.symlink(
            deployer.mdict['pki_subsystem_configuration_path'],
            deployer.mdict['pki_subsystem_conf_link'])

        # Link /var/lib/pki/<instance>/<subsystem>/logs
        # to /var/log/pki/<instance>/<subsystem>
        logger.info('Creating %s', deployer.mdict['pki_subsystem_logs_link'])
        instance.symlink(
            deployer.mdict['pki_subsystem_log_path'],
            deployer.mdict['pki_subsystem_logs_link'])

        # Link /var/lib/pki/<instance>/<subsystem>/registry
        # to /etc/sysconfig/pki/tomcat/<instance>
        logger.info('Creating %s', deployer.mdict['pki_subsystem_registry_link'])
        instance.symlink(
            deployer.mdict['pki_instance_registry_path'],
            deployer.mdict['pki_subsystem_registry_link'])

        instance = self.instance
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

        if external or standalone:

            # This is needed by IPA to detect step 1 completion.
            # See is_step_one_done() in ipaserver/install/cainstance.py.

            subsystem.config['preop.ca.type'] = 'otherca'

        elif subsystem.type != 'CA' or subordinate:

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
