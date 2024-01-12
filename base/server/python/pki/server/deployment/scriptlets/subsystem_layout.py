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
import os
import random
import string

import pki.server
import pki.util

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkiscriptlet

logger = logging.getLogger(__name__)


# PKI Deployment Subsystem Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping subsystem creation')
            return

        logger.info('Creating %s subsystem', deployer.subsystem_type)

        # If pki_one_time_pin is not specified, generate a new one
        if 'pki_one_time_pin' not in deployer.mdict:
            pin = ''.join(random.choice(string.ascii_letters + string.digits)
                          for x in range(20))
            deployer.mdict['pki_one_time_pin'] = pin

        instance = self.instance

        subsystem_name = deployer.subsystem_type.lower()
        subsystem = pki.server.subsystem.PKISubsystemFactory.create(instance, subsystem_name)
        instance.add_subsystem(subsystem)

        subsystem.create(exist_ok=True)
        subsystem.create_conf(exist_ok=True)
        subsystem.create_logs(exist_ok=True)

        # Link /var/lib/pki/<instance>/<subsystem>/alias
        # to /var/lib/pki/<instance>/alias

        nssdb_link = os.path.join(subsystem.base_dir, 'alias')

        instance.symlink(
            instance.nssdb_link,
            nssdb_link,
            exist_ok=True)

        if config.str2bool(deployer.mdict['pki_registry_enable']):
            subsystem.create_registry(exist_ok=True)

        deployer.create_cs_cfg(subsystem)

        # Copy /usr/share/pki/<subsystem>/conf/registry.cfg
        # to /etc/pki/<instance>/<subsystem>/registry.cfg

        pki_source_registry_cfg = os.path.join(
            pki.server.PKIServer.SHARE_DIR,
            subsystem_name,
            'conf',
            'registry.cfg')

        pki_target_registry_cfg = os.path.join(
            subsystem.conf_dir,
            'registry.cfg')

        instance.copy(
            pki_source_registry_cfg,
            pki_target_registry_cfg)

        if deployer.subsystem_type == "CA":

            # Copy /usr/share/pki/ca/emails
            # to /etc/pki/<instance>/ca/emails

            pki_source_emails = os.path.join(
                pki.server.PKIServer.SHARE_DIR,
                subsystem_name,
                'emails')

            instance.copy(
                pki_source_emails,
                subsystem.conf_dir + '/emails')

            # Link /var/lib/pki/<instance>/ca/emails
            # to /etc/pki/<instance>/ca/emails

            emails_path = os.path.join(instance.conf_dir, 'ca', 'emails')
            emails_link = os.path.join(instance.base_dir, 'ca', 'emails')
            instance.symlink(emails_path, emails_link, exist_ok=True)

            # Copy /usr/share/pki/ca/profiles
            # to /etc/pki/<instance>/ca/profiles

            pki_source_profiles = os.path.join(
                pki.server.PKIServer.SHARE_DIR,
                subsystem_name,
                'profiles')

            instance.copy(
                pki_source_profiles,
                subsystem.conf_dir + '/profiles')

            # Link /var/lib/pki/<instance>/ca/profiles
            # to /etc/pki/<instance>/ca/profiles
            profiles_path = os.path.join(instance.conf_dir, 'ca', 'profiles')
            profiles_link = os.path.join(instance.base_dir, 'ca', 'profiles')
            instance.symlink(profiles_path, profiles_link, exist_ok=True)

            # Copy /usr/share/pki/<subsystem>/conf/flatfile.txt
            # to /etc/pki/<instance>/<subsystem>/flatfile.txt

            pki_source_flatfile_txt = os.path.join(
                pki.server.PKIServer.SHARE_DIR,
                subsystem_name,
                'conf',
                'flatfile.txt')

            pki_target_flatfile_txt = os.path.join(
                subsystem.conf_dir,
                'flatfile.txt')

            instance.copy(
                pki_source_flatfile_txt,
                pki_target_flatfile_txt)

            # Copy /usr/share/pki/<subsystem>/conf/<type>AdminCert.profile
            # to /etc/pki/<instance>/<subsystem>/adminCert.profile

            admin_key_type = deployer.mdict['pki_admin_key_type']

            pki_source_admincert_profile = os.path.join(
                pki.server.PKIServer.SHARE_DIR,
                subsystem_name,
                'conf',
                admin_key_type + 'AdminCert.profile')

            pki_target_admincert_profile = os.path.join(
                subsystem.conf_dir,
                'adminCert.profile')

            instance.copy(
                pki_source_admincert_profile,
                pki_target_admincert_profile)

            # Copy /usr/share/pki/<subsystem>/conf/caAuditSigningCert.profile
            # to /etc/pki/<instance>/<subsystem>/caAuditSigningCert.profile

            pki_source_caauditsigningcert_profile = os.path.join(
                pki.server.PKIServer.SHARE_DIR,
                subsystem_name,
                'conf',
                'caAuditSigningCert.profile')

            pki_target_caauditsigningcert_profile = os.path.join(
                subsystem.conf_dir,
                'caAuditSigningCert.profile')

            instance.copy(
                pki_source_caauditsigningcert_profile,
                pki_target_caauditsigningcert_profile)

            # Copy /usr/share/pki/<subsystem>/conf/caCert.profile
            # to /etc/pki/<instance>/<subsystem>/caCert.profile

            pki_source_cacert_profile = os.path.join(
                pki.server.PKIServer.SHARE_DIR,
                subsystem_name,
                'conf',
                'caCert.profile')

            pki_target_cacert_profile = os.path.join(
                subsystem.conf_dir,
                'caCert.profile')

            instance.copy(
                pki_source_cacert_profile,
                pki_target_cacert_profile)

            # Copy /usr/share/pki/<subsystem>/conf/caOCSPCert.profile
            # to /etc/pki/<instance>/<subsystem>/caOCSPCert.profile

            pki_source_caocspcert_profile = os.path.join(
                pki.server.PKIServer.SHARE_DIR,
                subsystem_name,
                'conf',
                'caOCSPCert.profile')

            pki_target_caocspcert_profile = os.path.join(
                subsystem.conf_dir,
                'caOCSPCert.profile')

            instance.copy(
                pki_source_caocspcert_profile,
                pki_target_caocspcert_profile)

            # Copy /usr/share/pki/<subsystem>/conf/<type>ServerCert.profile
            # to /etc/pki/<instance>/<subsystem>/serverCert.profile

            sslserver_key_type = deployer.mdict['pki_sslserver_key_type']

            pki_source_servercert_profile = os.path.join(
                pki.server.PKIServer.SHARE_DIR,
                subsystem_name,
                'conf',
                sslserver_key_type + 'ServerCert.profile')

            pki_target_servercert_profile = os.path.join(
                subsystem.conf_dir,
                'serverCert.profile')

            instance.copy(
                pki_source_servercert_profile,
                pki_target_servercert_profile)

            # Copy /usr/share/pki/<subsystem>/conf/<type>SubsystemCert.profile
            # to /etc/pki/<instance>/<subsystem>/subsystemCert.profile

            subsystem_key_type = deployer.mdict['pki_subsystem_key_type']

            pki_source_subsystemcert_profile = os.path.join(
                pki.server.PKIServer.SHARE_DIR,
                subsystem_name,
                'conf',
                subsystem_key_type + 'SubsystemCert.profile')

            pki_target_subsystemcert_profile = os.path.join(
                subsystem.conf_dir,
                'subsystemCert.profile')

            instance.copy(
                pki_source_subsystemcert_profile,
                pki_target_subsystemcert_profile)

            # Copy /usr/share/pki/<subsystem>/conf/proxy.conf
            # to /etc/pki/<instance>/<subsystem>/proxy.conf

            pki_source_proxy_conf = os.path.join(
                pki.server.PKIServer.SHARE_DIR,
                subsystem_name,
                'conf',
                'proxy.conf')

            pki_target_proxy_conf = os.path.join(
                subsystem.conf_dir,
                'proxy.conf')

            instance.copyfile(
                pki_source_proxy_conf,
                pki_target_proxy_conf,
                params=deployer.mdict)

        elif deployer.subsystem_type == "TPS":

            # Copy /usr/share/pki/<subsystem>/conf/phoneHome.xml
            # to /etc/pki/<instance>/<subsystem>/phoneHome.xml

            pki_target_phone_home_xml = os.path.join(
                subsystem.conf_dir,
                'phoneHome.xml')

            instance.copyfile(
                deployer.mdict['pki_source_phone_home_xml'],
                pki_target_phone_home_xml,
                params=deployer.mdict)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        deployer.init_subsystem(subsystem)
        subsystem.save()

    def destroy(self, deployer):

        instance = self.instance
        subsystem_name = deployer.subsystem_type.lower()

        logger.info('Undeploying /%s web application', subsystem_name)

        subsystem = instance.get_subsystem(subsystem_name)
        subsystem.disable(force=deployer.force)

        logger.info('Removing %s subsystem', deployer.subsystem_type)

        instance.remove_subsystem(subsystem)

        if config.str2bool(deployer.mdict['pki_registry_enable']):
            subsystem.remove_registry(force=deployer.force)

        if deployer.remove_logs:
            subsystem.remove_logs(force=deployer.force)

        subsystem.remove_conf(force=deployer.force)
        subsystem.remove(force=deployer.force)
