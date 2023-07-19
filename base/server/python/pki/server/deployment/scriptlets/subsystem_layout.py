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
import pki.server.instance
import pki.util

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkiscriptlet

logger = logging.getLogger(__name__)


# PKI Deployment Subsystem Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        external = deployer.configuration_file.external
        standalone = deployer.configuration_file.standalone
        subordinate = deployer.configuration_file.subordinate
        clone = deployer.configuration_file.clone

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping subsystem creation')
            return

        logger.info('Creating %s subsystem', deployer.mdict['pki_subsystem'])

        # If pki_one_time_pin is not specified, generate a new one
        if 'pki_one_time_pin' not in deployer.mdict:
            pin = ''.join(random.choice(string.ascii_letters + string.digits)
                          for x in range(20))
            deployer.mdict['pki_one_time_pin'] = pin

        instance = self.instance

        subsystem_name = deployer.mdict['pki_subsystem'].lower()
        subsystem = pki.server.subsystem.PKISubsystemFactory.create(instance, subsystem_name)
        instance.add_subsystem(subsystem)

        subsystem.create(exist_ok=True)
        subsystem.create_conf(exist_ok=True)
        subsystem.create_logs(exist_ok=True)

        if config.str2bool(deployer.mdict['pki_registry_enable']):
            subsystem.create_registry(exist_ok=True)

        # Copy /usr/share/pki/<subsystem>/conf/CS.cfg
        # to /etc/pki/<instance>/<subsystem>/CS.cfg

        source_cs_cfg = os.path.join(
            pki.server.PKIServer.SHARE_DIR,
            subsystem_name,
            'conf',
            'CS.cfg')

        instance.copyfile(
            source_cs_cfg,
            subsystem.cs_conf,
            params=deployer.mdict)

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

        if deployer.mdict['pki_subsystem'] == "CA":

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

        elif deployer.mdict['pki_subsystem'] == "TPS":

            # Copy /usr/share/pki/<subsystem>/conf/phoneHome.xml
            # to /etc/pki/<instance>/<subsystem>/phoneHome.xml

            pki_target_phone_home_xml = os.path.join(
                subsystem.conf_dir,
                'phoneHome.xml')

            instance.copyfile(
                deployer.mdict['pki_source_phone_home_xml'],
                pki_target_phone_home_xml,
                params=deployer.mdict)

        # Link /var/lib/pki/<instance>/<subsystem>/conf
        # to /etc/pki/<instance>/<subsystem>

        subsystem_conf_link = os.path.join(subsystem.base_dir, 'conf')

        instance.symlink(
            subsystem.conf_dir,
            subsystem_conf_link,
            exist_ok=True)

        # Link /var/lib/pki/<instance>/<subsystem>/logs
        # to /var/log/pki/<instance>/<subsystem>

        subsystem_logs_link = os.path.join(subsystem.base_dir, 'logs')

        instance.symlink(
            subsystem.log_dir,
            subsystem_logs_link,
            exist_ok=True)

        # Link /var/lib/pki/<instance>/<subsystem>/registry
        # to /etc/sysconfig/pki/tomcat/<instance>

        registry_link = os.path.join(subsystem.base_dir, 'registry')

        instance.symlink(
            instance.registry_dir,
            registry_link,
            exist_ok=True)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if config.str2bool(deployer.mdict['pki_enable_proxy']):

            logger.info('Enabling HTTP proxy')

            subsystem.config['proxy.securePort'] = deployer.mdict['pki_proxy_https_port']
            subsystem.config['proxy.unsecurePort'] = deployer.mdict['pki_proxy_http_port']

        certs = subsystem.find_system_certs()
        for cert in certs:

            # get CS.cfg tag and pkispawn tag
            config_tag = cert['id']
            deploy_tag = config_tag

            if config_tag == 'signing':  # for CA and OCSP
                deploy_tag = subsystem.name + '_signing'

            key_type = deployer.mdict['pki_%s_key_type' % deploy_tag].upper()

            if key_type == 'ECC':
                key_type = 'EC'

            if key_type not in ['RSA', 'EC']:
                raise Exception('Unsupported key type: %s' % key_type)

            subsystem.config['preop.cert.%s.keytype' % config_tag] = key_type

        # configure SSL server cert
        if subsystem.type == 'CA' and clone or subsystem.type != 'CA':

            subsystem.config['preop.cert.sslserver.type'] = 'remote'
            key_type = subsystem.config['preop.cert.sslserver.keytype']

            if key_type == 'RSA':
                subsystem.config['preop.cert.sslserver.profile'] = 'caInternalAuthServerCert'

            elif key_type == 'EC':
                subsystem.config['preop.cert.sslserver.profile'] = 'caECInternalAuthServerCert'

        # configure subsystem cert
        if deployer.mdict['pki_security_domain_type'] == 'new':

            subsystem.config['preop.cert.subsystem.type'] = 'local'
            subsystem.config['preop.cert.subsystem.profile'] = 'subsystemCert.profile'

        else:  # deployer.mdict['pki_security_domain_type'] == 'existing':

            subsystem.config['preop.cert.subsystem.type'] = 'remote'
            key_type = subsystem.config['preop.cert.subsystem.keytype']

            if key_type == 'RSA':
                subsystem.config['preop.cert.subsystem.profile'] = 'caInternalAuthSubsystemCert'

            elif key_type == 'EC':
                subsystem.config['preop.cert.subsystem.profile'] = 'caECInternalAuthSubsystemCert'

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

        # configure CA
        if subsystem.type == 'CA':

            if external or subordinate:
                subsystem.config['hierarchy.select'] = 'Subordinate'
            else:
                subsystem.config['hierarchy.select'] = 'Root'

            if subordinate:
                subsystem.config['preop.cert.signing.type'] = 'remote'
                subsystem.config['preop.cert.signing.profile'] = 'caInstallCACert'

            if config.str2bool(deployer.mdict['pki_profiles_in_ldap']):
                index = subsystem.get_subsystem_index('profile')
                subsystem.config['subsystem.%d.class' % index] = \
                    'com.netscape.cmscore.profile.LDAPProfileSubsystem'

        # configure OCSP
        if subsystem.type == 'OCSP':
            if clone:
                subsystem.config['ocsp.store.defStore.refreshInSec'] = '14400'

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

        instance = self.instance
        subsystem_name = deployer.mdict['pki_subsystem'].lower()

        logger.info('Undeploying /%s web application', subsystem_name)

        subsystem = instance.get_subsystem(subsystem_name)
        subsystem.disable(force=deployer.force)

        logger.info('Removing %s subsystem', deployer.mdict['pki_subsystem'])

        instance.remove_subsystem(subsystem)

        if config.str2bool(deployer.mdict['pki_registry_enable']):
            subsystem.remove_registry(force=deployer.force)

        if deployer.mdict['pki_subsystem'] == "CA":

            logger.info('Removing %s/emails', subsystem.conf_dir)
            pki.util.rmtree(
                path=subsystem.conf_dir + '/emails',
                force=deployer.force)

            logger.info('Removing %s/profiles', subsystem.conf_dir)
            pki.util.rmtree(
                path=subsystem.conf_dir + '/profiles',
                force=deployer.force)

        if deployer.remove_logs:
            subsystem.remove_logs(force=deployer.force)

        subsystem.remove_conf(force=deployer.force)
        subsystem.remove(force=deployer.force)
