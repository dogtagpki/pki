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

# System Imports
from __future__ import absolute_import
import logging
import os

import pki
import pki.server.instance
import pki.util

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkiscriptlet

logger = logging.getLogger(__name__)


# PKI Deployment Instance Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping instance creation')
            return

        logger.info('Preparing %s instance', deployer.mdict['pki_instance_name'])

        instance = self.instance
        instance.load()

        # Create /var/lib/pki/<instance>
        instance.makedirs(instance.base_dir, exist_ok=True)

        logger.info('Creating %s', instance.conf_dir)
        instance.makedirs(instance.conf_dir, exist_ok=True)

        instance.makedirs(instance.certs_dir, exist_ok=True)

        # Configuring internal token password

        internal_token = deployer.mdict['pki_self_signed_token']
        if pki.nssdb.internal_token(internal_token):
            internal_token = pki.nssdb.INTERNAL_TOKEN_NAME

        # If instance already exists and has password, reuse the password
        if internal_token in instance.passwords:
            logger.info('Reusing server NSS database password')
            deployer.mdict['pki_server_database_password'] = instance.passwords.get(internal_token)

        # Otherwise, use user-provided password if specified
        elif deployer.mdict['pki_server_database_password']:
            logger.info('Using specified server NSS database password')

        # Otherwise, use user-provided pin if specified
        elif deployer.mdict['pki_pin']:
            logger.info('Using specified PIN as server NSS database password')
            deployer.mdict['pki_server_database_password'] = deployer.mdict['pki_pin']

        # Otherwise, generate a random password
        else:
            logger.info('Generating random server NSS database password')
            deployer.mdict['pki_server_database_password'] = pki.generate_password()

        instance.passwords[internal_token] = deployer.mdict['pki_server_database_password']

        # Configuring HSM password

        if config.str2bool(deployer.mdict['pki_hsm_enable']):
            hsm_token = deployer.mdict['pki_token_name']
            instance.passwords['hardware-%s' % hsm_token] = deployer.mdict['pki_token_password']

        # Configuring internal database password

        if 'internaldb' in instance.passwords:
            logger.info('Reusing internal database password')
            deployer.mdict['pki_ds_password'] = instance.passwords.get('internaldb')

        else:
            logger.info('Using specified internal database password')

        instance.passwords['internaldb'] = deployer.mdict['pki_ds_password']

        # Configuring replication manager password
        # Bug #430745 Create separate password for replication manager
        # Use user-provided password if specified

        if 'replicationdb' in instance.passwords:
            logger.info('Reusing replication manager password')

        elif deployer.mdict['pki_replication_password']:
            logger.info('Using specified replication manager password')
            instance.passwords['replicationdb'] = deployer.mdict['pki_replication_password']

        else:
            logger.info('Generating random replication manager password')
            instance.passwords['replicationdb'] = pki.generate_password()

        logger.info('Creating %s', instance.password_conf)
        instance.store_passwords()

        # if this is not the first subsystem, skip
        if instance.get_subsystems():
            logger.info('Installing %s instance', deployer.mdict['pki_instance_name'])
            return

        deployer.directory.create(instance.log_dir)

        shared_conf_path = os.path.join(
            pki.server.PKIServer.SHARE_DIR,
            'server',
            'conf')

        deployer.configure_server_xml()

        # Link /etc/pki/<instance>/catalina.properties
        # to /usr/share/pki/server/conf/catalina.properties.
        instance.symlink(
            os.path.join(shared_conf_path, 'catalina.properties'),
            os.path.join(instance.conf_dir, 'catalina.properties'),
            exist_ok=True)

        # Link /etc/pki/<instance>/context.xml
        # to /usr/share/tomcat/conf/context.xml.
        context_xml = os.path.join(pki.server.Tomcat.CONF_DIR, 'context.xml')
        instance.symlink(context_xml, instance.context_xml, exist_ok=True)

        # Link /etc/pki/<instance>/logging.properties
        # to /usr/share/pki/server/conf/logging.properties.
        instance.symlink(
            os.path.join(shared_conf_path, 'logging.properties'),
            os.path.join(instance.conf_dir, 'logging.properties'),
            exist_ok=True)

        # Copy /usr/share/pki/server/conf/tomcat.conf
        # to /etc/sysconfig/<instance>

        source_tomcat_conf = os.path.join(
            pki.server.PKIServer.SHARE_DIR,
            'server',
            'conf',
            'tomcat.conf')

        deployer.file.copy_with_slot_substitution(
            source_tomcat_conf,
            instance.service_conf,
            overwrite_flag=True)

        # Copy /usr/share/pki/server/conf/tomcat.conf to
        # /var/lib/pki/<instance>/conf/tomcat.conf.
        deployer.file.copy_with_slot_substitution(
            os.path.join(shared_conf_path, 'tomcat.conf'),
            os.path.join(instance.conf_dir, 'tomcat.conf'),
            overwrite_flag=True)

        # Link /etc/pki/<instance>/web.xml
        # to /usr/share/tomcat/conf/web.xml.
        web_xml = os.path.join(pki.server.Tomcat.CONF_DIR, 'web.xml')
        instance.symlink(web_xml, instance.web_xml, exist_ok=True)

        # Create /etc/pki/<instance>/Catalina
        catalina_dir = os.path.join(instance.conf_dir, 'Catalina')
        instance.makedirs(catalina_dir, exist_ok=True)

        # Create /etc/pki/<instance>/Catalina/localhost
        localhost_dir = os.path.join(catalina_dir, 'localhost')
        instance.makedirs(localhost_dir, exist_ok=True)

        # Rewrite rules are subsystem-specific, but the config is server-wide.
        # So we deploy them as part of the server config, regardless of which
        # subsystem(s) will eventually be deployed.
        #
        logger.info('Deploying HTTP rewrite rules (rewrite.config)')
        instance.symlink(
            os.path.join(shared_conf_path, 'Catalina', 'localhost', 'rewrite.config'),
            os.path.join(localhost_dir, 'rewrite.config'),
            exist_ok=True,
        )

        logger.info('Deploying ROOT web application')
        # Copy /usr/share/pki/server/conf/ROOT.xml
        # to /etc/pki/<instance>/Catalina/localhost/ROOT.xml
        instance.deploy_webapp(
            "ROOT",
            os.path.join(
                shared_conf_path,
                "Catalina",
                "localhost",
                "ROOT.xml"))

        logger.info('Deploying /pki web application')
        # Deploy pki web application which includes themes,
        # admin templates, and JS libraries
        # Copy /usr/share/pki/server/conf/pki.xml
        # to /etc/pki/<instance>/Catalina/localhost/pki.xml
        instance.deploy_webapp(
            "pki",
            os.path.join(
                shared_conf_path,
                "Catalina",
                "localhost",
                "pki.xml"))

        # Link /var/lib/pki/<instance>/lib to /usr/share/pki/server/lib
        # Link /var/lib/pki/<instance>/common/lib to /usr/share/pki/server/common/lib
        instance.with_maven_deps = deployer.with_maven_deps
        instance.create_libs(force=True)

        # Create /var/lib/pki/<instance>/temp
        deployer.directory.create(instance.temp_dir)

        # Create /var/lib/pki/<instance>/work
        deployer.directory.create(instance.work_dir)

        # Link /var/lib/pki/<instance>/bin to /usr/share/tomcat/bin
        deployer.symlink.create(
            deployer.mdict['pki_tomcat_bin_path'],
            instance.bin_dir)

        # Link /var/lib/pki/<instance>/conf to /etc/pki/<instance>
        conf_link = os.path.join(instance.base_dir, 'conf')
        deployer.symlink.create(
            instance.conf_dir,
            conf_link)

        # Create /etc/pki/<instance>/certs
        certs_path = os.path.join(instance.conf_dir, 'certs')
        deployer.directory.create(certs_path)

        # Link /var/lib/pki/<instance>/logs to /var/log/pki/<instance>
        logs_link = os.path.join(instance.base_dir, 'logs')
        deployer.symlink.create(
            instance.log_dir,
            logs_link)

        if config.str2bool(deployer.mdict['pki_registry_enable']):
            instance.create_registry()

        if config.str2bool(deployer.mdict['pki_systemd_service_create']):

            user = deployer.mdict['pki_user']
            group = deployer.mdict['pki_group']

            if user != 'pkiuser' or group != 'pkiuser':
                deployer.systemd.set_override(
                    'Service', 'User', user, 'user.conf')
                deployer.systemd.set_override(
                    'Service', 'Group', group, 'user.conf')

            deployer.systemd.write_overrides()
            deployer.systemd.daemon_reload()

            # Link /etc/systemd/system/pki-tomcatd.target.wants/pki-tomcatd@<instance>.service
            # to /lib/systemd/system/pki-tomcatd@.service

            systemd_service_link = os.path.join(
                pki.server.instance.PKIInstance.TARGET_WANTS,
                instance.service_name + '.service')

            deployer.symlink.create(
                pki.server.instance.PKIInstance.UNIT_FILE,
                systemd_service_link)

    def destroy(self, deployer):

        instance = self.instance

        # if this is not the last subsystem, skip
        if instance.get_subsystems():
            return

        logger.info('Removing %s instance', deployer.mdict['pki_instance_name'])

        logger.info('Removing %s', deployer.systemd.systemd_link)
        pki.util.unlink(link=deployer.systemd.systemd_link,
                        force=deployer.force)

        if deployer.directory.exists(deployer.systemd.base_override_dir):
            logger.info('Removing %s', deployer.systemd.base_override_dir)
            pki.util.rmtree(path=deployer.systemd.base_override_dir,
                            force=deployer.force)

        if deployer.directory.exists(deployer.systemd.nuxwdog_override_dir):
            logger.info('Removing %s', deployer.systemd.nuxwdog_override_dir)
            pki.util.rmtree(path=deployer.systemd.nuxwdog_override_dir,
                            force=deployer.force)

        deployer.systemd.daemon_reload()

        if config.str2bool(deployer.mdict['pki_registry_enable']):
            instance.remove_registry(force=deployer.force)

        logger.info('Removing %s', instance.base_dir)
        pki.util.rmtree(path=instance.base_dir,
                        force=deployer.force)

        if deployer.remove_logs:

            logger.info('Removing %s', instance.log_dir)
            pki.util.rmtree(path=instance.log_dir,
                            force=deployer.force)

        logger.info('Removing %s', instance.conf_dir)
        pki.util.rmtree(
            path=instance.conf_dir,
            force=deployer.force)

        logger.info('Removing %s', instance.service_conf)
        pki.util.remove(
            path=instance.service_conf,
            force=deployer.force)
