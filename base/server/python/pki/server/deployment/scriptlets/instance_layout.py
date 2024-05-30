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

        instance = self.instance

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping instance creation')
            return

        logger.info('Preparing %s instance', instance.name)

        instance.load()

        # Create /var/lib/pki/<instance>
        instance.makedirs(instance.base_dir, exist_ok=True)

        # Link /var/lib/pki/<instance>/bin to /usr/share/tomcat/bin
        bin_dir = os.path.join(pki.server.Tomcat.SHARE_DIR, 'bin')
        instance.symlink(bin_dir, instance.bin_dir, exist_ok=True)

        # Create /etc/pki/<instance> and /var/lib/pki/<instance>/conf
        instance.create_conf_dir(exist_ok=True)

        # Create /var/log/pki/<instance> and /var/lib/pki/<instance>/logs
        instance.create_logs_dir(exist_ok=True)

        # Link /var/lib/pki/<instance>/lib to /usr/share/pki/server/lib
        # Link /var/lib/pki/<instance>/common/lib to /usr/share/pki/server/common/lib
        instance.with_maven_deps = deployer.with_maven_deps
        instance.create_libs(force=True)

        # Create /var/lib/pki/<instance>/temp
        instance.makedirs(instance.temp_dir, exist_ok=True)

        # Create /var/lib/pki/<instance>/work
        instance.makedirs(instance.work_dir, exist_ok=True)

        # Create /var/lib/pki/<instance>/conf/certs
        instance.makedirs(instance.certs_dir, exist_ok=True)

        instance.create_server_xml(exist_ok=True)
        deployer.configure_server_xml()
        deployer.configure_http_connectors()
        instance.enable_rewrite(exist_ok=True)

        if config.str2bool(deployer.mdict['pki_enable_proxy']):
            deployer.enable_proxy()

        if config.str2bool(deployer.mdict['pki_enable_access_log']):
            deployer.enable_access_log()
        else:
            deployer.disable_access_log()

        shared_conf_path = os.path.join(
            pki.server.PKIServer.SHARE_DIR,
            'server',
            'conf')

        instance.create_catalina_properties(exist_ok=True)
        instance.create_context_xml(exist_ok=True)
        instance.create_logging_properties(exist_ok=True)
        instance.create_web_xml(exist_ok=True)

        # Configuring internal token password

        token = deployer.mdict['pki_self_signed_token']
        if pki.nssdb.internal_token(token):
            token = pki.nssdb.INTERNAL_TOKEN_NAME

        # If instance already exists and has password, reuse the password
        if token in instance.passwords:
            logger.info('Reusing server NSS database password')

        # Otherwise, use user-provided password if specified
        elif deployer.mdict['pki_server_database_password']:
            logger.info('Using specified server NSS database password')
            instance.passwords[token] = deployer.mdict['pki_server_database_password']

        # Otherwise, use user-provided pin if specified
        elif deployer.mdict['pki_pin']:
            logger.info('Using specified PIN as server NSS database password')
            instance.passwords[token] = deployer.mdict['pki_pin']

        # Otherwise, generate a random password
        else:
            logger.info('Generating random server NSS database password')
            instance.passwords[token] = pki.generate_password()

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

        instance.store_passwords()

        deployer.create_server_nssdb()

        # Copy /usr/share/pki/server/conf/tomcat.conf
        # to /etc/sysconfig/<instance>

        instance.copyfile(
            os.path.join(shared_conf_path, 'tomcat.conf'),
            instance.service_conf,
            params=deployer.mdict,
            exist_ok=True)

        # Copy /usr/share/pki/server/conf/tomcat.conf to
        # /var/lib/pki/<instance>/conf/tomcat.conf.

        instance.copyfile(
            os.path.join(shared_conf_path, 'tomcat.conf'),
            instance.tomcat_conf,
            params=deployer.mdict,
            exist_ok=True)

        # Copy /usr/share/pki/server/conf/ROOT.xml
        # to /var/lib/pki/<instance>/conf/Catalina/localhost/ROOT.xml

        instance.deploy_webapp(
            'ROOT',
            os.path.join(
                shared_conf_path,
                'Catalina',
                'localhost',
                'ROOT.xml'))

        # Deploy pki web application which includes themes,
        # admin templates, and JS libraries
        # Copy /usr/share/pki/server/conf/pki.xml
        # to /var/lib/pki/<instance>/conf/Catalina/localhost/pki.xml

        instance.deploy_webapp(
            'pki',
            os.path.join(
                shared_conf_path,
                'Catalina',
                'localhost',
                'pki.xml'))

        if config.str2bool(deployer.mdict['pki_registry_enable']):
            instance.create_registry()

        # if this is not the first subsystem, skip
        if instance.get_subsystems():
            logger.info('Installing %s instance', instance.name)
            return

        if config.str2bool(deployer.mdict['pki_systemd_service_create']):

            user = deployer.mdict['pki_user']
            group = deployer.mdict['pki_group']

            if user != 'pkiuser' or group != 'pkiuser':
                deployer.set_systemd_override(
                    'Service', 'User', user, 'user.conf')
                deployer.set_systemd_override(
                    'Service', 'Group', group, 'user.conf')

            deployer.write_systemd_overrides()
            deployer.systemd.daemon_reload()

            # Link /etc/systemd/system/pki-tomcatd.target.wants/pki-tomcatd@<instance>.service
            # to /lib/systemd/system/pki-tomcatd@.service

            systemd_service_link = os.path.join(
                pki.server.instance.PKIInstance.TARGET_WANTS,
                instance.service_name + '.service')

            instance.symlink(
                pki.server.instance.PKIInstance.UNIT_FILE,
                systemd_service_link,
                exist_ok=True)

    def destroy(self, deployer):

        instance = self.instance

        # if this is not the last subsystem, skip
        if instance.get_subsystems():
            return

        logger.info('Removing %s instance', instance.name)

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

        logger.info('Removing %s', instance.service_conf)
        pki.util.remove(instance.service_conf, force=deployer.force)

        logger.info('Removing %s', instance.work_dir)
        pki.util.rmtree(instance.work_dir, force=deployer.force)

        logger.info('Removing %s', instance.webapps_dir)
        pki.util.rmtree(instance.webapps_dir, force=deployer.force)

        logger.info('Removing %s', instance.temp_dir)
        pki.util.rmtree(instance.temp_dir, force=deployer.force)

        if deployer.remove_logs:
            # Remove /var/log/pki/<instance> and /var/lib/pki/<instance>/logs
            instance.remove_logs_dir(force=deployer.force)

        instance.remove_libs(force=deployer.force)

        if deployer.remove_conf:
            # Remove /etc/pki/<instance> and /var/lib/pki/<instance>/conf
            instance.remove_conf_dir(force=deployer.force)

        logger.info('Removing %s', instance.bin_dir)
        pki.util.unlink(instance.bin_dir, force=deployer.force)

        logger.info('Removing %s', instance.nssdb_link)
        pki.util.unlink(instance.nssdb_link, deployer.force)

        if os.path.isdir(instance.base_dir) and not os.listdir(instance.base_dir):

            # Remove /var/lib/pki/<instance> if empty
            logger.info('Removing %s', instance.base_dir)
            pki.util.rmtree(path=instance.base_dir, force=deployer.force)
