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

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet

logger = logging.getLogger('instance')


# PKI Deployment Instance Layout Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping instance creation')
            return

        # if this is not the first subsystem, skip
        if len(deployer.instance.tomcat_instance_subsystems()) != 1:
            logger.info('Installing %s instance', deployer.mdict['pki_instance_name'])
            return

        logger.info('Creating new %s instance', deployer.mdict['pki_instance_name'])

        instance = pki.server.instance.PKIInstance(deployer.mdict['pki_instance_name'])
        instance.load()

        # establish instance logs
        deployer.directory.create(deployer.mdict['pki_instance_log_path'])

        logger.info('Creating %s', deployer.mdict['pki_instance_configuration_path'])
        # copy /usr/share/pki/server/conf tree into
        # /var/lib/pki/<instance>/conf
        # except common ldif files and theme deployment descriptor
        deployer.directory.copy(
            deployer.mdict['pki_source_server_path'],
            deployer.mdict['pki_instance_configuration_path'],
            ignore_cb=file_ignore_callback_src_server)

        logger.info('Creating %s', deployer.mdict['pki_target_server_xml'])
        # Copy /usr/share/pki/server/conf/server.xml
        # to /etc/pki/<instance>/server.xml.
        deployer.file.copy_with_slot_substitution(
            deployer.mdict['pki_source_server_xml'],
            deployer.mdict['pki_target_server_xml'],
            overwrite_flag=True)

        # Link /etc/pki/<instance>/catalina.properties
        # to /usr/share/pki/server/conf/catalina.properties.
        deployer.symlink.create(
            os.path.join(deployer.mdict['pki_source_server_path'],
                         "catalina.properties"),
            os.path.join(deployer.mdict['pki_instance_configuration_path'],
                         "catalina.properties"))

        # Link /etc/pki/<instance>/ciphers.info
        # to /usr/share/pki/server/conf/ciphers.info.
        deployer.symlink.create(
            os.path.join(deployer.mdict['pki_source_server_path'],
                         "ciphers.info"),
            os.path.join(deployer.mdict['pki_instance_configuration_path'],
                         "ciphers.info"))

        # Link /etc/pki/<instance>/context.xml
        # to /usr/share/tomcat/conf/context.xml.
        context_xml = os.path.join(pki.server.Tomcat.CONF_DIR, 'context.xml')
        instance.symlink(context_xml, instance.context_xml)

        # Link /etc/pki/<instance>/logging.properties
        # to /usr/share/pki/server/conf/logging.properties.
        deployer.symlink.create(
            os.path.join(deployer.mdict['pki_source_server_path'],
                         "logging.properties"),
            os.path.join(deployer.mdict['pki_instance_configuration_path'],
                         "logging.properties"))

        logger.info('Creating %s', deployer.mdict['pki_target_tomcat_conf_instance_id'])
        # create /etc/sysconfig/<instance>
        deployer.file.copy_with_slot_substitution(
            deployer.mdict['pki_source_tomcat_conf'],
            deployer.mdict['pki_target_tomcat_conf_instance_id'],
            overwrite_flag=True)

        logger.info('Creating %s', deployer.mdict['pki_target_tomcat_conf'])
        # create /var/lib/pki/<instance>/conf/tomcat.conf
        deployer.file.copy_with_slot_substitution(
            deployer.mdict['pki_source_tomcat_conf'],
            deployer.mdict['pki_target_tomcat_conf'],
            overwrite_flag=True)

        # Link /etc/pki/<instance>/tomcat-users.xml
        # to /usr/share/tomcat/conf/tomcat-users.xml.
        tomcat_users_xml = os.path.join(pki.server.Tomcat.CONF_DIR, 'tomcat-users.xml')
        instance.symlink(tomcat_users_xml, instance.tomcat_users_xml)

        # Link /etc/pki/<instance>/tomcat-users.xsd
        # to /usr/share/tomcat/conf/tomcat-users.xsd.
        tomcat_users_xsd = os.path.join(pki.server.Tomcat.CONF_DIR, 'tomcat-users.xsd')
        instance.symlink(tomcat_users_xsd, instance.tomcat_users_xsd)

        # Link /etc/pki/<instance>/web.xml
        # to /usr/share/tomcat/conf/web.xml.
        web_xml = os.path.join(pki.server.Tomcat.CONF_DIR, 'web.xml')
        instance.symlink(web_xml, instance.web_xml)

        logger.info('Deploying ROOT web application')
        instance.deploy_webapp(
            "ROOT",
            os.path.join(
                deployer.mdict['pki_source_server_path'],
                "Catalina",
                "localhost",
                "ROOT.xml"))

        logger.info('Deploying /pki web application')
        # Deploy pki web application which includes themes,
        # admin templates, and JS libraries
        instance.deploy_webapp(
            "pki",
            os.path.join(
                deployer.mdict['pki_source_server_path'],
                "Catalina",
                "localhost",
                "pki.xml"))

        instance.with_maven_deps = deployer.with_maven_deps
        instance.create_libs()

        deployer.directory.create(deployer.mdict['pki_tomcat_tmpdir_path'])

        deployer.directory.create(deployer.mdict['pki_tomcat_work_path'])
        deployer.directory.create(
            deployer.mdict['pki_tomcat_work_catalina_path'])
        deployer.directory.create(
            deployer.mdict['pki_tomcat_work_catalina_host_path'])
        deployer.directory.create(
            deployer.mdict['pki_tomcat_work_catalina_host_run_path'])
        deployer.directory.create(
            deployer.mdict['pki_tomcat_work_catalina_host_subsystem_path'])
        # establish Tomcat instance logs
        # establish Tomcat instance registry
        # establish Tomcat instance convenience symbolic links
        deployer.symlink.create(
            deployer.mdict['pki_tomcat_bin_path'],
            deployer.mdict['pki_tomcat_bin_link'])

        logger.info('Creating %s', deployer.mdict['pki_instance_systemd_link'])
        # create systemd links
        deployer.symlink.create(
            deployer.mdict['pki_tomcat_systemd'],
            deployer.mdict['pki_instance_systemd_link'],
            uid=0, gid=0)
        user = deployer.mdict['pki_user']
        group = deployer.mdict['pki_group']
        if user != 'pkiuser' or group != 'pkiuser':
            deployer.systemd.set_override(
                'Service', 'User', user, 'user.conf')
            deployer.systemd.set_override(
                'Service', 'Group', group, 'user.conf')
        deployer.systemd.write_overrides()
        deployer.systemd.daemon_reload()

        # establish shared NSS security databases for this instance
        deployer.directory.create(deployer.mdict['pki_server_database_path'])
        # establish instance convenience symbolic links
        deployer.symlink.create(
            deployer.mdict['pki_server_database_path'],
            deployer.mdict['pki_instance_database_link'])
        deployer.symlink.create(
            deployer.mdict['pki_instance_configuration_path'],
            deployer.mdict['pki_instance_conf_link'])
        deployer.symlink.create(
            deployer.mdict['pki_instance_log_path'],
            deployer.mdict['pki_instance_logs_link'])

        # create Tomcat instance systemd service link
        deployer.symlink.create(deployer.mdict['pki_systemd_service'],
                                deployer.mdict['pki_systemd_service_link'])

        # create instance registry
        deployer.file.copy_with_slot_substitution(
            deployer.mdict['pki_source_registry'],
            os.path.join(deployer.mdict['pki_instance_registry_path'],
                         deployer.mdict['pki_instance_name']),
            overwrite_flag=True)

    def destroy(self, deployer):

        logger.info('Removing %s instance', deployer.mdict['pki_instance_name'])

        # if this is not the last subsystem, skip
        if len(deployer.instance.tomcat_instance_subsystems()) != 0:
            return

        # remove Tomcat instance systemd service link
        deployer.symlink.delete(deployer.systemd.systemd_link)

        # delete systemd override directories
        if deployer.directory.exists(deployer.systemd.base_override_dir):
            deployer.directory.delete(deployer.systemd.base_override_dir)
        if deployer.directory.exists(deployer.systemd.nuxwdog_override_dir):
            deployer.directory.delete(deployer.systemd.nuxwdog_override_dir)
        deployer.systemd.daemon_reload()

        # remove Tomcat instance base
        deployer.directory.delete(deployer.mdict['pki_instance_path'])

        # remove Tomcat instance logs only if --remove-logs is specified
        if deployer.mdict['pki_remove_logs']:
            deployer.directory.delete(deployer.mdict['pki_instance_log_path'])

        # remove shared NSS security database path for this instance
        deployer.directory.delete(deployer.mdict['pki_server_database_path'])
        # remove Tomcat instance configuration
        deployer.directory.delete(
            deployer.mdict['pki_instance_configuration_path'])
        # remove PKI 'tomcat.conf' instance file
        deployer.file.delete(
            deployer.mdict['pki_target_tomcat_conf_instance_id'])
        # remove Tomcat instance registry
        deployer.directory.delete(
            deployer.mdict['pki_instance_registry_path'])


# Callback only when the /usr/share/pki/server/conf directory
# Is getting copied to the etc tree.
# Don't copy the shared ldif files:
# schema.ldif, manager.ldif, database.ldif
def file_ignore_callback_src_server(src, names):
    logger.debug(log.FILE_EXCLUDE_CALLBACK_2, src, names)

    return {
        'catalina.properties',
        'ciphers.info',
        'schema.ldif',
        'database.ldif',
        'manager.ldif',
        'pki.xml',
        'logging.properties',
        'schema-authority.ldif',
        'schema-certProfile.ldif',
        'serverCertNick.conf',
        'tomcat-users.xml',
        'usn.ldif'
    }
