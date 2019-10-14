# Authors:
#     Endi S. Dewata <edewata@redhat.com>
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
# Copyright (C) 2019 Red Hat, Inc.
# All rights reserved.

from __future__ import absolute_import
import logging
from lxml import etree
import os

import pki

logger = logging.getLogger(__name__)


class RemoveUserDatabase(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(RemoveUserDatabase, self).__init__()
        self.message = 'Remove unused UserDatabase from server.xml'

        self.parser = etree.XMLParser(remove_blank_text=True)

    def upgrade_instance(self, instance):

        self.remove_user_database(instance)

        logger.info('Removing tomcat-users.xml')

        tomcat_users_xml = os.path.join(instance.conf_dir, 'tomcat-users.xml')

        if os.path.lexists(tomcat_users_xml):
            self.backup(tomcat_users_xml)
            pki.util.remove(tomcat_users_xml)

        logger.info('Removing tomcat-users.xsd')

        tomcat_users_xsd = os.path.join(instance.conf_dir, 'tomcat-users.xsd')

        if os.path.lexists(tomcat_users_xsd):
            self.backup(tomcat_users_xsd)
            pki.util.remove(tomcat_users_xsd)

    def remove_user_database(self, instance):

        document = etree.parse(instance.server_xml, self.parser)

        server = document.getroot()

        logger.info('Searching for GlobalNamingResources')

        global_naming_resources = server.find('GlobalNamingResources')

        if len(global_naming_resources) == 0:
            logger.info('GlobalNamingResources not found')
            return

        logger.info('Searching for Resources under GlobalNamingResources')

        resources = global_naming_resources.findall('Resource')

        if len(resources) == 0:
            logger.info('No Resources under GlobalNamingResources')
            return

        logger.info('Searching for UserDatabase Resource')

        user_database = None
        for resource in resources:
            name = resource.get('name')
            if name == 'UserDatabase':
                user_database = resource
                break

        if user_database is None:
            logger.info('UserDatabase not found')
            return

        logger.info('Removing UserDatabase Resource')

        self.backup(instance.server_xml)

        global_naming_resources.remove(user_database)

        with open(instance.server_xml, 'wb') as f:
            document.write(f, pretty_print=True, encoding='utf-8')
