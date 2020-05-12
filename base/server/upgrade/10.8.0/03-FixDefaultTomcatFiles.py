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
import os

import pki

logger = logging.getLogger(__name__)


class FixDefaultTomcatFiles(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(FixDefaultTomcatFiles, self).__init__()
        self.message = 'Fix links to default Tomcat files'

    def upgrade_instance(self, instance):

        logger.info('Checking %s', instance.context_xml)
        if not os.path.islink(instance.context_xml):

            context_xml = os.path.join(pki.server.Tomcat.CONF_DIR, 'context.xml')
            logger.info('Linking %s to %s', instance.context_xml, context_xml)

            self.backup(instance.context_xml)

            if os.path.exists(instance.context_xml):
                pki.util.remove(instance.context_xml)

            instance.symlink(context_xml, instance.context_xml)

        logger.info('Checking %s', instance.web_xml)
        if not os.path.islink(instance.web_xml):

            web_xml = os.path.join(pki.server.Tomcat.CONF_DIR, 'web.xml')
            logger.info('Linking %s to %s', instance.web_xml, web_xml)

            self.backup(instance.web_xml)

            if os.path.exists(instance.web_xml):
                pki.util.remove(instance.web_xml)

            instance.symlink(web_xml, instance.web_xml)
