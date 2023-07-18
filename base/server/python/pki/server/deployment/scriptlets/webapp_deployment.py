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

# System Imports
from __future__ import absolute_import
import logging
import os

import pki
import pki.server.instance
import pki.util

# PKI Deployment Imports
from .. import pkiscriptlet

logger = logging.getLogger(__name__)


# PKI Web Application Deployment Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):
        pass

    def destroy(self, deployer):

        logger.info('Undeploying /%s web application', deployer.mdict['pki_subsystem'].lower())

        # Delete /etc/pki/<instance>/Catalina/localhost/<subsystem>.xml if exists

        context_xml = os.path.join(
            self.instance.conf_dir,
            'Catalina',
            'localhost',
            deployer.mdict['pki_subsystem'].lower() + '.xml')

        if os.path.exists(context_xml):
            pki.util.remove(context_xml)
