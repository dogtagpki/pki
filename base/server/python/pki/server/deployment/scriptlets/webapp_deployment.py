#!/usr/bin/python -t
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
import os

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet


# PKI Web Application Deployment Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):
    rv = 0

    def spawn(self, deployer):
        if config.str2bool(deployer.mdict['pki_skip_installation']):
            config.pki_log.info(log.SKIP_WEBAPP_DEPLOYMENT_SPAWN_1,
                                __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return self.rv

        config.pki_log.info(log.WEBAPP_DEPLOYMENT_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        # Create subsystem webapps folder to store custom webapps:
        # <instance>/<subsystem>/webapps.
        deployer.directory.create(
            deployer.mdict['pki_tomcat_subsystem_webapps_path'])

        # set ownerships, permissions, and acls
        deployer.directory.set_mode(
            deployer.mdict['pki_tomcat_subsystem_webapps_path'])

        # Deploy web application directly from /usr/share/pki.
        deployer.deploy_webapp(
            deployer.mdict['pki_subsystem'].lower(),
            os.path.join(
                config.PKI_DEPLOYMENT_SOURCE_ROOT,
                deployer.mdict['pki_subsystem'].lower(),
                "webapps",
                deployer.mdict['pki_subsystem'].lower()),
            os.path.join(
                config.PKI_DEPLOYMENT_SOURCE_ROOT,
                deployer.mdict['pki_subsystem'].lower(),
                "conf",
                "Catalina",
                "localhost",
                deployer.mdict['pki_subsystem'].lower() + ".xml"))

        return self.rv

    def destroy(self, deployer):
        config.pki_log.info(log.WEBAPP_DEPLOYMENT_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        # Delete <instance>/conf/Catalina/localhost/<subsystem>.xml
        deployer.file.delete(
            os.path.join(
                deployer.mdict['pki_instance_configuration_path'],
                "Catalina",
                "localhost",
                deployer.mdict['pki_subsystem'].lower() + ".xml"))

        return self.rv
