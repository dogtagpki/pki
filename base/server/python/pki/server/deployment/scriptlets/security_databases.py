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

import logging

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkiscriptlet

logger = logging.getLogger(__name__)


# PKI Deployment Security Databases Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping NSS database creation')
            return

        deployer.import_server_pkcs12()
        deployer.import_clone_pkcs12()
        deployer.install_cert_chain()
        deployer.import_ds_ca_cert()
        deployer.init_client_nssdb()
