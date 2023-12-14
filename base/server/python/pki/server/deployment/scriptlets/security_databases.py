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
from __future__ import print_function
import logging

import pki.nssdb
import pki.pkcs12
import pki.server
import pki.util

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

        instance = self.instance
        instance.load()

        subsystem = instance.get_subsystem(deployer.subsystem_type.lower())

        if config.str2bool(deployer.mdict['pki_use_pss_rsa_signing_algorithm']):
            deployer.update_rsa_pss_algorithms(subsystem)

        deployer.init_server_nssdb(subsystem)
        deployer.import_server_pkcs12()
        deployer.import_clone_pkcs12()
        deployer.install_cert_chain()
        deployer.import_ds_ca_cert()

        deployer.init_system_cert_params(subsystem)
        subsystem.save()

        deployer.init_client_nssdb()

    def destroy(self, deployer):

        instance = self.instance

        # if this is not the last subsystem, skip
        if instance.get_subsystems():
            return

        if deployer.directory.exists(deployer.mdict['pki_client_dir']):
            logger.info('Removing %s', deployer.mdict['pki_client_dir'])
            pki.util.rmtree(deployer.mdict['pki_client_dir'],
                            deployer.force)

        logger.info('Removing %s', instance.nssdb_dir)
        pki.util.rmtree(instance.nssdb_dir, deployer.force)

        logger.info('Removing %s', instance.password_conf)
        pki.util.remove(instance.password_conf, deployer.force)
