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

import pki.server

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkimessages as log
from .. import pkiscriptlet


# PKI Deployment Slot Substitution Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    def spawn(self, deployer):

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            config.pki_log.info(log.SKIP_SLOT_ASSIGNMENT_SPAWN_1, __name__,
                                extra=config.PKI_INDENTATION_LEVEL_1)
            return

        config.pki_log.info(log.SLOT_ASSIGNMENT_SPAWN_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)

        instance = pki.server.PKIInstance(deployer.mdict['pki_instance_name'])
        instance.load()

        subsystem = instance.get_subsystem(deployer.mdict['pki_subsystem'].lower())

        # Configure internal database parameters.

        subsystem.config['internaldb.ldapconn.host'] = deployer.mdict['pki_ds_hostname']

        subsystem.config['internaldb.ldapconn.secureConn'] = \
            deployer.mdict['pki_ds_secure_connection'].lower()

        if config.str2bool(deployer.mdict['pki_ds_secure_connection']):
            subsystem.config['internaldb.ldapconn.port'] = \
                deployer.mdict['pki_ds_secure_connection']
        else:
            subsystem.config['internaldb.ldapconn.port'] = \
                deployer.mdict['pki_ds_ldap_port']

        subsystem.config['internaldb.basedn'] = deployer.mdict['pki_ds_base_dn']
        subsystem.config['internaldb.ldapauth.bindDN'] = deployer.mdict['pki_ds_bind_dn']
        subsystem.config['internaldb.database'] = deployer.mdict['pki_ds_database']

        subsystem.config['preop.database.removeData'] = \
            deployer.mdict['pki_ds_remove_data'].lower()

        subsystem.config['preop.database.createNewDB'] = \
            deployer.mdict['pki_ds_create_new_db'].lower()

        subsystem.config['preop.database.setupReplication'] = \
            deployer.mdict['pki_clone_setup_replication'].lower()

        subsystem.config['preop.database.reindexData'] = \
            deployer.mdict['pki_clone_reindex_data'].lower()

        subsystem.save()

    def destroy(self, deployer):
        config.pki_log.info(log.SLOT_ASSIGNMENT_DESTROY_1, __name__,
                            extra=config.PKI_INDENTATION_LEVEL_1)
        config.pki_log.info("NOTHING NEEDS TO BE IMPLEMENTED",
                            extra=config.PKI_INDENTATION_LEVEL_2)
