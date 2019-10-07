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
#

from __future__ import absolute_import

import os
import pki


class RemoveLDAPSetupFiles(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(RemoveLDAPSetupFiles, self).__init__()
        self.message = 'Remove LDAP setup files from instance folder'

    def upgrade_instance(self, instance):

        schema_authority_ldif = os.path.join(instance.conf_dir, 'schema-authority.ldif')
        if os.path.exists(schema_authority_ldif):
            self.backup(schema_authority_ldif)
            pki.util.remove(schema_authority_ldif)

        schema_certProfile_ldif = os.path.join(instance.conf_dir, 'schema-certProfile.ldif')
        if os.path.exists(schema_certProfile_ldif):
            self.backup(schema_certProfile_ldif)
            pki.util.remove(schema_certProfile_ldif)

        usn_ldif = os.path.join(instance.conf_dir, 'usn.ldif')
        if os.path.exists(usn_ldif):
            self.backup(usn_ldif)
            pki.util.remove(usn_ldif)
