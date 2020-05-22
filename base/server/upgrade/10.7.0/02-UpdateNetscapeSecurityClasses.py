#!/usr/bin/python

# Authors:
#     Alexander Scheel <ascheel@redhat.com>
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

import pki


class UpdateNetscapeSecurityClasses(
        pki.server.upgrade.PKIServerUpgradeScriptlet):

    PROPERTIES = [
        "oidmap.auth_info_access.class",
        "oidmap.extended_key_usage.class",
        "oidmap.netscape_comment.class",
        "oidmap.ocsp_no_check.class",
        "oidmap.pse.class",
        "oidmap.subject_info_access.class"
    ]

    NEW_PREFIX = "org.mozilla.jss."

    def __init__(self):
        super(UpdateNetscapeSecurityClasses, self).__init__()
        self.message = 'Update netscape.security class references'

    def upgrade_subsystem(self, instance, subsystem):
        self.backup(subsystem.cs_conf)

        for prop_name in self.PROPERTIES:
            value = subsystem.config.get(prop_name)
            if not value or value.startswith(self.NEW_PREFIX):
                continue

            subsystem.config[prop_name] = self.NEW_PREFIX + value

        subsystem.save()
