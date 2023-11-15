# Authors:
#     Marco Fargetta <mfargett@redhat.com>
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
# Copyright (C) 2023 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
import grp
import logging
import os
import pwd
import subprocess

import pki

# PKI Deployment Imports
from .. import pkiconfig as config
from .. import pkiscriptlet

fapolicy_rules_path = '/etc/fapolicyd/rules.d/'

logger = logging.getLogger(__name__)


# PKI Deployment File Access Policy Setup Scriptlet
class PkiScriptlet(pkiscriptlet.AbstractBasePkiScriptlet):

    # Helper function to restart the fapolicyd after the rules are updated
    def restart_fapolicy_daemon(self):
        stat = subprocess.call(["systemctl", "is-active", "--quiet", "fapolicyd"])
        if (stat == 0):
            logger.info('Restart fapolicyd to update the rules')
            subprocess.call(["systemctl", "restart", "--quiet", "fapolicyd"])

    def spawn(self, deployer):

        instance = self.instance

        if config.str2bool(deployer.mdict['pki_skip_installation']):
            logger.info('Skipping fapolicy setup')
            return

        if not os.path.exists(fapolicy_rules_path):
            logger.info('Fapolicy folder not found. Rule configuration skipped')
            return

        fapolicy_rule_file = os.path.join(
            fapolicy_rules_path,
            '61-pki-{}.rules'.format(instance.name)
        )

        logger.info('Add fapolicy rule for the instance %s', instance.name)

        template = os.path.join(
            pki.server.PKIServer.SHARE_DIR,
            'server',
            'etc',
            'fapolicy.rules')

        params = {
            'WORK_DIR': self.instance.work_dir
        }

        uid = pwd.getpwnam('root').pw_uid
        gid = grp.getgrnam('fapolicyd').gr_gid
        mode = 0o644

        pki.util.copyfile(
            template,
            fapolicy_rule_file,
            params=params,
            uid=uid,
            gid=gid,
            mode=mode,
            force=True)

        self.restart_fapolicy_daemon()

    def destroy(self, deployer):

        instance = self.instance

        fapolicy_rule_file = os.path.join(
            fapolicy_rules_path,
            '61-pki-{}.rules'.format(instance.name)
        )

        if not os.path.exists(fapolicy_rule_file):
            logger.info('Fapolicy custom rules for the instance %s not found.',
                        instance.name)
            return

        logger.info('Removing fapolicy rules for the instance %s.',
                    instance.name)
        os.remove(fapolicy_rule_file)

        self.restart_fapolicy_daemon()
