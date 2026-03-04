# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import logging
import os

import pki.server
import pki.server.upgrade

logger = logging.getLogger(__name__)


class FixPerms(pki.server.upgrade.PKIServerUpgradeScriptlet):
    """
    Fix directory permissions for instances to reflect tomcat 10 fresh install.
    """

    def __init__(self):
        super().__init__()
        self.message = 'Fix directory permissions'

    def fix_permissions(self, instance, path, target_mode, description):
        """
        Fix permissions and ownership for a given path.
        """
        if not os.path.exists(path):
            logger.debug('%s does not exist: %s', description, path)
            return

        logger.debug('Updating instance: %s %s: %s', instance.name, description, path)
        logger.debug('Setting mode: %o', target_mode)

        os.chmod(path, target_mode)

    def upgrade_instance(self, instance):
        """
        Update directory permissions to match fresh installs.
        """

        # List of paths to fix with their target permissions
        paths_to_fix = [
            (instance.webapps_dir, pki.server.DEFAULT_DIR_MODE, 'Webapps directory'),
            # Add more paths here as needed, for example:
            # (instance.work_dir, 0o770, 'Work directory'),
        ]

        for path, target_mode, description in paths_to_fix:
            self.fix_permissions(instance, path, target_mode, description)
