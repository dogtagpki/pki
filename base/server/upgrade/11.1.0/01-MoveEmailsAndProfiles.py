#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
import logging
import os
import shutil

import pki.server.upgrade

logger = logging.getLogger(__name__)


class MoveEmailsAndProfiles(
        pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(MoveEmailsAndProfiles, self).__init__()
        self.message = 'Move emails and profiles'

    def upgrade_subsystem(self, instance, subsystem):

        if subsystem.name != 'ca':
            return

        old_emails = os.path.join(instance.base_dir, 'ca', 'emails')
        new_emails = os.path.join(instance.conf_dir, 'ca', 'emails')

        if not os.path.islink(old_emails):

            logger.info('Moving %s to %s', old_emails, new_emails)

            self.backup(old_emails)

            shutil.move(old_emails, new_emails)
            instance.symlink(new_emails, old_emails)

        old_profiles = os.path.join(instance.base_dir, 'ca', 'profiles')
        new_profiles = os.path.join(instance.conf_dir, 'ca', 'profiles')

        if not os.path.islink(old_profiles):

            logger.info('Moving %s to %s', old_profiles, new_profiles)

            self.backup(old_profiles)

            shutil.move(old_profiles, new_profiles)
            instance.symlink(new_profiles, old_profiles)
