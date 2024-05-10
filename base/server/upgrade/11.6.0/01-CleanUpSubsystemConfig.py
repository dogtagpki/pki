# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os

import pki

logger = logging.getLogger(__name__)


class CleanUpSubsystemConfig(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Clean up subsystem config'

    def upgrade_subsystem(self, instance, subsystem):

        self.backup(subsystem.cs_conf)

        param = '%s.admin.cert' % subsystem.name
        if subsystem.config.get(param):
            logger.info('Removing %s', param)
            subsystem.config.pop(param, None)

        param = '%s.standalone' % subsystem.name
        if subsystem.config.get(param):
            logger.info('Removing %s', param)
            subsystem.config.pop(param, None)

        # remove passwordFile if it contains the default value
        value = subsystem.config.get('passwordFile')
        if value and os.path.realpath(value) == os.path.realpath(instance.password_conf):
            logger.info('Removing passwordFile')
            subsystem.config.pop('passwordFile', None)

        # remove passwordClass if it contains the default value
        value = subsystem.config.get('passwordClass')
        if value == 'com.netscape.cmsutil.password.PlainPasswordFile':
            logger.info('Removing passwordClass')
            subsystem.config.pop('passwordClass', None)

        subsystem.save()
