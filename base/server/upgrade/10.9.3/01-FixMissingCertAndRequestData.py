# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import absolute_import
import logging

import pki

logger = logging.getLogger(__name__)


class FixMissingCertAndRequestData(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(FixMissingCertAndRequestData, self).__init__()
        self.message = 'Fix missing SSL server and subsystem cert/request data'

    def upgrade_instance(self, instance):

        subsystems = instance.get_subsystems()

        # there should be at least a source and a target
        if len(subsystems) < 2:
            return

        logger.info('Finding a subsystem that has the cert/request data')
        source = self.find_source_subsystem(subsystems)

        # fix all subsystems other than the source
        for subsystem in subsystems:

            if subsystem.name == source.name:
                continue

            logger.info('Importing cert/request data into %s subsystem', subsystem.name)
            self.backup(subsystem.cs_conf)

            subsystem.config['%s.sslserver.cert' % subsystem.name] = \
                source.config['%s.sslserver.cert' % source.name]

            subsystem.config['%s.subsystem.cert' % subsystem.name] = \
                source.config['%s.subsystem.cert' % source.name]

            subsystem.config['%s.sslserver.certreq' % subsystem.name] = \
                source.config['%s.sslserver.certreq' % source.name]

            subsystem.config['%s.subsystem.certreq' % subsystem.name] = \
                source.config['%s.subsystem.certreq' % source.name]

            subsystem.save()

    def find_source_subsystem(self, subsystems):

        # check each subsystem
        for subsystem in subsystems:

            if not subsystem.config.get('%s.sslserver.cert' % subsystem.name):
                continue

            if not subsystem.config.get('%s.subsystem.cert' % subsystem.name):
                continue

            if not subsystem.config.get('%s.sslserver.certreq' % subsystem.name):
                continue

            if not subsystem.config.get('%s.subsystem.certreq' % subsystem.name):
                continue

            # if the subsystem has the cert/request data, use it as the source
            return subsystem

        raise Exception('Unable to find source subsystem')
