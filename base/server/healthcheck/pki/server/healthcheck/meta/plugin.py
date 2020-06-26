# Authors:
#     Rob Crittenden <rcrit@redhat.com>
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

from ipahealthcheck.core.plugin import Plugin, Registry
from pki.server.instance import PKIInstance

from pki.server.healthcheck.core.main import merge_dogtag_config

import logging

logging.getLogger().setLevel(logging.WARNING)


class MetaPlugin(Plugin):
    def __init__(self, registry):
        # pylint: disable=redefined-outer-name
        super(MetaPlugin, self).__init__(registry)

        self.instance = PKIInstance(self.config.instance_name)


class MetaRegistry(Registry):
    def initialize(self, framework, config):
        # Read dogtag specific config values and merge with already existing config
        # before adding it to registry
        merge_dogtag_config(config)

        super(MetaRegistry, self).initialize(framework, config)


registry = MetaRegistry()
