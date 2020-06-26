# Authors:
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

# Temporary workaround to skip VERBOSE data. Fix already pushed to upstream
# freeipa-healthcheck: https://github.com/freeipa/freeipa-healthcheck/pull/126
logging.getLogger().setLevel(logging.WARNING)


class CertsPlugin(Plugin):
    def __init__(self, registry):
        # pylint: disable=redefined-outer-name
        super(CertsPlugin, self).__init__(registry)
        # TODO: Support custom instance names
        self.instance = PKIInstance('pki-tomcat')


class CertsRegistry(Registry):
    def initialize(self, framework, config):
        # Read dogtag specific config values and merge with already existing config
        # before adding it to registry
        merge_dogtag_config(config)

        super(CertsRegistry, self).initialize(framework, config)
        pass


registry = CertsRegistry()
