# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

from ipahealthcheck.core.plugin import Plugin, Registry
from pki.server.instance import PKIInstance

import logging

logging.getLogger().setLevel(logging.WARNING)


class CertsPlugin(Plugin):
    def __init__(self, registry):
        # pylint: disable=redefined-outer-name
        super(CertsPlugin, self).__init__(registry)
        # TODO: Support custom instance names
        self.instance = PKIInstance('pki-tomcat')


class CertsRegistry(Registry):
    def initialize(self, framework, config):
        pass


registry = CertsRegistry()
