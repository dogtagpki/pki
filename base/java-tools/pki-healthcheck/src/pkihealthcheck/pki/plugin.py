#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
#

from ipahealthcheck.core.plugin import Plugin, Registry
from pki.server.instance import PKIInstance


class CSPlugin(Plugin):
    def __init__(self, registry):
        super(CSPlugin, self).__init__(registry)
        # TODO: Support custom instance names
        self.instance = PKIInstance('pki-tomcat')


class CSRegistry(Registry):
    def initialize(self, framework):
        pass


registry = CSRegistry()
