#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
import logging

import pki.util
import pki.server.upgrade

logger = logging.getLogger(__name__)


class DropTomcatJSSDependency(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Drop Tomcat JSS dependency'

    def upgrade_instance(self, instance):

        logger.info('Updating %s', instance.server_xml)
        self.backup(instance.server_xml)

        server_config = instance.get_server_config()

        for listener in server_config.get_listeners():

            # replace org.dogtagpki.tomcat.JSSListener
            # with org.dogtagpki.jss.tomcat.JSSListener

            if listener.get('className') == 'org.dogtagpki.tomcat.JSSListener':
                listener.set('className', 'org.dogtagpki.jss.tomcat.JSSListener')

        for connector in server_config.get_connectors():

            ssl_enabled = connector.get('SSLEnabled')
            if not ssl_enabled:
                continue

            # replace org.dogtagpki.tomcat.JSSImplementation
            # or org.apache.tomcat.util.net.jss.JSSImplementation
            # with org.dogtagpki.jss.tomcat.JSSImplementation

            if connector.get('sslImplementationName') in [
                    'org.dogtagpki.tomcat.JSSImplementation',
                    'org.apache.tomcat.util.net.jss.JSSImplementation']:
                connector.set(
                    'sslImplementationName',
                    'org.dogtagpki.jss.tomcat.JSSImplementation')

            # replace org.apache.tomcat.util.net.jss.PlainPasswordFile
            # with org.dogtagpki.jss.tomcat.PlainPasswordFile

            if connector.get('passwordClass') == \
                    'org.apache.tomcat.util.net.jss.PlainPasswordFile':
                connector.set(
                    'passwordClass',
                    'org.dogtagpki.jss.tomcat.PlainPasswordFile')

            # replace org.dogtagpki.tomcat.Http11NioProtocol
            # with org.dogtagpki.jss.tomcat.Http11NioProtocol

            if connector.get('protocol') == \
                    'org.dogtagpki.tomcat.Http11NioProtocol':
                connector.set(
                    'protocol',
                    'org.dogtagpki.jss.tomcat.Http11NioProtocol')

        server_config.save()
