#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import logging

import pki

logger = logging.getLogger(__name__)


class DisableJavaSecurityManager(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super().__init__()
        self.message = 'Disable Java Security Manager'

    def upgrade_instance(self, instance):

        # Updating /etc/sysconfig/<instance>
        logger.info('Updating %s', instance.service_conf)
        self.backup(instance.service_conf)

        result = self.disable_java_security_manager(instance.service_conf)
        self.store_config(instance.service_conf, result)

        # Updating /var/lib/pki/<instance>/conf/tomcat.conf
        logger.info('Updating %s', instance.tomcat_conf)
        self.backup(instance.tomcat_conf)

        result = self.disable_java_security_manager(instance.tomcat_conf)
        self.store_config(instance.tomcat_conf, result)

    def disable_java_security_manager(self, path):
        result = []

        with open(path, 'r', encoding='utf-8') as f:
            for line in f:

                if line.startswith('SECURITY_MANAGER='):
                    line = 'SECURITY_MANAGER="false"\n'

                elif line.startswith('TOMCAT_SECURITY='):
                    line = 'TOMCAT_SECURITY="false"\n'

                result.append(line)

        return result

    def store_config(self, path, output):
        with open(path, 'w', encoding='utf-8') as f:
            for line in output:
                print(line, end='', file=f)
