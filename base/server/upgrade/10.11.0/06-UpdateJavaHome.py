#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
import logging
import os

import pki

logger = logging.getLogger(__name__)


class UpdateJavaHome(pki.server.upgrade.PKIServerUpgradeScriptlet):

    def __init__(self):
        super(UpdateJavaHome, self).__init__()
        self.message = 'Update JAVA_HOME in service configuration files'

    def upgrade_instance(self, instance):

        # When JAVA_HOME in the Tomcat service config differs from the
        # value in /usr/share/pki/etc/pki.conf, update the value in
        # the service config.

        if 'JAVA_HOME' not in os.environ or not os.environ['JAVA_HOME']:
            raise Exception('Missing JAVA_HOME environment variable')

        java_home = os.environ['JAVA_HOME']

        # Updating /etc/sysconfig/<instance>
        logger.info('Updating %s', instance.service_conf)
        self.backup(instance.service_conf)

        result = self.update_java_home(instance.service_conf, java_home)
        self.store_config(instance.service_conf, result)

        # Updating /var/lib/pki/<instance>/conf/tomcat.conf
        logger.info('Updating %s', instance.tomcat_conf)
        self.backup(instance.tomcat_conf)

        result = self.update_java_home(instance.tomcat_conf, java_home)
        self.store_config(instance.tomcat_conf, result)

    def update_java_home(self, path, java_home):
        result = []

        with open(path, 'r', encoding='utf-8') as f:
            for line in f:

                if not line.startswith('JAVA_HOME='):
                    result.append(line)
                    continue

                new_line = 'JAVA_HOME="%s"\n' % java_home
                result.append(new_line)

        return result

    def store_config(self, path, output):
        with open(path, 'w', encoding='utf-8') as f:
            for line in output:
                print(line, end='', file=f)
