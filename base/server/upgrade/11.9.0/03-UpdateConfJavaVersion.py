#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
import logging
import re

import pki
logger = logging.getLogger(__name__)


class UpdateConfJavaVersion(pki.server.upgrade.PKIServerUpgradeScriptlet):
    def __init__(self):
        super().__init__()
        self.message = "Update Conf Java Version"

    def upgrade_instance(self, instance):

        # Getting correct JAVA_HOME version from /usr/share/pki/etc/pki.conf
        pki_conf_path = instance.SHARE_DIR + "/etc/pki.conf"
        logger.info("Pulling JAVA_HOME version from %s", pki_conf_path)
        java_home = self.get_java_version(pki_conf_path)

        # Updating /etc/pki/<instance>/tomcat.conf
        logger.info("Updating %s", instance.tomcat_conf)
        self.backup(instance.tomcat_conf)
        self.update_conf_java_version(instance.tomcat_conf, java_home)

    def get_java_version(self, path):
        java_home = ''
        try:
            with open(path, 'r', encoding='utf-8') as f:
                for line in f:
                    if line.startswith('JAVA_HOME='):
                        java_home = line.strip().replace('JAVA_HOME=', 'JAVA_HOME=\"')
                        java_home = java_home + "\""
                        return java_home
        except FileNotFoundError:
            logger.error("Error: The file %s was not found", path)

        logger.error("JAVA_HOME was not found in %s", path)
        raise ValueError(f"JAVA_HOME was not found in {path}")

    def update_conf_java_version(self, path, java_version):
        conf_file = []
        with open(path, 'r', encoding="utf-8") as f:
            conf_file = f.read()

        conf_file = re.sub('^JAVA_HOME=.*', java_version, conf_file)

        with open(path, "w", encoding="utf-8") as f:
            f.write(conf_file)
