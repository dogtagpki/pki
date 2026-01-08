# Authors:
#     Marco Fargetta <mfargett@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os
import pki


class UpdateJDKFIPS(pki.server.upgrade.PKIServerUpgradeScriptlet):
    msg = "# Adding -Dredhat.crypto-policies=false for JDK>=25 as "\
          "SunJSSE+SunPKCS11 conflicts with JSS\n"

    def __init__(self):
        super(UpdateJDKFIPS, self).__init__()
        self.message = 'Set -Dredhat.crypto-policies=false in Tomcat configuration'

    def upgrade_instance(self, instance):
        self.fix_tomcat_config(instance.tomcat_conf)
        self.fix_tomcat_config('/etc/sysconfig/%s' % instance.name)

    def fix_tomcat_config(self, filename):
        if not os.path.exists(filename):
            logging.debug("Unknown file: %s", filename)
            return

        with open(filename, 'r', encoding='utf-8') as in_fp:
            lines = in_fp.readlines()

        with open(filename, 'w', encoding='utf-8') as out_fp:
            for line in lines:
                if 'JAVA_OPTS="' in line and 'redhat.crypto-policies' not in line:
                    out_fp.write(self.msg)
                    line = line.replace(
                        'JAVA_OPTS="',
                        'JAVA_OPTS="-Dredhat.crypto-policies=false ',
                        1
                    )

                out_fp.write(line)
