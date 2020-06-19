# Authors:
#     Alexander Scheel <ascheel@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

from __future__ import absolute_import

import logging
import os
import pki


class DisableOpenJDKFIPS(pki.server.upgrade.PKIServerUpgradeScriptlet):
    msg = "# Adding -Dcom.redhat.fips=false as SunJSSE+SunPKCS11 conflicts with JSS\n"

    def __init__(self):
        super(DisableOpenJDKFIPS, self).__init__()
        self.message = 'Set -Dcom.redhat.fips=false in Tomcat configuration'

    def upgrade_instance(self, instance):
        self.fix_tomcat_config('/etc/pki/%s/tomcat.conf' % instance.name)
        self.fix_tomcat_config('/etc/sysconfig/%s' % instance.name)

    def fix_tomcat_config(self, filename):
        if not os.path.exists(filename):
            logging.debug("Unknown file: %s", filename)

        with open(filename, 'r') as in_fp:
            lines = in_fp.readlines()

        with open(filename, 'w') as out_fp:
            for line in lines:
                if 'JAVA_OPTS="' in line and 'com.redhat.fips' not in line:
                    out_fp.write(self.msg)
                    line = line.replace('JAVA_OPTS="', 'JAVA_OPTS="-Dcom.redhat.fips=false ', 1)

                out_fp.write(line)
