# Authors:
#     Rob Crittenden <rcrit@redhat.com>
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import logging
import sys

from ipahealthcheck.core.core import RunChecks

logging.basicConfig(format='%(message)s')
logger = logging.getLogger()


def main():
    checks = RunChecks(['pkihealthcheck.registry'],
                       '/etc/pki/pki-healthcheck.conf')
    sys.exit(checks.run_healthcheck())
