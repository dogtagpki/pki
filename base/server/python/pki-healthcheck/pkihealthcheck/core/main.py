#
# Copyright (C) 2019 FreeIPA Contributors see COPYING for license
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
