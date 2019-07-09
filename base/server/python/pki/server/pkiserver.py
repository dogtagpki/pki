# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; version 2 of the License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function
import logging
import subprocess
import sys
import traceback

import pki.server.cli


if __name__ == '__main__':

    logging.basicConfig(format='%(levelname)s: %(message)s')

    cli = pki.server.cli.PKIServerCLI()

    try:
        cli.execute(sys.argv)

    except KeyboardInterrupt:
        if logging.getLogger().isEnabledFor(logging.INFO):
            traceback.print_exc()
        sys.exit(1)

    except subprocess.CalledProcessError as e:
        if logging.getLogger().isEnabledFor(logging.INFO):
            traceback.print_exc()
        logging.error('Command: %s', ' '.join(e.cmd))
        sys.exit(e.returncode)

    except Exception as e:  # pylint: disable=broad-except
        if logging.getLogger().isEnabledFor(logging.INFO):
            traceback.print_exc()
        logging.error(e)
        sys.exit(1)
