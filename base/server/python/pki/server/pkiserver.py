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

import logging
import subprocess
import sys
import traceback

import pki.server.cli

logger = logging.getLogger(__name__)


if __name__ == '__main__':

    logging.basicConfig(format='%(levelname)s: %(message)s')

    cli = pki.server.cli.PKIServerCLI()

    try:
        cli.create_parser()

        # exclude script name
        cli.execute(sys.argv[1:])

    except KeyboardInterrupt as e:

        if logger.isEnabledFor(logging.INFO):
            logger.exception(e)

        sys.exit(1)

    except subprocess.CalledProcessError as e:

        if logger.isEnabledFor(logging.DEBUG):
            traceback.print_exc()

        if e.stderr:
            print(e.stderr.decode().strip(), file=sys.stderr)

        sys.exit(e.returncode)

    except pki.cli.CLIException as e:
        logger.error(str(e))

    except Exception as e:  # pylint: disable=broad-except

        logger.exception(e)
        sys.exit(1)
