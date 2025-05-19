#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import json
import subprocess

from mcp.server.fastmcp import FastMCP

mcp = FastMCP('pki-server')

@mcp.tool()
def find_users(subsystem: str) -> str:
    '''Find subsystem users'''

    subsystem = subsystem.lower()

    result = subprocess.run([
        'pki-server',
        '{}-user-find'.format(subsystem)
    ], capture_output=True)

    return result.stdout

if __name__ == '__main__':
    mcp.run(transport='stdio')
