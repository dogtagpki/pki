# Authors:
#     Matthew Harmsen <mharmsen@redhat.com>
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
# Copyright (C) 2012 Red Hat, Inc.
# All rights reserved.
#

# System Imports
from __future__ import absolute_import
import logging
import pprint

sensitive_parameters = []

# Initialize 'pretty print' for objects
pp = pprint.PrettyPrinter(indent=4)


def log_format(given_dict):
    new_dict = {}

    # mask sensitive data
    for key in given_dict:
        if key in sensitive_parameters:
            value = 'XXXXXXXX'
        else:
            value = given_dict[key]
        new_dict[key] = value

    return pp.pformat(new_dict)


# PKI Deployment Logging Functions
def enable_pki_logger(filename):

    # Configure console handler
    console = logging.StreamHandler()
    console_format = logging.Formatter('%(levelname)s: %(message)s')
    console.setFormatter(console_format)

    # Configure file handler
    log_file = logging.FileHandler(filename, 'w')
    file_format = logging.Formatter('%(asctime)s %(levelname)s: %(message)s',
                                    '%Y-%m-%d %H:%M:%S')
    log_file.setFormatter(file_format)

    logger = logging.getLogger('pki')
    logger.addHandler(console)
    logger.addHandler(log_file)
