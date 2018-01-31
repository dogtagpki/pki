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
import os
import pprint

from pki.server.deployment import pkiconfig as config

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
def enable_pki_logger(log_dir, log_name, log_level, console_log_level, name):

    if not os.path.isdir(log_dir):
        os.makedirs(log_dir)

    # Configure console handler
    console = logging.StreamHandler()
    console.setLevel(console_log_level)
    console_format = logging.Formatter('%(name)-12s: ' +
                                       '%(levelname)-8s ' +
                                       '%(indent)s%(message)s')
    console.setFormatter(console_format)

    # Configure file handler
    log_file = logging.FileHandler(log_dir + "/" + log_name, 'w')
    log_file.setLevel(log_level)
    file_format = logging.Formatter('%(asctime)s %(name)-12s: ' +
                                    '%(levelname)-8s ' +
                                    '%(indent)s%(message)s',
                                    '%Y-%m-%d %H:%M:%S')
    log_file.setFormatter(file_format)

    # Configure pkispawn/pkidestroy logger
    config.pki_log = logging.getLogger(name)
    config.pki_log.setLevel(log_level)
    config.pki_log.addHandler(console)
    config.pki_log.addHandler(log_file)

    # Configure pki logger
    logger = logging.getLogger('pki')
    logger.setLevel(log_level)
    logger.addHandler(console)
    logger.addHandler(log_file)
