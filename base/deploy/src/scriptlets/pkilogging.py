#!/usr/bin/python -t
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
import logging
import os
import pprint

sensitive_parameters = []

# Initialize 'pretty print' for objects
pp = pprint.PrettyPrinter(indent=4)

def format(dict):
    new_dict = {}

    # mask sensitive data
    for key in dict:
        if key in sensitive_parameters:
            value = 'XXXXXXXX'
        else:
            value = dict[key]
        new_dict[key] = value

    return pp.pformat(new_dict)

# PKI Deployment Logging Functions
def enable_pki_logger(log_dir, log_name, log_level, console_log_level, logger):
    if not os.path.isdir(log_dir):
        try:
            os.makedirs(log_dir)
        except OSError:
            return OSError

    # Establish 'file' logger using 'basicConfig()'
    logging.LoggerAdapter(logging.getLogger(''), {'indent' : ''})
    logging.basicConfig(level=log_level,
                        format='%(asctime)s %(name)-12s ' +\
                               '%(levelname)-8s ' +\
                               '%(indent)s%(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename=log_dir + "/" + log_name,
                        filemode='w')

    # Establish 'console' logger
    console = logging.StreamHandler()
    logging.LoggerAdapter(console, {'indent' : ''})
    console.setLevel(console_log_level)
    console_format = logging.Formatter('%(name)-12s: ' +\
                                       '%(levelname)-8s ' +\
                                       '%(indent)s%(message)s')
    console.setFormatter(console_format)
    logging.getLogger('').addHandler(console)

    # Establish 'file' logger
#   file = logging.FileHandler(log_dir + "/" + log_name, 'w')
#   logging.LoggerAdapter(file, {'indent' : ''})
#   file.setLevel(log_level)
#   file_format = logging.Formatter('%(asctime)s %(name)-12s: ' +\
#                                   '%(levelname)-8s ' +\
#                                   '%(indent)s%(message)s',
#                                   '%Y-%m-%d %H:%M:%S')
#   file.setFormatter(file_format)
#   logging.getLogger('').addHandler(file)

    return logging.getLogger(logger)
