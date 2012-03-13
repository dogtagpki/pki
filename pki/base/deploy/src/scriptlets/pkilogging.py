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
# Copyright (C) 2011 Red Hat, Inc.
# All rights reserved.
#

# System Imports
import logging
import os


# PKI Deployment Logging Functions
def enable_pki_logger(log_dir, log_name, log_level, console_log_level, logger):
    if not os.path.isdir(log_dir):
        try:
            os.makedirs(log_dir)
        except OSError:
            return OSError
    logging.basicConfig(level=log_level,
                        format='%(asctime)s %(name)-12s ' +\
                               '%(levelname)-8s %(message)s',
                        datefmt='%Y-%m-%d %H:%M:%S',
                        filename=log_dir + "/" + log_name,
                        filemode='w')
    console = logging.StreamHandler()
    console.setLevel(console_log_level)
    formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(message)s')
    console.setFormatter(formatter)
    logging.getLogger('').addHandler(console)
    return logging.getLogger(logger)

