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
