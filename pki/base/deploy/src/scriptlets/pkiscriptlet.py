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
import abc


# PKI Deployment Classes
class AbstractBasePkiScriptlet(object):
    __metaclass__ = abc.ABCMeta

    @abc.abstractmethod
    def spawn(self):
        """Retrieve data from the specified dictionaries and
           use it to install a new PKI instance."""
        return

    @abc.abstractmethod
    def respawn(self):
        """Retrieve data from the specified dictionaries and
           use it to update an existing PKI instance."""
        return

    @abc.abstractmethod
    def destroy(self):
        """Retrieve data from the specified dictionaries and
           use it to destroy an existing PKI instance."""
        return

