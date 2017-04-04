# This program is free software; you can redistribute it and/or modify
# it under the terms of the Lesser GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#
# Author:
#     Ade Lee <alee@redhat.com>
#
"""
Module containing the Python client classes for the InfoClient
"""
from six import iteritems

import pki


class Info(object):
    """
    This class encapsulates the parameters returned by the server's
    InfoService.
    """

    json_attribute_names = {
        'Version': 'version',
        'Banner': 'banner'
    }

    def __init__(self, version=None, banner=None):
        """ Constructor """
        self.version = version
        self.banner = banner

    @classmethod
    def from_json(cls, attr_list):
        """ Return Info from JSON dict """
        info = cls()
        for k, v in iteritems(attr_list):
            if k in Info.json_attribute_names:
                setattr(info, Info.json_attribute_names[k], v)
            else:
                setattr(info, k, v)
        return info


class Version(object):
    """
    This class encapsulates a version object as returned from
    a Dogtag server and decomposes it into major, minor, etc.
    """

    def __init__(self, version_string):
        for idx, val in enumerate(version_string.split('.')):
            if idx == 0:
                self.major = val
            if idx == 1:
                self.minor = val
            if idx == 2:
                self.patch = val


class InfoClient(object):
    """
    Class encapsulating and mirroring the functionality in the
    InfoResource Java interface class defining the REST API for
    server Info resources.
    """

    def __init__(self, connection):
        """ Constructor """
        self.connection = connection

    @pki.handle_exceptions()
    def get_info(self):
        """ Return an Info object form a PKI server """

        url = '/pki/rest/info'
        headers = {'Content-type': 'application/json',
                   'Accept': 'application/json'}
        r = self.connection.get(url, headers, use_root_uri=True)
        return Info.from_json(r.json())

    @pki.handle_exceptions()
    def get_version(self):
        """ return Version object from server """
        version_string = self.get_info().version
        return Version(version_string)
