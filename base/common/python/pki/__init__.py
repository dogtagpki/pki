#!/usr/bin/python
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
# Copyright (C) 2013 Red Hat, Inc.
# All rights reserved.
#
"""
This module contains top-level classes and functions used by the Dogtag project.
"""
from __future__ import absolute_import
from __future__ import print_function

from functools import wraps
import os
import re
import sys

import requests
from six.moves import input   # pylint: disable=W0622,F0401
import six


CONF_DIR = '/etc/pki'
SHARE_DIR = '/usr/share/pki'
BASE_DIR = '/var/lib'
LOG_DIR = '/var/log/pki'

PACKAGE_VERSION = SHARE_DIR + '/VERSION'
CERT_HEADER = "-----BEGIN CERTIFICATE-----"
CERT_FOOTER = "-----END CERTIFICATE-----"


def read_text(message,
              options=None, default=None, delimiter=':',
              allow_empty=True, case_sensitive=True):
    """
    Get an input from the user. This is used, for example, in
    pkispawn and pkidestroy to obtain user input.

    :param message: prompt to display to the user
    :type message: str
    :param options: list of possible inputs by the user.
    :type options: list
    :param default: default value of parameter being prompted.
    :type default: str
    :param delimiter: delimiter to be used at the end of the prompt.
    :type delimiter: str
    :param allow_empty: Allow input to be empty.
    :type allow_empty: boolean -- True/False
    :param case_sensitive: Allow input to be case sensitive.
    :type case_sensitive: boolean -- True/False
    :returns: str -- value obtained from user input.
    """
    if default:
        message = message + ' [' + default + ']'
    message = message + delimiter + ' '

    done = False
    value = None
    while not done:
        value = input(message)
        value = value.strip()

        if len(value) == 0:  # empty value
            if allow_empty:
                value = default
                break

        else:  # non-empty value
            if options is not None:
                for val in options:
                    if case_sensitive:
                        if val == value:
                            done = True
                            break
                    else:
                        if val.lower() == value.lower():
                            done = True
                            break
            else:
                break

    return value


def implementation_version():
    """
    Return implementation version.

    :returns: str --implementation version
    """
    with open(PACKAGE_VERSION, 'r') as input_file:
        for line in input_file:
            line = line.strip('\n')

            # parse <key>: <value>
            match = re.match(r'^\s*(\S*)\s*:\s*(.*)\s*$', line)

            if not match:
                continue

            key = match.group(1)
            value = match.group(2)

            if key.lower() != 'implementation-version':
                continue

            return value

    raise Exception('Missing implementation version.')


# pylint: disable=R0903
class Attribute(object):
    """
    Class representing a key/value pair.

    This object is the basis of the representation of a ResourceMessage.
    """

    def __init__(self, name, value):
        """ Constructor """
        self.name = name
        self.value = value


# pylint: disable=R0903
class AttributeList(object):
    """
    Class representing a list of attributes.

    This class is needed because of a JavaMapper used in the REST API.
    """

    # pylint: disable=C0103
    def __init__(self):
        """ Constructor """
        self.Attribute = []


class ResourceMessage(object):
    """
    This class is the basis for the various types of key requests.
    It is essentially a list of attributes.
    """

    # pylint: disable=C0103
    def __init__(self, class_name):
        """ Constructor """
        self.Attributes = AttributeList()
        self.ClassName = class_name

    def add_attribute(self, name, value):
        """
        Add an attribute to the list.

        :param name: name of attribute to add
        :type name: str
        :param value: value to add
        :type value: str
        :returns: None
        """
        attr = Attribute(name, value)
        self.Attributes.Attribute.append(attr)

    def get_attribute_value(self, name):
        """
        Get the value of a given attribute.

        :param name: name of attribute to retrieve
        :type name: str
        :returns: str -- value of parameter
        """
        for attr in self.Attributes.Attribute:
            if attr.name == name:
                return attr.value
        return None


class PKIException(Exception, ResourceMessage):
    """
    Base exception class for REST Interface
    """

    def __init__(self, message, exception=None, code=None, class_name=None):
        """ Constructor """
        Exception.__init__(self, message)
        ResourceMessage.__init__(self, class_name)
        self.code = code
        self.message = message
        self.exception = exception

    @classmethod
    def from_json(cls, json_value):
        """
        Construct PKIException from JSON.
        :param json_value: JSON representation of the exception.
        :type json_value: str
        :return: pki.PKIException
        """
        ret = cls(
            message=json_value['Message'],
            code=json_value['Code'],
            class_name=json_value['ClassName']
        )
        for attr in json_value['Attributes']['Attribute']:
            ret.add_attribute(attr["name"], attr["value"])
        return ret


class BadRequestException(PKIException):
    """ Bad Request Exception: return code = 400 """


class ConflictingOperationException(PKIException):
    """ Conflicting Operation Exception: return code = 409 """


class ForbiddenException(PKIException):
    """ Forbidden Exception: return code = 403 """


class HTTPGoneException(PKIException):
    """ Gone Exception: return code = 410 """


class ResourceNotFoundException(PKIException):
    """ Not Found Exception: return code = 404 """


class UnauthorizedException(PKIException):
    """ Unauthorized Exception: return code = 401 """


class CertNotFoundException(ResourceNotFoundException):
    """ Cert Not Found Exception: return code = 404 """


class GroupNotFoundException(ResourceNotFoundException):
    """ Group Not Found Exception: return code = 404 """


class KeyNotFoundException(ResourceNotFoundException):
    """ Key Not Found Exception: return code 404 """


class ProfileNotFoundException(ResourceNotFoundException):
    """ Profile Not Found Exception: return code = 404 """


class RequestNotFoundException(ResourceNotFoundException):
    """ Request Not Found Exception: return code = 404 """


class UserNotFoundException(ResourceNotFoundException):
    """ User Not Found Exception: return code = 404 """

"""
Mapping from Java Server exception classes to python exception classes
"""
EXCEPTION_MAPPINGS = {
    "com.netscape.certsrv.base.BadRequestException": BadRequestException,
    "com.netscape.certsrv.base.ConflictingOperationException":
        ConflictingOperationException,
    "com.netscape.certsrv.base.ForbiddenException": ForbiddenException,
    "com.netscape.certsrv.base.HTTPGoneException": HTTPGoneException,
    "com.netscape.certsrv.base.ResourceNotFoundException":
        ResourceNotFoundException,
    "com.netscape.certsrv.cert.CertNotFoundException": CertNotFoundException,
    "com.netscape.certsrv.group.GroupNotFoundException": GroupNotFoundException,
    "com.netscape.certsrv.key.KeyNotFoundException": KeyNotFoundException,
    "com.netscape.certsrv.profile.ProfileNotFoundException":
        ProfileNotFoundException,
    "com.netscape.certsrv.request.RequestNotFoundException":
        RequestNotFoundException,
    "com.netscape.certsrv.base.UserNotFoundException": UserNotFoundException,
    "com.netscape.certsrv.base.PKIException": PKIException}


def handle_exceptions():
    """ Decorator handling exceptions from REST methods. """

    def exceptions_decorator(fn_call):
        """ The actual decorator handler."""

        @wraps(fn_call)
        def handler(inst, *args, **kwargs):
            """ Decorator to catch and re-throw PKIExceptions."""
            try:
                return fn_call(inst, *args, **kwargs)
            except requests.exceptions.HTTPError:
                # store exception information. json may raise another
                # exception. We want to re-raise the HTTPError.
                exc_type, exc_val, exc_tb = sys.exc_info()
                try:
                    json = exc_val.response.json()
                except ValueError:
                    # json raises ValueError. simplejson raises
                    # JSONDecodeError, which is a subclass of ValueError.
                    # re-raise original exception
                    six.reraise(exc_type, exc_val, exc_tb)
                else:
                    # clear reference cycle
                    exc_type = exc_val = exc_tb = None
                    clazz = json.get('ClassName')
                    if clazz and clazz in EXCEPTION_MAPPINGS:
                        exception_class = EXCEPTION_MAPPINGS[clazz]
                        pki_exception = exception_class.from_json(json)
                        raise pki_exception

        return handler

    return exceptions_decorator


class PropertyFile(object):
    """
    Class to manage property files  The contents of the property file
    are maintained internally as a list of properties.

    Properties are strings of the format <name> <delimiter> <value> where
    '=' is the default delimiter.
    """

    def __init__(self, filename, delimiter='='):
        """ Constructor """
        self.filename = filename
        self.delimiter = delimiter

        self.lines = []

    def read(self):
        """
        Read from property file into the list of properties
        maintained by this object.

        :return: None
        """
        self.lines = []

        if not os.path.exists(self.filename):
            return

        # read all lines and preserve the original order
        with open(self.filename, 'r') as f_in:
            for line in f_in:
                line = line.strip('\n')
                self.lines.append(line)

    def write(self):
        """
        Write the list of properties maintained by this object
        to the property file.

        :return: None
        """
        # write all lines in the original order
        with open(self.filename, 'w') as f_out:
            for line in self.lines:
                f_out.write(line + '\n')

    def show(self):
        """
        Print the contents of the list of properties maintained by this object
        to STDOUT.

        :return: None
        """
        for line in self.lines:
            print(line)

    def insert_line(self, index, line):
        """
        Insert property into the list of properties maintained by this object
        at the specified location (index).

        :param index: point at which to insert value.
        :type index: int
        :param line: value to be inserted.
        :type line: str
        :return: None
        """
        self.lines.insert(index, line)

    def remove_line(self, index):
        """
        Remove property at specified index from the properties list.

        :param index: location of property to be removed.
        :type index: int
        :return: None
        """
        self.lines.pop(index)

    def index(self, name):
        """
        Find the index (position) of a property in a property file.

        :param name: name of property
        :type name: str
        :return: int -- index of property.
        """
        for i, line in enumerate(self.lines):

            # parse <key> <delimiter> <value>
            match = re.match(r'^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter,
                             line)

            if not match:
                continue

            key = match.group(1)

            if key.lower() == name.lower():
                return i

        return -1

    def get(self, name):
        """
        Get the value of the specified property.

        :param name: name of property to be fetched.
        :type name: str
        :return: str -- value of property
        """
        result = None

        for line in self.lines:

            # parse <key> <delimiter> <value>
            match = re.match(r'^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter,
                             line)

            if not match:
                continue

            key = match.group(1)
            value = match.group(2)

            if key.lower() == name.lower():
                return value

        return result

    def set(self, name, value, index=None):
        """
        Set value of specified property.

        :param name: name of property to set.
        :type name: str
        :param value: value to set
        :type value: str
        :param index: (optional) position of property
        :type index: int
        :return: None
        """
        for i, line in enumerate(self.lines):

            # parse <key> <delimiter> <value>
            match = re.match(r'^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter,
                             line)

            if not match:
                continue

            key = match.group(1)

            if key.lower() == name.lower():
                self.lines[i] = key + self.delimiter + value
                return

        if index is None:
            self.lines.append(name + self.delimiter + value)

        else:
            self.insert_line(index, name + self.delimiter + value)

    def remove(self, name):
        """
        Remove property from list of properties maintained by this object.

        :param name: name of property to be removed.
        :type name: str
        :returns: None
        """
        for i, line in enumerate(self.lines):

            # parse <key> <delimiter> <value>
            match = re.match(r'^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter,
                             line)

            if not match:
                continue

            key = match.group(1)
            value = match.group(2)

            if key.lower() == name.lower():
                self.lines.pop(i)
                return value

        return None


class Link(object):
    """
        Stores the information of the  resteasy's Link object sent by the server
        for a resource.
    """

    def __init__(self):
        pass

    @classmethod
    def from_json(cls, attr_list):
        """
        Generate Link from JSON

        :param attr_list: JSON representation of Link
        :type attr_list: str
        :return: pki.Link
        """
        if attr_list is None:
            return None

        link = cls()
        for attr in attr_list:
            setattr(link, attr, attr_list[attr])
        return link
