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
'''
This module contains top-level classes and functions used by the Dogtag project.
'''
import os
import re
import requests


CONF_DIR = '/etc/pki'
SHARE_DIR = '/usr/share/pki'
BASE_DIR = '/var/lib'
LOG_DIR = '/var/log/pki'

PACKAGE_VERSION = SHARE_DIR + '/VERSION'
CERT_HEADER = "-----BEGIN NEW CERTIFICATE REQUEST-----"
CERT_FOOTER = "-----END NEW CERTIFICATE REQUEST-----"

def read_text(message,
    options=None, default=None, delimiter=':',
    allow_empty=True, case_sensitive=True):
    ''' get an input from the user. '''
    if default:
        message = message + ' [' + default + ']'
    message = message + delimiter + ' '

    done = False
    while not done:
        value = raw_input(message)
        value = value.strip()

        if len(value) == 0:  # empty value
            if allow_empty:
                value = default
                done = True
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
                done = True
                break

    return value


def implementation_version():
    ''' Return implementation version '''
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

class Attribute(object):
    '''
    Class representing a key/value pair.

    This object is the basis of the representation of a ResourceMessage.
    '''

    def __init__(self, name, value):
        ''' Constructor '''
        self.name = name
        self.value = value

class AttributeList(object):
    '''
    Class representing a list of attributes.

    This class is needed because of a JavaMapper used in the REST API.
    '''

    def __init__(self):
        ''' Constructor '''
        self.Attribute = []

class ResourceMessage(object):
    '''
    This class is the basis for the various types of key requests.
    It is essentially a list of attributes.
    '''

    def __init__(self, class_name):
        ''' Constructor '''
        self.Attributes = AttributeList()
        self.ClassName = class_name

    def add_attribute(self, name, value):
        ''' Add an attribute to the list. '''
        attr = Attribute(name, value)
        self.Attributes.Attribute.append(attr)

    def get_attribute_value(self, name):
        ''' Get the value of a given attribute '''
        for attr in self.Attributes.Attribute:
            if attr.name == name:
                return attr.value
        return None

class PKIException(Exception, ResourceMessage):
    '''
    Base exception class for REST Interface
    '''

    def __init__(self, message, exception=None, code=None, class_name=None):
        ''' Constructor '''
        Exception.__init__(self, message)
        ResourceMessage.__init__(self, class_name)
        self.code = code
        self.message = message
        self.exception = exception

    @classmethod
    def from_json(cls, json_value):
        ''' Construct exception from JSON '''
        ret = cls(json_value['Message'], json_value['Code'], json_value['ClassName'])
        for attr in json_value['Attributes']['Attribute']:
            print str(attr)
            ret.add_attribute(attr["name"], attr["value"])
        return ret

class BadRequestException(PKIException):
    ''' Bad Request Exception: return code = 400 '''

class ConflictingOperationException(PKIException):
    ''' Conflicting Operation Exception: return code = 409 '''

class ForbiddenException(PKIException):
    ''' Forbidden Exception: return code = 403 '''

class HTTPGoneException(PKIException):
    ''' Gone Exception: return code = 410 '''

class ResourceNotFoundException(PKIException):
    ''' Not Found Exception: return code = 404 '''

class UnauthorizedException(PKIException):
    ''' Unauthorized Exception: return code = 401 '''

class CertNotFoundException(ResourceNotFoundException):
    ''' Cert Not Found Exception: return code = 404 '''

class GroupNotFoundException(ResourceNotFoundException):
    ''' Group Not Found Exception: return code = 404 '''

class KeyNotFoundException(ResourceNotFoundException):
    ''' Key Not Found Exception: return code 404 '''

class ProfileNotFoundException(ResourceNotFoundException):
    ''' Profile Not Found Exception: return code = 404 '''

class RequestNotFoundException(ResourceNotFoundException):
    ''' Request Not Found Exception: return code = 404 '''

class UserNotFoundException(ResourceNotFoundException):
    ''' User Not Found Exception: return code = 404 '''

EXCEPTION_MAPPINGS = {
    "com.netscape.certsrv.base.BadRequestException": BadRequestException,
    "com.netscape.certsrv.base.ConflictingOperationException": ConflictingOperationException,
    "com.netscape.certsrv.base.ForbiddenException": ForbiddenException,
    "com.netscape.certsrv.base.HTTPGoneException": HTTPGoneException,
    "com.netscape.certsrv.base.ResourceNotFoundException": ResourceNotFoundException,
    "com.netscape.certsrv.cert.CertNotFoundException": CertNotFoundException,
    "com.netscape.certsrv.group.GroupNotFoundException": GroupNotFoundException,
    "com.netscape.certsrv.key.KeyNotFoundException": KeyNotFoundException,
    "com.netscape.certsrv.profile.ProfileNotFoundException": ProfileNotFoundException,
    "com.netscape.certsrv.request.RequestNotFoundException": RequestNotFoundException,
    "com.netscape.certsrv.base.UserNotFoundException": UserNotFoundException,
    "com.netscape.certsrv.base.PKIException": PKIException}

def handle_exceptions():
    ''' Decorator handling exceptions from REST methods. '''

    def exceptions_decorator(fn_call):
        ''' The actual decorator handler.'''

        def handler(inst, *args, **kwargs):
            ''' Decorator to catch and re-throw PKIExceptions.'''
            try:
                return fn_call(inst, *args, **kwargs)
            except requests.exceptions.HTTPError as exc:
                clazz = exc.response.json()['ClassName']
                if clazz in EXCEPTION_MAPPINGS:
                    exception_class = EXCEPTION_MAPPINGS[clazz]
                    pki_exception = exception_class.from_json(exc.response.json())
                    raise pki_exception
                else:
                    raise exc

        return handler
    return exceptions_decorator


class PropertyFile(object):
    ''' Class to manage property files '''

    def __init__(self, filename, delimiter='='):
        ''' Constructor '''
        self.filename = filename
        self.delimiter = delimiter

        self.lines = []

    def read(self):
        ''' Read from propert file '''
        self.lines = []

        if not os.path.exists(self.filename):
            return

        # read all lines and preserve the original order
        with open(self.filename, 'r') as f:
            for line in f:
                line = line.strip('\n')
                self.lines.append(line)

    def write(self):
        ''' Write to property file '''
        # write all lines in the original order
        with open(self.filename, 'w') as f:
            for line in self.lines:
                f.write(line + '\n')

    def show(self):
        ''' Show contents of property file.'''
        for line in self.lines:
            print line

    def insert_line(self, index, line):
        ''' Insert line in property file '''
        self.lines.insert(index, line)

    def remove_line(self, index):
        ''' Remove line from property file '''
        self.lines.pop(index)

    def index(self, name):
        ''' Find the index (position) of a property in a property file '''
        for i, line in enumerate(self.lines):

            # parse <key> <delimiter> <value>
            match = re.match(r'^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter, line)

            if not match:
                continue

            key = match.group(1)

            if key.lower() == name.lower():
                return i

        return -1

    def get(self, name):
        ''' Get value for specified property '''
        result = None

        for line in self.lines:

            # parse <key> <delimiter> <value>
            match = re.match(r'^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter, line)

            if not match:
                continue

            key = match.group(1)
            value = match.group(2)

            if key.lower() == name.lower():
                return value

        return result

    def set(self, name, value, index=None):
        ''' Set value for specified property '''
        for i, line in enumerate(self.lines):

            # parse <key> <delimiter> <value>
            match = re.match(r'^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter, line)

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
        ''' Remove property from property file '''
        for i, line in enumerate(self.lines):

            # parse <key> <delimiter> <value>
            match = re.match(r'^\s*(\S*)\s*%s\s*(.*)\s*$' % self.delimiter, line)

            if not match:
                continue

            key = match.group(1)
            value = match.group(2)

            if key.lower() == name.lower():
                self.lines.pop(i)
                return value

        return None
