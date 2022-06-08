# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
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
"""
This module contains top-level classes and functions used by the Dogtag project.
"""
from __future__ import absolute_import
from __future__ import print_function

from functools import wraps
import cryptography.x509
import ldap.dn
import logging
import os
import random
import re
import string
import subprocess
import sys

import requests
import six


CONF_DIR = '/etc/pki'
SHARE_DIR = '/usr/share/pki'
BASE_DIR = '/var/lib'
LOG_DIR = '/var/log/pki'

PACKAGE_VERSION = SHARE_DIR + '/VERSION'
CERT_HEADER = "-----BEGIN CERTIFICATE-----"
CERT_FOOTER = "-----END CERTIFICATE-----"

# Valid punctuation characters for random password.
# This is based on string.punctuation except:
#  - equal sign since it's used as delimiter in password.conf
#  - backslash since it's causing SSL handshake failure
#  - it should be relatively safe in an XML attribute
PUNCTUATIONS = '!#*+,-./:;^_|~'
GEN_PASS_CHARSET = string.digits + string.ascii_lowercase + string.ascii_uppercase + PUNCTUATIONS

# Map X.509 attribute OID to its short name.
# See also:
# - https://github.com/pyca/cryptography/blob/master/src/cryptography/x509/name.py
# - https://github.com/freeipa/freeipa/blob/master/ipapython/dn.py
ATTR_NAME_BY_OID = {
    cryptography.x509.oid.NameOID.COMMON_NAME: 'CN',
    cryptography.x509.oid.NameOID.COUNTRY_NAME: 'C',
    cryptography.x509.oid.NameOID.LOCALITY_NAME: 'L',
    cryptography.x509.oid.NameOID.STATE_OR_PROVINCE_NAME: 'ST',
    cryptography.x509.oid.NameOID.ORGANIZATION_NAME: 'O',
    cryptography.x509.oid.NameOID.ORGANIZATIONAL_UNIT_NAME: 'OU',
    cryptography.x509.oid.NameOID.SERIAL_NUMBER: 'serialNumber',
    cryptography.x509.oid.NameOID.SURNAME: 'SN',
    cryptography.x509.oid.NameOID.GIVEN_NAME: 'givenName',
    cryptography.x509.oid.NameOID.TITLE: 'title',
    cryptography.x509.oid.NameOID.GENERATION_QUALIFIER: 'generationQualifier',
    cryptography.x509.oid.NameOID.DN_QUALIFIER: 'dnQualifier',
    cryptography.x509.oid.NameOID.PSEUDONYM: 'pseudonym',
    cryptography.x509.oid.NameOID.DOMAIN_COMPONENT: 'DC',
    cryptography.x509.oid.NameOID.EMAIL_ADDRESS: 'E',
    cryptography.x509.oid.NameOID.JURISDICTION_COUNTRY_NAME:
        'incorporationCountry',
    cryptography.x509.oid.NameOID.JURISDICTION_LOCALITY_NAME:
        'incorporationLocality',
    cryptography.x509.oid.NameOID.JURISDICTION_STATE_OR_PROVINCE_NAME:
        'incorporationState',
    cryptography.x509.oid.NameOID.BUSINESS_CATEGORY: 'businessCategory',
    cryptography.x509.ObjectIdentifier('2.5.4.9'): 'STREET',
    cryptography.x509.ObjectIdentifier('2.5.4.17'): 'postalCode',
    cryptography.x509.ObjectIdentifier('0.9.2342.19200300.100.1.1'): 'UID',
}

# Retry-able connection errors, see https://github.com/dogtagpki/pki/issues/3091
RETRYABLE_EXCEPTIONS = (
    requests.exceptions.ConnectionError,  # connection failed
    requests.exceptions.Timeout,  # connection or read time out
)

logger = logging.getLogger(__name__)


def convert_x509_name_to_dn(name):
    """
    Convert X.509 Name into NSS-style DN string.

    See also:
    - https://cryptography.io/en/latest/x509/reference.html#cryptography.x509.Name
    - https://cryptography.io/en/latest/x509/reference.html#cryptography.x509.RelativeDistinguishedName
    - https://cryptography.io/en/latest/x509/reference.html#cryptography.x509.NameAttribute
    - https://cryptography.io/en/latest/x509/reference.html#cryptography.x509.ObjectIdentifier

    :param name: X.509 Name
    :type name: cryptography.x509.Name
    :returns: str -- DN string.
    """  # noqa: E501

    # Do not use cryptography.x509.Name.rfc4514_string() since
    # it generates a DN with reversed RDN order:
    #   dn = name.rfc4514_string()

    dn = None

    for attr in name:

        # Do not use cryptography.x509.RelativeDistinguishedName.rfc4514_string()
        # since it may generate an RDN with incorrect attribute names:
        #   rdn = attr.rfc4514_string()

        oid = attr.oid
        attr_name = ATTR_NAME_BY_OID.get(oid, oid.dotted_string)
        attr_value = ldap.dn.escape_dn_chars(attr.value)
        rdn = '%s=%s' % (attr_name, attr_value)

        if dn:
            dn = rdn + ',' + dn
        else:
            dn = rdn

    return dn


def specification_version():
    """
    Return specification version.

    :returns: str -- specification version
    """
    return get_info('Specification-Version')


def implementation_version():
    """
    Return implementation version.

    :returns: str -- implementation version
    """
    return get_info('Implementation-Version')


def get_info(name):
    with open(PACKAGE_VERSION, 'r', encoding='utf-8') as input_file:
        for line in input_file:
            line = line.strip('\n')

            # parse <key>: <value>
            match = re.match(r'^\s*(\S*)\s*:\s*(.*)\s*$', line)

            if not match:
                continue

            key = match.group(1)
            value = match.group(2)

            if key.lower() == name.lower():
                return value

    raise Exception('Property not found: %s' % name)


def generate_password(charset=GEN_PASS_CHARSET, length=12):
    """
    This function generates FIPS-compliant password.

    See sftk_newPinCheck() in the following file:
    https://dxr.mozilla.org/nss/source/nss/lib/softoken/fipstokn.c

    The minimum password length is FIPS_MIN_PIN Unicode characters.

    The password must contain at least 3 character classes:
     * digits (string.digits)
     * ASCII lowercase letters (string.ascii_lowercase)
     * ASCII uppercase letters (string.ascii_uppercase)
     * ASCII non-alphanumeric characters (PUNCTUATIONS)
     * non-ASCII characters

    If an ASCII uppercase letter is the first character of the password,
    the uppercase letter is not counted toward its character class.

    If a digit is the last character of the password, the digit is not
    counted toward its character class.

    The FIPS_MIN_PIN is defined in the following file:
    https://dxr.mozilla.org/nss/source/nss/lib/softoken/pkcs11i.h

    #define FIPS_MIN_PIN 7
    """

    rnd = random.SystemRandom()

    chars = []

    # add 1 random char from each present char class to meet
    # the minimum number of char class requirement
    if string.digits in charset:
        chars.append(rnd.choice(string.digits))
    if string.ascii_lowercase in charset:
        chars.append(rnd.choice(string.ascii_lowercase))
    if string.ascii_uppercase in charset:
        chars.append(rnd.choice(string.ascii_uppercase))
    if PUNCTUATIONS in charset:
        chars.append(rnd.choice(PUNCTUATIONS))

    # extend chars to specified length via any valid character classes
    chars.extend(rnd.choice(charset) for i in range(length - len(chars)))

    # randomize the char order
    rnd.shuffle(chars)

    # final password is `length` chars
    password = ''.join(chars)

    return password


class FIPS:

    @staticmethod
    def is_enabled():

        # Check if /proc/sys/crypto/fips_enabled exists
        if not os.path.exists('/proc/sys/crypto/fips_enabled'):
            return False

        # Check to see if FIPS is enabled on this system
        command = ['sysctl', 'crypto.fips_enabled', '-bn']

        with open(os.devnull, 'w', encoding='utf-8') as fnull:
            output = subprocess.check_output(command, stderr=fnull).decode('utf-8')

        if output != '0':
            return True

        else:
            return False


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


# Mapping from Java Server exception classes to python exception classes
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
        with open(self.filename, 'r', encoding='utf-8') as f_in:
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
        with open(self.filename, 'w', encoding='utf-8') as f_out:
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
            match = re.match(r'^\s*([^%s]*)\s*%s\s*(.*)\s*$' % (self.delimiter, self.delimiter),
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
            match = re.match(r'^\s*([^%s]*)\s*%s\s*(.*)\s*$' % (self.delimiter, self.delimiter),
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
            match = re.match(r'^\s*([^%s]*)\s*%s\s*(.*)\s*$' % (self.delimiter, self.delimiter),
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
            match = re.match(r'^\s*([^%s]*)\s*%s\s*(.*)\s*$' % (self.delimiter, self.delimiter),
                             line)

            if not match:
                continue

            key = match.group(1)
            value = match.group(2)

            if key.lower() == name.lower():
                self.lines.pop(i)
                return value

        return None
