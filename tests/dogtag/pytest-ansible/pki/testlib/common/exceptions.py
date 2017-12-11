# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2017 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
    Provide Exceptions for py.test framework
"""


class StandardException(Exception):
    """ Overrides Exception class """

    def __init__(self, msg=None, rval=1):
        if msg is None:
            msg = 'Error'
        self.msg = msg
        self.rval = rval

    def __str__(self):
        return "{} ({})".format(self.msg, self.rval)


class InvalidInput(StandardException):
    """
    Override StandardException used mainly when invalid input is passed
    """


class DirSrvException(StandardException):
    """
    Override StandardException, This exception s to be used for Directory Server related Errors
    """


class PkiLibException(StandardException):
    """
    Override StandardException , This exception is to be used for Dogtag/CS related Errors
    """


class OSException(StandardException):
    """
    Override StandardException, This exception is to be used for Operating system errors.
    """


class LdapException(StandardException):
    """
    Override StandardException, This exception is to be used for LDAP Errors
    """
class RPMException(StandardException):
    """
    Override StandardException, This exception is to be used for LDAP Errors
    """
