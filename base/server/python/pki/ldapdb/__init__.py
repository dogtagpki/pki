# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
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

from __future__ import absolute_import
from __future__ import print_function

import tempfile
import ldap
import os
import shutil
import logging
import ldap.modlist as modlist

logger = logging.getLogger(__name__)


class PKILDAPDatabase(object):
    """Provides an LDAP wrapper to access 389-Directory server.

    By creating an instance of this class, following LDAP
    operations can be performed:

    * Searching entries
    * Adding entries
    * Deleting entries
    * Editing entries

    """

    def __init__(self, url='ldap://localhost:389'):
        """
        Return a ldapdb instance with the provided URL

        :param url: str
            URL of the LDAP instance to perform operations

        """
        self.url = url

        self.nssdb_dir = None

        self.bind_dn = None
        self.bind_password = None

        self.client_cert_nickname = None
        self.nssdb_password = None

        self.temp_dir = None
        self.ldap = None

    def set_security_database(self, nssdb_dir=None):
        self.nssdb_dir = nssdb_dir

    def set_credentials(self, bind_dn=None, bind_password=None,
                        client_cert_nickname=None, nssdb_password=None):
        """
        Set credentials to authenticate during LDAP connection establishment

        :param bind_dn: str
            The `bind_dn` to connect to the LDAP instance
        :param bind_password: str
            The password to the LDAP instance
        :param client_cert_nickname: str
            Client cert nickname to authenticate against LDAP
        :param nssdb_password: str
            nssdb password
        :return:
            None
        """

        self.bind_dn = bind_dn
        self.bind_password = bind_password
        self.client_cert_nickname = client_cert_nickname
        self.nssdb_password = nssdb_password

    def open(self):
        """
        Initialize a LDAP connection object with necessary options as
        provided earlier

        :return: None
        """

        self.temp_dir = tempfile.mkdtemp()

        if self.nssdb_dir:
            ldap.set_option(ldap.OPT_X_TLS_CACERTDIR, self.nssdb_dir)

        if self.client_cert_nickname:
            password_file = os.path.join(self.temp_dir, 'password.txt')
            with open(password_file, 'w') as f:
                f.write(self.nssdb_password)

            ldap.set_option(ldap.OPT_X_TLS_CERTFILE, self.client_cert_nickname)
            ldap.set_option(ldap.OPT_X_TLS_KEYFILE, password_file)

        self.ldap = ldap.initialize(self.url)

        if self.bind_dn and self.bind_password:
            self.ldap.simple_bind_s(self.bind_dn, self.bind_password)

    def close(self):

        if self.ldap:
            self.ldap.unbind_s()

        if self.temp_dir:
            shutil.rmtree(self.temp_dir)

    def get(self, base_dn, search_scope, search_filter, retrieve_attributes):
        """
        Retrieve entries from the LDAP database synchronously

        :param base_dn:
            The base Distinguished Name (DN) to start search
        :type base_dn: str

        :param search_scope:
            The scope of this search (SCOPE_BASE, SCOPE_ONELEVEL, SCOPE_SUBTREE)
        :type search_scope: int

        :param search_filter:
            The search filter string
        :type search_filter: str

        :param retrieve_attributes:
            List of attributes to retrieve
        :type retrieve_attributes: list

        :return:
            Result of the query
        :rtype: list

        """

        # If ldap object isn't initialized, no operation can be performed
        if not self.ldap:
            raise Exception('LDAP instance uninitialized.')

        try:
            # Perform a synchronous search
            ldap_result = self.ldap.search_s(
                base_dn, search_scope, search_filter, retrieve_attributes)
            return ldap_result

        except ldap.LDAPError as e:
            logger.error(e)

    def put(self, dn, attr):
        """
        Add an entry to the LDAP database synchronously

        :param dn:
            The base Distinguished Name (DN) to start search
        :type dn: str

        :param attr:
            The scope of this search (SCOPE_BASE, SCOPE_ONELEVEL, SCOPE_SUBTREE)
        :type attr: dict

        :return:
            Result of the insert operation
        :rtype: bool

        """

        if not self.ldap:
            raise Exception('LDAP instance uninitialized.')

        try:
            logger.debug('Converting dict to LDAP entry syntax')
            # Convert our dict to nice syntax for the add-function
            ldif = modlist.addModlist(attr)

            logger.debug('Adding entry to LDAP db')
            # Perform a synchronous add operation
            ldap_result = self.ldap.add_s(dn, ldif)

            if ldap_result:
                return True

        except ldap.LDAPError as e:
            logger.error(e)

        return False


