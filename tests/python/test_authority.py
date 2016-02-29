# -*- coding: utf-8 -*-
# Authors:
#     Ade Lee <alee@redhat.com>
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
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#

try:
    from unittest import mock
except ImportError:
    import mock
import unittest
import uuid

from pki import authority


class AuthorityTests(unittest.TestCase):
    """ Unit test cases for the authority resource
    """

    def setUp(self):
        super(AuthorityTests, self).setUp()

        self.connection = mock.MagicMock()
        self.authority_client = authority.AuthorityClient(self.connection)
        self.top_level_aid = str(uuid.uuid4())
        self.aid = str(uuid.uuid4())
        self.aid2 = str(uuid.uuid4())
        self.dn = "cn=subordinate ca, o=example.com"
        self.dn2 = "cn=subordinate ca2, o=example.com"
        self.description = "subordinate CA1"
        self.description2 = "subordinate CA2"

        self.subca_data = {
            "dn": self.dn,
            "description": self.description,
            "parent_aid": self.top_level_aid
        }

        self.ca1_data = {
            "aid": self.aid,
            "dn": self.dn,
            "description": self.description
        }

        self.ca2_data = {
            "aid": self.aid2,
            "dn": self.dn2,
            "description": self.description2
        }
        post_return = mock.MagicMock()
        post_return.json.return_value = self.ca1_data
        self.connection.post.return_value = post_return

    def test_should_create_subca(self):
        authority_data = authority.AuthorityData(** self.subca_data)
        ca = self.authority_client.create_ca(authority_data)
        self.assertEquals(ca.aid, self.aid)
        self.assertEquals(ca.dn, self.dn)

    def test_create_should_raise_ca_data_not_defined(self):
        self.assertRaises(
            ValueError,
            self.authority_client.create_ca,
            None
        )

    def test_create_should_raise_dn_not_defined(self):
        del self.subca_data['dn']
        authority_data = authority.AuthorityData(** self.subca_data)
        self.assertRaises(
            ValueError,
            self.authority_client.create_ca,
            authority_data
        )

    def test_create_should_raise_description_not_defined(self):
        del self.subca_data['description']
        authority_data = authority.AuthorityData(** self.subca_data)
        self.assertRaises(
            ValueError,
            self.authority_client.create_ca,
            authority_data
        )

    def test_create_should_raise_parent_aid_not_defined(self):
        del self.subca_data["parent_aid"]
        authority_data = authority.AuthorityData(** self.subca_data)
        self.assertRaises(
            ValueError,
            self.authority_client.create_ca,
            authority_data
        )

    def test_should_get_ca(self):
        get_return = mock.MagicMock()
        get_return.json.return_value = self.ca1_data
        self.connection.get.return_value = get_return

        ca = self.authority_client.get_ca(self.aid)
        self.assertEquals(ca.aid, self.aid)
        self.assertEquals(ca.dn, self.dn)

    def test_should_list_cas(self):
        get_return = mock.MagicMock()
        ca_list = [self.ca1_data, self.ca2_data]
        get_return.json.return_value = ca_list
        self.connection.get.return_value = get_return

        cas = self.authority_client.list_cas()
        for ca in cas:
            self.assertIsInstance(ca, authority.AuthorityData)
            if ca.aid == self.aid2:
                self.assertEquals(ca.dn, self.dn2)
            else:
                self.assertEquals(ca.dn, self.dn)
