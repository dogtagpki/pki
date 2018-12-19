# Authors:
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
# Copyright (C) 2018 Red Hat, Inc.
# All rights reserved.
#

import unittest
import subprocess

from pki.keyring import Keyring


class KeyringTests(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.keyring = Keyring()
        cls.password = 'Secret.123'
        cls.key_name = 'test-key'

    def put_pass(self, key_name, password):
        key_id, err = self.keyring.put_password(key_name=key_name,
                                                password=bytearray(password))

        key_id = key_id.decode('utf-8').strip()

        self.assertTrue(key_id.isdigit())
        self.assertIsNone(err)
        return key_id

    def get_key_id(self, key_name, orig_key_id):
        retrieved_key_id = self.keyring.get_key_id(key_name=key_name)
        self.assertEquals(retrieved_key_id, orig_key_id)

    def get_key_value_raw(self, key_name, orig_pass):
        retrieved_pass_raw = self.keyring.get_password(key_name=key_name, output_format='raw')
        self.assertEqual(retrieved_pass_raw, orig_pass)

    def get_key_value_hex(self, key_name, orig_pass):
        retrieved_pass_hex = self.keyring.get_password(key_name=key_name, output_format='hex')

        # Remove 1st line that reads 'xx bytes of data in key'
        retrieved_pass_hex = retrieved_pass_hex.split('\n')[1]
        # Remove spaces in the retrieved hex value
        retrieved_pass_hex = retrieved_pass_hex.replace(' ', '')
        self.assertEquals(retrieved_pass_hex.strip(), orig_pass.encode().hex())

    def clear_pass(self, key_name):
        self.keyring.clear_keyring()
        self.assertRaises(subprocess.CalledProcessError, self.keyring.get_key_id, key_name)

    def test_password(self):
        # Test putting a value
        orig_key_id = self.put_pass(self.key_name, self.password.encode())

        # Test the keyID
        self.get_key_id(self.key_name, orig_key_id)

        # Test retrieving value in 'raw' format
        self.get_key_value_raw(self.key_name, self.password)

        # Test retrieving the value in 'hex' format
        self.get_key_value_hex(self.key_name, self.password)

        # Test clearing the keyring
        self.clear_pass(self.key_name)


if __name__ == '__main__':
    unittest.main()
