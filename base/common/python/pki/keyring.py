# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
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
# Copyright (C) 2018 Red Hat, Inc.
# All rights reserved.
#


"""
Module that provides interface to access Kernel Keyring
"""
import subprocess


class Keyring:
    """
    Utility class to deal with keyrings. This class is a simple wrapper
    against the `keyutils` package. Defaults to user keyring `@u` and key
    type `user`
    """

    def __init__(self, keyring='@u', key_type='user'):
        self.keyring = keyring
        self.key_type = key_type

    def put_password(self, key_name, password):
        """
        Save a password to the keyring

        :param key_name: Name of they key
        :type key_name: str
        :param password: Password value to be stored
        :type password: bytearray
        :return: Key ID, Error (if any)
        :rtype: (bytearray, bytearray)
        """

        cmd = ['keyctl', 'padd', self.key_type, key_name, self.keyring]

        p = subprocess.Popen(cmd,
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)

        return p.communicate(input=password)

    def get_key_id(self, key_name):
        """
        Retrieve key ID from the provided key name

        :param key_name: Name of the key to search
        :type key_name: str
        :return: key_ID
        :rtype: int
        """

        cmd = ['keyctl', 'search', self.keyring, self.key_type, key_name]

        return subprocess.check_output(cmd).decode('utf-8').strip()

    def get_password(self, key_name, output_format='raw'):
        """
        Retrieve password in the given format

        :param key_name: The value of the key to be retrieved
        :type key_name: str
        :param output_format: Retrieval format: hex or raw (default)
        :type output_format: str
        :return: Value of the key in specified format
        :rtype: str
        """

        if output_format.lower() == 'raw':
            mode = 'pipe'
        elif output_format.lower() == 'hex':
            mode = 'read'
        else:
            raise AttributeError('output_format must be one of [\'raw\', \'hex\'].')

        key_id = self.get_key_id(key_name)

        cmd = ['keyctl', mode, key_id]

        return subprocess.check_output(cmd).decode('utf-8')

    def clear_keyring(self):
        """
        Clear the default keyring

        :return: Return code
        :rtype: int
        """
        cmd = ['keyctl', 'clear', self.keyring]
        return subprocess.check_call(cmd)
