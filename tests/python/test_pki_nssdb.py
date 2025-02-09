# -*- coding: utf-8 -*-
# Authors:
#     Christian Heimes <cheimes@redhat.com>
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

import binascii
import os
import shutil
import subprocess
import tempfile
import unittest

from pki import nssdb


# DNS name "example.org"
SAN_OID = "2.5.29.17"
SAN_DATA = binascii.unhexlify("300D820B6578616D706C652E6F7267")


class PKINSSDBTests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.password_file = os.path.join(self.tmpdir, 'passwd.txt')
        with open(self.password_file, 'w') as f:
            f.write('SecretPassword.123')

    def tearDown(self):
        shutil.rmtree(self.tmpdir)

    def create_db(self, dbtype):
        subprocess.check_call([
            'certutil',
            '-d', '{}:{}'.format(dbtype, self.tmpdir),
            '-N',
            '-f', self.password_file,
        ])

    def _check_dbfiles(self, dbtype, exists):
        if dbtype == 'dbm':
            filenames = ('cert8.db', 'key3.db', 'secmod.db')
        elif dbtype == 'sql':
            filenames = ('cert9.db', 'key4.db', 'pkcs11.txt')
        else:
            raise ValueError(dbtype)
        for name in filenames:
            filename = os.path.join(self.tmpdir, name)
            if exists:
                self.assertTrue(os.path.isfile(filename), filename)
            else:
                self.assertFalse(os.path.isfile(filename), filename)

    def assertDBMFiles(self):
        self._check_dbfiles('dbm', True)

    def assertNotDBMFiles(self):
        self._check_dbfiles('dbm', False)

    def assertSQLFiles(self):
        self._check_dbfiles('sql', True)

    def assertNotSQLFiles(self):
        self._check_dbfiles('sql', False)

    def test_dbtype_dbm(self):
        db = nssdb.NSSDatabase(self.tmpdir, password_file=self.password_file)
        self.assertEqual(db.get_dbtype(), None)
        self.create_db('dbm')
        self.assertDBMFiles()
        self.assertNotSQLFiles()
        self.assertEqual(db.get_dbtype(), 'dbm')

    def test_dbtype_sql(self):
        db = nssdb.NSSDatabase(self.tmpdir, password_file=self.password_file)
        self.assertEqual(db.get_dbtype(), None)
        self.create_db('sql')
        self.assertSQLFiles()
        self.assertNotDBMFiles()
        self.assertEqual(db.get_dbtype(), 'sql')

    def test_dbtype_both(self):
        db = nssdb.NSSDatabase(self.tmpdir, password_file=self.password_file)

        with open(os.path.join(self.tmpdir, 'cert8.db'), 'w') as f:
            f.write('testfile')
        with self.assertRaises(RuntimeError) as cm:
            db.get_dbtype()
        self.assertIn(
            "incomplete NSS database in DBM format",
            str(cm.exception)
        )

        for name in ('key3.db', 'secmod.db'):
            with open(os.path.join(self.tmpdir, name), 'w') as f:
                f.write('testfile')
        self.assertEqual(db.get_dbtype(), 'dbm')

        with open(os.path.join(self.tmpdir, 'cert9.db'), 'w') as f:
            f.write('testfile')
        with self.assertRaises(RuntimeError) as cm:
            db.get_dbtype()
        self.assertIn(
            "incomplete NSS database in SQL format",
            str(cm.exception)
        )

        for name in ('key4.db', 'pkcs11.txt'):
            with open(os.path.join(self.tmpdir, name), 'w') as f:
                f.write('testfile')
        self.assertEqual(db.get_dbtype(), 'sql')

    def test_convertdb(self):
        db = nssdb.NSSDatabase(self.tmpdir, password_file=self.password_file)

        self.create_db('dbm')
        self.assertDBMFiles()
        self.assertNotSQLFiles()
        self.assertEqual(db.get_dbtype(), 'dbm')

        db.convert_db()
        self.assertSQLFiles()
        self.assertNotDBMFiles()
        self.assertEqual(db.get_dbtype(), 'sql')

    def test_request_generic_ext(self):
        self.create_db('sql')
        db = nssdb.NSSDatabase(
            'sql:' + self.tmpdir,
            password_file=self.password_file
        )

        reqfile = os.path.join(self.tmpdir, "req.csr")

        db.create_request(
            "CN=testrequest",
            reqfile,
            key_type="rsa"
        )

        out = subprocess.check_output(
            ['openssl', 'req', '-text', '-in', reqfile],
            env={}
        )
        self.assertIn(b'CN = testrequest', out)
        self.assertIn(b'-----BEGIN CERTIFICATE REQUEST-----', out)
        self.assertIn(b'-----END CERTIFICATE REQUEST-----', out)


if __name__ == '__main__':
    unittest.main()
