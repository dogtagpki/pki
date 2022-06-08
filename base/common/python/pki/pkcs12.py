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
# Copyright (C) 2016 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
import os
import shutil
import subprocess
import tempfile


class PKCS12(object):

    def __init__(self, path, password=None, password_file=None, nssdb=None):

        # The pki CLI needs an NSS database to run PKCS #12 operations
        # as required by JSS. If the nssdb parameter is provided, the CLI
        # will use the specified NSS database object. Otherwise, it will use
        # the default NSS database in ~/.dogtag/nssdb.

        self.path = path
        self.nssdb = nssdb

        self.tmpdir = tempfile.mkdtemp()

        if password:
            self.password_file = os.path.join(self.tmpdir, 'password.txt')
            with open(self.password_file, 'w', encoding='utf-8') as f:
                f.write(password)

        elif password_file:
            self.password_file = password_file

        else:
            raise Exception('Missing PKCS #12 password')

    def close(self):
        shutil.rmtree(self.tmpdir)

    def show_certs(self):

        cmd = ['pki']

        if self.nssdb:
            cmd.extend([
                '-d', self.nssdb.directory,
                '-C', self.nssdb.password_file
            ])

        cmd.extend([
            'pkcs12-cert-find',
            '--pkcs12', self.path,
            '--password-file', self.password_file
        ])

        subprocess.check_call(cmd)
