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
# Copyright (C) 2017 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function
import getopt
import os
import shutil
import subprocess
import sys
import tempfile

import pki.cli


class AuditCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(AuditCLI, self).__init__(
            'audit', 'Audit management commands')

        self.parent = parent
        self.add_module(AuditFileFindCLI(self))
        self.add_module(AuditFileVerifyCLI(self))


class AuditFileFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(AuditFileFindCLI, self).__init__(
            'file-find', 'Find audit log files')

        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-audit-file-find [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            print('ERROR: No %s subsystem in instance %s.'
                  % (subsystem_name.upper(), instance_name))
            sys.exit(1)

        log_files = subsystem.get_audit_log_files()

        self.print_message('%s entries matched' % len(log_files))

        first = True
        for filename in log_files:
            if first:
                first = False
            else:
                print()

            print('  File name: %s' % filename)


class AuditFileVerifyCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(AuditFileVerifyCLI, self).__init__(
            'file-verify', 'Verify audit log files')

        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-audit-file-verify [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            print('ERROR: No %s subsystem in instance %s.'
                  % (subsystem_name.upper(), instance_name))
            sys.exit(1)

        log_dir = subsystem.get_audit_log_dir()
        log_files = subsystem.get_audit_log_files()
        signing_cert = subsystem.get_subsystem_cert('audit_signing')

        tmpdir = tempfile.mkdtemp()

        try:
            file_list = os.path.join(tmpdir, 'audit.txt')

            with open(file_list, 'w') as f:
                for filename in log_files:
                    f.write(os.path.join(log_dir, filename) + '\n')

            cmd = ['AuditVerify',
                   '-d', instance.nssdb_dir,
                   '-n', signing_cert['nickname'],
                   '-a', file_list]

            if self.verbose:
                print('Command: %s' % ' '.join(cmd))

            subprocess.call(cmd)

        finally:
            shutil.rmtree(tmpdir)
