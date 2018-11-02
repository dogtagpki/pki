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

from __future__ import absolute_import, print_function

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
        self.add_module(AuditEventFindCLI(self))
        self.add_module(AuditEventEnableCLI(self))
        self.add_module(AuditEventUpdateCLI(self))
        self.add_module(AuditEventDisableCLI(self))
        self.add_module(AuditFileFindCLI(self))
        self.add_module(AuditFileVerifyCLI(self))
        self.add_module(AuditConfigModifyCLI(self))


class AuditConfigModifyCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(AuditConfigModifyCLI, self).__init__(
            'config-mod', 'Enable/Disable signed audit logs')
        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-audit-config-mod [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --enabled <True|False>         Show enabled/disabled events only.')
        print('      --fileSize                     Set Audit file size. (Default 2000)')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'fileSize=',
                'enabled=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        enabled = None
        file_size = 2000
        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--enabled':
                if a.lower().title() not in ['True', 'False']:
                    raise ValueError("Not valid input. Specify True or False")
                if a.lower() == 'true':
                    enabled = True
                else:
                    enabled = False

            elif o == '--fileSize':
                if o.isdigit():
                    file_size = o
                else:
                    raise ValueError("Not valid input, Specify file size in digits")

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

        subsystem.signed_audit_log(enabled, file_size)
        subsystem.save()
        if enabled:
            self.print_message("Signed Audit enabled for {}".format(instance_name))
        else:
            self.print_message("Signed Audit disabled for {}".format(instance_name))
        self.print_message("You might need to restart the instance")


class AuditEventFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(AuditEventFindCLI, self).__init__(
            'event-find', 'Find audit event configurations')

        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-audit-event-find [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --enabled <True|False>         Show enabled/disabled events only.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'enabled=',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        enabled = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--enabled':
                enabled = a == 'True'

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

        events = subsystem.find_audit_events(enabled)

        self.print_message('%s entries matched' % len(events))

        first = True
        for event in events:
            if first:
                first = False
            else:
                print()

            print('  Event Name: %s' % event.get('name'))
            print('  Enabled: %s' % event.get('enabled'))
            print('  Filter: %s' % event.get('filter'))


class AuditEventEnableCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(AuditEventEnableCLI, self).__init__(
            'event-enable', 'Enable audit event configurations')

        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-audit-event-enable <event_name> [OPTIONS]'
              % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'verbose', 'help'])

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

        if len(args) == 0:
            raise getopt.GetoptError("Missing event name.")
        if len(args) > 1:
            raise getopt.GetoptError("Too many arguments specified.")
        event_name = args[0]

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

        msg = None
        enabled = subsystem.enable_audit_event(event_name)
        if enabled:
            msg = 'Event "{}" enabled successfully. You may need to ' \
                  'restart the instance.'.format(event_name)
        else:
            msg = 'Event "{}" may be already enabled.'.format(event_name)
        print(len(msg) * '-')
        print(msg)
        print(len(msg) * '-')


class AuditEventUpdateCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(AuditEventUpdateCLI, self).__init__(
            'event-update', 'Update audit event configurations')

        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-audit-event-update <event_name> '
              '[OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -f, --filter <event filter>        Event Filter (Ex: (Outcome=Failure)).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:f:v',
                                           ['instance=', 'filter=', 'verbose',
                                            'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        event_filter = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-f', '--filter'):
                event_filter = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        if len(args) == 0:
            raise getopt.GetoptError("Missing event name.")
        if len(args) > 1:
            raise getopt.GetoptError("Too many arguments specified.")

        event_name = args[0]

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

        subsystem.update_audit_event_filter(event_name, event_filter)
        subsystem.save()


class AuditEventDisableCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(AuditEventDisableCLI, self).__init__(
            'event-disable', 'Disable audit event configurations')

        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-audit-event-disable <event_name> [OPTIONS]'
              % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'verbose', 'help'])

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

        if len(args) == 0:
            raise getopt.GetoptError("Missing event name.")
        if len(args) > 1:
            raise getopt.GetoptError("Too many arguments specified.")

        event_name = args[0]

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

        msg = None
        disable = subsystem.disable_audit_event(event_name)
        if disable:
            msg = 'Audit event "{}" disabled. You may need to restart the ' \
                  'instance.'.format(event_name)
        else:
            msg = 'Audit event "{}" already disabled.'.format(event_name)

        print(len(msg) * '-')
        print(msg)
        print(len(msg) * '-')


class AuditFileFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super(AuditFileFindCLI, self).__init__(
            'file-find', 'Find audit log files')

        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-audit-file-find [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
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
        print('  -v, --verbose                      Run in verbose mode.')
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

            cmd = ['AuditVerify']

            if self.verbose:
                cmd.append('-v')

            cmd.extend([
                '-d', instance.nssdb_dir,
                '-n', signing_cert['nickname'],
                '-a', file_list])

            if self.verbose:
                print('Command: %s' % ' '.join(cmd))

            subprocess.call(cmd)

        finally:
            shutil.rmtree(tmpdir)
