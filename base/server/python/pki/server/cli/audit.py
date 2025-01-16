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

import argparse
import logging
import os
import shutil
import subprocess
import sys
import tempfile

import pki.cli

logger = logging.getLogger(__name__)


class AuditCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('audit', 'Audit management commands')

        self.parent = parent
        self.add_module(AuditConfigShowCLI(self))
        self.add_module(AuditConfigModifyCLI(self))
        self.add_module(AuditEventFindCLI(self))
        self.add_module(AuditEventShowCLI(self))
        self.add_module(AuditEventEnableCLI(self))
        self.add_module(AuditEventDisableCLI(self))
        self.add_module(AuditEventUpdateCLI(self))
        self.add_module(AuditFileFindCLI(self))
        self.add_module(AuditFileVerifyCLI(self))

    @staticmethod
    def print_audit_config(subsystem):

        name = 'log.instance.SignedAudit.%s'

        enabled = subsystem.config[name % 'enable'].lower() == 'true'

        fileName = subsystem.config[name % 'fileName']
        bufferSize = subsystem.config[name % 'bufferSize']
        flushInterval = subsystem.config[name % 'flushInterval']

        maxFileSize = subsystem.config[name % 'maxFileSize']
        rolloverInterval = subsystem.config[name % 'rolloverInterval']
        expirationTime = subsystem.config[name % 'expirationTime']

        logSigning = subsystem.config[name % 'logSigning'].lower() == 'true'
        signedAuditCertNickname = subsystem.config[name % 'signedAuditCertNickname']

        print('  Enabled: %s' % enabled)

        print('  Log File: %s' % fileName)
        print('  Buffer Size (bytes): %s' % bufferSize)
        print('  Flush Interval (seconds): %s' % flushInterval)

        print('  Max File Size (bytes): %s' % maxFileSize)
        print('  Rollover Interval (seconds): %s' % rolloverInterval)
        print('  Expiration Time (seconds): %s' % expirationTime)

        print('  Log Signing: %s' % logSigning)
        print('  Signing Certificate: %s' % signedAuditCertNickname)

    @staticmethod
    def print_audit_event_config(event):
        print('  Event Name: %s' % event.get('name'))
        print('  Enabled: %s' % event.get('enabled'))
        print('  Filter: %s' % event.get('filter'))


class AuditConfigShowCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('config-show', 'Display audit configuration')

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')

    def print_help(self):
        print('Usage: pki-server %s-audit-config-show [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        AuditCLI.print_audit_config(subsystem)


class AuditConfigModifyCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('config-mod', 'Modify audit configuration')

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--enabled')
        self.parser.add_argument('--logFile')
        self.parser.add_argument(
            '--bufferSize',
            type=int)
        self.parser.add_argument(
            '--flushInterval',
            type=int)
        self.parser.add_argument(
            '--maxFileSize',
            type=int)
        self.parser.add_argument(
            '--rolloverInterval',
            type=int)
        self.parser.add_argument(
            '--expirationTime',
            type=int)
        self.parser.add_argument('--logSigning')
        self.parser.add_argument('--signingCert')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')

    def print_help(self):
        print('Usage: pki-server %s-audit-config-mod [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --enabled <True|False>         Enable/disable audit logging.')
        print('      --logFile <path>               Set log file.')
        print('      --bufferSize <size>            Set buffer size (bytes).')
        print('      --flushInterval <interval>     Set flush interval (seconds).')
        print('      --maxFileSize <size>           Set maximum file size (bytes).')
        print('      --rolloverInterval <interval>  Set rollover interval (seconds).')
        print('      --expirationTime <time>        Set expiration time (seconds).')
        print('      --logSigning <True|False>      Enable/disable log signing.')
        print('      --signingCert <nickname>       Set signing certificate.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance

        if args.enabled:
            enabled = args.enabled.lower() == 'true'
        else:
            enabled = None

        logFile = args.logFile

        bufferSize = args.bufferSize
        flushInterval = args.flushInterval
        maxFileSize = args.maxFileSize
        rolloverInterval = args.rolloverInterval
        expirationTime = args.expirationTime

        if args.logSigning:
            logSigning = args.logSigning.lower() == 'true'
        else:
            logSigning = None

        signingCert = args.signingCert

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        name = 'log.instance.SignedAudit.%s'

        if enabled is None:
            pass
        elif enabled:
            subsystem.set_config(name % 'enable', 'true')
        else:
            subsystem.set_config(name % 'enable', 'false')

        if logFile:
            subsystem.set_config(name % 'fileName', logFile)

        if bufferSize:
            subsystem.set_config(name % 'bufferSize', bufferSize)

        if flushInterval:
            subsystem.set_config(name % 'flushInterval', flushInterval)

        if maxFileSize:
            subsystem.set_config(name % 'maxFileSize', maxFileSize)

        if rolloverInterval:
            subsystem.set_config(name % 'rolloverInterval', rolloverInterval)

        if expirationTime:
            subsystem.set_config(name % 'expirationTime', expirationTime)

        if logSigning is None:
            pass
        elif logSigning:
            subsystem.set_config(name % 'logSigning', 'true')
        else:
            subsystem.set_config(name % 'logSigning', 'false')

        if signingCert:
            subsystem.set_config(name % 'signedAuditCertNickname', signingCert)

        subsystem.save()

        AuditCLI.print_audit_config(subsystem)


class AuditEventFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('event-find', 'Find audit event configurations')

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--enabled')
        self.parser.add_argument('--enabledByDefault')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')

    def print_help(self):
        print('Usage: pki-server %s-audit-event-find [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       '
              '  Instance ID (default: pki-tomcat).')
        print('      --enabled <True|False>         '
              '  Show events currently enabled/disabled only.')
        print('      --enabledByDefault <True|False>'
              '  Show events enabled/disabled by default only.')
        print('  -v, --verbose                      '
              '  Run in verbose mode.')
        print('      --debug                        '
              '  Run in debug mode.')
        print('      --help                         '
              '  Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance

        if args.enabled:
            enabled = args.enabled.lower() == 'true'
        else:
            enabled = None

        if args.enabledByDefault:
            enabled_by_default = args.enabledByDefault.lower() == 'true'
        else:
            enabled_by_default = None

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        events = subsystem.find_audit_event_configs(enabled, enabled_by_default)

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


class AuditEventShowCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('event-show', 'Show audit event configuration')

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')
        self.parser.add_argument('event_name')

    def print_help(self):
        print('Usage: pki-server %s-audit-event-show [OPTIONS] <event name>'
              % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        event_name = args.event_name

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        event = subsystem.get_audit_event_config(event_name)
        AuditCLI.print_audit_event_config(event)


class AuditEventEnableCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('event-enable', 'Enable audit event configurations')

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')
        self.parser.add_argument('event_name')

    def print_help(self):
        print('Usage: pki-server %s-audit-event-enable [OPTIONS] <event_name>'
              % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        event_name = args.event_name

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        enabled = subsystem.enable_audit_event(event_name)
        subsystem.save()

        msg = None
        if enabled:
            msg = 'Event "{}" enabled successfully. You may need to ' \
                  'restart the instance.'.format(event_name)
        else:
            msg = 'Event "{}" may be already enabled.'.format(event_name)

        print(len(msg) * '-')
        print(msg)
        print(len(msg) * '-')

        event = subsystem.get_audit_event_config(event_name)
        AuditCLI.print_audit_event_config(event)


class AuditEventUpdateCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('event-update', 'Update audit event configurations')

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '-f',
            '--filter')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')
        self.parser.add_argument('event_name')

    def print_help(self):
        print('Usage: pki-server %s-audit-event-update <event_name> '
              '[OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -f, --filter <event filter>        Event Filter (Ex: (Outcome=Failure)).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        event_filter = args.event_filter
        event_name = args.event_name

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.update_audit_event_filter(event_name, event_filter)
        subsystem.save()

        event = subsystem.get_audit_event_config(event_name)
        AuditCLI.print_audit_event_config(event)


class AuditEventDisableCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('event-disable', 'Disable audit event configurations')

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')
        self.parser.add_argument('event_name')

    def print_help(self):
        print('Usage: pki-server %s-audit-event-disable [OPTIONS] <event_name>'
              % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance
        event_name = args.event_name

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        disable = subsystem.disable_audit_event(event_name)
        subsystem.save()

        msg = None
        if disable:
            msg = 'Audit event "{}" disabled. You may need to restart the ' \
                  'instance.'.format(event_name)
        else:
            msg = 'Audit event "{}" already disabled.'.format(event_name)

        print(len(msg) * '-')
        print(msg)
        print(len(msg) * '-')

        event = subsystem.get_audit_event_config(event_name)
        AuditCLI.print_audit_event_config(event)


class AuditFileFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('file-find', 'Find audit log files')

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')

    def print_help(self):
        print('Usage: pki-server %s-audit-file-find [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
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
        super().__init__('file-verify', 'Verify audit log files')

        self.parent = parent

        self.parser = argparse.ArgumentParser(
            prog=self.name,
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '-v',
            '--verbose',
            action='store_true')
        self.parser.add_argument(
            '--debug',
            action='store_true')
        self.parser.add_argument(
            '--help',
            action='store_true')

    def print_help(self):
        print('Usage: pki-server %s-audit-file-verify [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv, args=None):

        if not args:
            args = self.parser.parse_args(args=argv)

        if args.help:
            self.print_help()
            return

        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)

        elif args.verbose:
            logging.getLogger().setLevel(logging.INFO)

        instance_name = args.instance

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance %s.', instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)
        if not subsystem:
            logger.error('No %s subsystem in instance %s.',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        log_dir = subsystem.get_audit_log_dir()
        log_files = subsystem.get_audit_log_files()
        signing_cert = subsystem.get_subsystem_cert('audit_signing')

        tmpdir = tempfile.mkdtemp()

        try:
            file_list = os.path.join(tmpdir, 'audit.txt')

            with open(file_list, 'w', encoding='utf-8') as f:
                for filename in log_files:
                    f.write(os.path.join(log_dir, filename) + '\n')

            cmd = ['AuditVerify']

            if logger.isEnabledFor(logging.INFO):
                cmd.append('-v')

            cmd.extend([
                '-d', instance.nssdb_dir,
                '-n', signing_cert['nickname'],
                '-a', file_list])

            logger.debug('Command: %s', ' '.join(cmd))

            subprocess.call(cmd)

        finally:
            shutil.rmtree(tmpdir)
