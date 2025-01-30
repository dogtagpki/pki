#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import inspect
import logging
import sys
import textwrap

import pki.cli

logger = logging.getLogger(__name__)


class UserCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('user', '%s user management commands' % parent.name.upper())

        self.parent = parent

        self.add_module(UserAddCLI(self))
        self.add_module(UserFindCLI(self))
        self.add_module(UserModifyCLI(self))
        self.add_module(UserRemoveCLI(self))
        self.add_module(UserShowCLI(self))

        self.add_module(UserCertCLI(self))
        self.add_module(UserRoleCLI(self))


class UserAddCLI(pki.cli.CLI):
    '''
    Add {subsystem} user
    '''

    help = '''\
        Usage: pki-server {subsystem}-user-add [OPTIONS] <user ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --full-name <full name>        Full name
              --email <email>                Email
              --password <password>          Password
              --password-file <path>         Password file
              --cert <path>                  Certificate file
              --cert-format <format>         Certificate format (default: PEM)
              --phone <phone>                Phone
              --type <type>                  Type: userType, agentType, adminType, subsystemType
              --state <state>                State
              --tps-profiles <profiles>      Comma-separated TPS profiles
              --ignore-duplicate             Ignore duplicate.
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'add',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.name.upper()))

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--full-name')
        self.parser.add_argument('--email')
        self.parser.add_argument('--password')
        self.parser.add_argument('--password-file')
        self.parser.add_argument('--cert')
        self.parser.add_argument('--cert-format')
        self.parser.add_argument('--phone')
        self.parser.add_argument('--type')
        self.parser.add_argument('--state')
        self.parser.add_argument('--tps-profiles')
        self.parser.add_argument(
            '--ignore-duplicate',
            action='store_true')
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
        self.parser.add_argument('user_id')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.name))

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
        subsystem_name = self.parent.parent.name
        full_name = args.full_name
        email = args.email
        password = args.password
        password_file = args.password_file
        cert_path = args.cert
        cert_format = args.cert_format
        phone = args.phone
        user_type = args.type
        state = args.state

        tps_profiles = None
        if args.tps_profiles:
            tps_profiles = [x.strip() for x in args.tps_profiles.split(',')]

        ignore_duplicate = args.ignore_duplicate
        user_id = args.user_id

        if not full_name:
            logger.error('Missing full name')
            self.print_help()
            sys.exit(1)

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.add_user(
            user_id,
            full_name=full_name,
            email=email,
            password=password,
            password_file=password_file,
            phone=phone,
            user_type=user_type,
            state=state,
            tps_profiles=tps_profiles,
            ignore_duplicate=ignore_duplicate)

        if cert_path:
            subsystem.add_user_cert(
                user_id,
                cert_path=cert_path,
                cert_format=cert_format)


class UserFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('find', 'Find %s users' % parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--see-also')
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
        print('Usage: pki-server %s-user-find [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --see-also <subject DN>        Find users linked to a certificate.')
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
        subsystem_name = self.parent.parent.name
        see_also = args.see_also

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        users = subsystem.find_users(see_also=see_also)

        first = True

        for user in users['entries']:
            if first:
                first = False
            else:
                print()

            print('  User ID: {}'.format(user['id']))

            full_name = user.get('fullName')
            if full_name:
                print('  Full Name: {}'.format(full_name))

            email = user.get('email')
            if email:
                print('  Email: {} '.format(email))

            phone = user.get('phone')
            if phone:
                print('  Phone: {} '.format(phone))

            user_type = user.get('type')
            if user_type:
                print('  Type: {} '.format(user_type))

            state = user.get('state')
            if state:
                print('  State: {} '.format(state))


class UserModifyCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('mod', 'Modify %s user' % parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--password')
        self.parser.add_argument('--password-file')
        self.parser.add_argument('--add-see-also')
        self.parser.add_argument('--del-see-also')
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
        self.parser.add_argument('user_id')

    def print_help(self):
        print('Usage: pki-server %s-user-mod [OPTIONS] <user ID>' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --password <password>          User password')
        print('      --password-file <path>         User password file')
        print('      --add-see-also <subject DN>    Link user to a certificate.')
        print('      --del-see-also <subject DN>    Unlink user from a certificate.')
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
        subsystem_name = self.parent.parent.name
        password = args.password
        password_file = args.password_file
        add_see_also = args.add_see_also
        del_see_also = args.del_see_also
        user_id = args.user_id

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.modify_user(
            user_id,
            password=password,
            password_file=password_file,
            add_see_also=add_see_also,
            del_see_also=del_see_also)


class UserRemoveCLI(pki.cli.CLI):
    '''
    Remove {subsystem} user
    '''

    help = '''\
        Usage: pki-server {subsystem}-user-del [OPTIONS] <user ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat).
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'del',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.name.upper()))

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
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
        self.parser.add_argument('user_id')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.name))

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
        subsystem_name = self.parent.parent.name
        user_id = args.user_id

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.remove_user(user_id)


class UserShowCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('show', 'Display %s user' % parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
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
        self.parser.add_argument('user_id')

    def print_help(self):
        print('Usage: pki-server %s-user-show [OPTIONS] <user ID>' % self.parent.parent.name)
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
        subsystem_name = self.parent.parent.name
        user_id = args.user_id

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        user = subsystem.get_user(user_id)

        print('  User ID: {}'.format(user['id']))

        full_name = user.get('fullName')
        if full_name:
            print('  Full Name: {}'.format(full_name))

        email = user.get('email')
        if email:
            print('  Email: {}'.format(email))

        phone = user.get('phone')
        if phone:
            print('  Phone: {}'.format(phone))

        user_type = user.get('type')
        if user_type:
            print('  Type: {}'.format(user_type))

        state = user.get('state')
        if state:
            print('  State: {}'.format(state))


class UserCertCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('cert', '%s user cert management commands' % parent.parent.name.upper())

        self.parent = parent
        self.add_module(UserCertFindCLI(self))
        self.add_module(UserCertAddCLI(self))
        self.add_module(UserCertRemoveCLI(self))


class UserCertFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('find', 'Find %s user certificates' % parent.parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
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
        self.parser.add_argument('user_id')

    def print_help(self):
        print('Usage: pki-server %s-user-cert-find [OPTIONS] <user ID>'
              % self.parent.parent.parent.name)
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
        subsystem_name = self.parent.parent.parent.name
        user_id = args.user_id

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.find_user_certs(user_id)


class UserCertAddCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('add', 'Add %s user cert' % parent.parent.parent.name.upper())

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--cert')
        self.parser.add_argument(
            '--format',
            default='PEM')
        self.parser.add_argument(
            '--ignore-duplicate',
            action='store_true')
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
        self.parser.add_argument('user_id')

    def print_help(self):
        print('Usage: pki-server %s-user-cert-add [OPTIONS] <user ID>'
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --cert <path>                  Certificate to add.')
        print('      --format <format>              Certificate format: PEM (default), DER.')
        print('      --ignore-duplicate             Ignore duplicate.')
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
        subsystem_name = self.parent.parent.parent.name
        cert_path = args.cert
        cert_format = args.format
        ignore_duplicate = args.ignore_duplicate
        user_id = args.user_id

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.add_user_cert(
            user_id,
            cert_path=cert_path,
            cert_format=cert_format,
            ignore_duplicate=ignore_duplicate)


class UserCertRemoveCLI(pki.cli.CLI):
    '''
    Remove {subsystem} user certificate
    '''

    help = '''\
        Usage: pki-server {subsystem}-user-cert-del [OPTIONS] <user ID> <cert ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat).
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'del',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.name.upper()))

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
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
        self.parser.add_argument('user_id')
        self.parser.add_argument('cert_id')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

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
        subsystem_name = self.parent.parent.parent.name
        user_id = args.user_id
        cert_id = args.cert_id

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.remove_user_cert(user_id, cert_id)


class UserRoleCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('role', '%s user role management commands' % parent.parent.name.upper())

        self.parent = parent
        self.add_module(UserRoleFindCLI(self))
        self.add_module(UserRoleAddCLI(self))
        self.add_module(UserRoleRemoveCLI(self))


class UserRoleFindCLI(pki.cli.CLI):
    '''
    Find {subsystem} user roles
    '''

    help = '''\
        Usage: pki-server {subsystem}-user-role-find [OPTIONS] <user ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --output-format <format>       Output format: text (default), json.
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'find',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.name.upper()))

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--output-format')
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
        self.parser.add_argument('user_id')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

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
        subsystem_name = self.parent.parent.parent.name
        output_format = args.output_format
        user_id = args.user_id

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.find_user_roles(user_id, output_format=output_format)


class UserRoleAddCLI(pki.cli.CLI):
    '''
    Add {subsystem} user role
    '''

    help = '''\
        Usage: pki-server {subsystem}-user-role-add [OPTIONS] <user ID> <role ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'add',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.name.upper()))

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
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
        self.parser.add_argument('user_id')
        self.parser.add_argument('role_id')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

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
        subsystem_name = self.parent.parent.parent.name

        user_id = args.user_id
        role_id = args.role_id

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.add_user_role(user_id, role_id)


class UserRoleRemoveCLI(pki.cli.CLI):
    '''
    Remove {subsystem} user role
    '''

    help = '''\
        Usage: pki-server {subsystem}-user-role-del [OPTIONS] <user ID> <role ID>

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self, parent):
        super().__init__(
            'del',
            inspect.cleandoc(self.__class__.__doc__).format(
                subsystem=parent.parent.parent.name.upper()))

        self.parent = parent

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
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
        self.parser.add_argument('user_id')
        self.parser.add_argument('role_id')

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

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
        subsystem_name = self.parent.parent.parent.name

        user_id = args.user_id
        role_id = args.role_id

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            logger.error('Invalid instance: %s', instance_name)
            sys.exit(1)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            logger.error('No %s subsystem in instance %s',
                         subsystem_name.upper(), instance_name)
            sys.exit(1)

        subsystem.remove_user_role(user_id, role_id)
