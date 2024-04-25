#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
from __future__ import absolute_import
from __future__ import print_function
import getopt
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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.name))

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'full-name=', 'email=',
                'password=', 'password-file=',
                'phone=', 'type=', 'state=', 'tps-profiles=', 'ignore-duplicate'
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.name
        full_name = None
        email = None
        password = None
        password_file = None
        phone = None
        user_type = None
        state = None
        tps_profiles = None
        ignore_duplicate = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--full-name':
                full_name = a

            elif o == '--email':
                email = a

            elif o == '--password':
                password = a

            elif o == '--password-file':
                password_file = a

            elif o == '--phone':
                phone = a

            elif o == '--type':
                user_type = a

            elif o == '--state':
                state = a

            elif o == '--tps-profiles':
                tps_profiles = [x.strip() for x in a.split(',')]

            elif o == '--ignore-duplicate':
                ignore_duplicate = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing user ID')
            self.print_help()
            sys.exit(1)

        user_id = args[0]

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


class UserFindCLI(pki.cli.CLI):

    def __init__(self, parent):
        super().__init__('find', 'Find %s users' % parent.parent.name.upper())

        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-user-find [OPTIONS]' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --see-also <subject DN>        Find users linked to a certificate.')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'see-also=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.name
        see_also = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--see-also':
                see_also = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
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

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'password=', 'password-file=',
                'add-see-also=', 'del-see-also=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.name
        password = None
        password_file = None
        add_see_also = None
        del_see_also = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--password':
                password = a

            elif o == '--password-file':
                password_file = a

            elif o == '--add-see-also':
                add_see_also = a

            elif o == '--del-see-also':
                del_see_also = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing user ID')
            self.print_help()
            sys.exit(1)

        user_id = args[0]

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.name))

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.name

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing user ID')
            self.print_help()
            sys.exit(1)

        user_id = args[0]

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

    def print_help(self):
        print('Usage: pki-server %s-user-show [OPTIONS] <user ID>' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.name

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing user ID')
            self.print_help()
            sys.exit(1)

        user_id = args[0]

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

    def print_help(self):
        print('Usage: pki-server %s-user-cert-find [OPTIONS] <user ID>'
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -v, --verbose                      Run in verbose mode.')
        print('      --debug                        Run in debug mode.')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing user ID')
            self.print_help()
            sys.exit(1)

        user_id = args[0]

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

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'cert=', 'format=', 'ignore-duplicate'
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name
        cert_path = None
        cert_format = 'PEM'
        ignore_duplicate = False

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--cert':
                cert_path = a

            elif o == '--format':
                cert_format = a

            elif o == '--ignore-duplicate':
                ignore_duplicate = True

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing user ID')
            self.print_help()
            sys.exit(1)

        user_id = args[0]

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

    def execute(self, argv):

        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing user ID')
            self.print_help()
            sys.exit(1)

        if len(args) < 2:
            logger.error('Missing certificate ID')
            self.print_help()
            sys.exit(1)

        user_id = args[0]
        cert_id = args[1]

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=', 'output-format=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name
        output_format = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--output-format':
                output_format = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing user ID')
            self.print_help()
            sys.exit(1)

        user_id = args[0]

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing user ID')
            self.print_help()
            sys.exit(1)

        user_id = args[0]

        if len(args) < 2:
            logger.error('Missing role ID')
            self.print_help()
            sys.exit(1)

        role_id = args[1]

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format(
            subsystem=self.parent.parent.parent.name))

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        subsystem_name = self.parent.parent.parent.name

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Invalid option: %s', o)
                self.print_help()
                sys.exit(1)

        if len(args) < 1:
            logger.error('Missing user ID')
            self.print_help()
            sys.exit(1)

        user_id = args[0]

        if len(args) < 2:
            logger.error('Missing role ID')
            self.print_help()
            sys.exit(1)

        role_id = args[1]

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
