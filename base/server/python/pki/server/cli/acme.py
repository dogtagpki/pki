# Authors:
#     Endi S. Dewata <edewata@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

import argparse
import inspect
import logging
import os
import textwrap

import pki.cli
import pki.server
import pki.server.cli.db
import pki.server.cli.subsystem

logger = logging.getLogger(__name__)


class ACMECLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('acme', 'ACME management commands')

        self.add_module(ACMECreateCLI())
        self.add_module(ACMERemoveCLI())

        self.add_module(pki.server.cli.subsystem.SubsystemDeployCLI(self))
        self.add_module(pki.server.cli.subsystem.SubsystemUndeployCLI(self))
        self.add_module(pki.server.cli.subsystem.SubsystemRedeployCLI(self))

        self.add_module(ACMEMetadataCLI())
        self.add_module(ACMEDatabaseCLI())
        self.add_module(ACMEIssuerCLI())
        self.add_module(ACMERealmCLI())


class ACMECreateCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('create', 'Create ACME subsystem')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--force',
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

    def print_help(self):
        print('Usage: pki-server acme-create [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --force                        Force creation.')
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
        force = args.force

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem = pki.server.subsystem.ACMESubsystem(instance)
        subsystem.create(force=force)
        subsystem.create_conf(force=force)
        subsystem.create_logs(force=force)


class ACMERemoveCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('remove', 'Remove ACME subsystem')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--remove-conf',
            action='store_true')
        self.parser.add_argument(
            '--remove-logs',
            action='store_true')
        self.parser.add_argument(
            '--force',
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

    def print_help(self):
        print('Usage: pki-server acme-remove [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --remove-conf                  Remove config folder.')
        print('      --remove-logs                  Remove logs folder.')
        print('      --force                        Force removal.')
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
        remove_conf = args.remove_conf
        remove_logs = args.remove_logs
        force = args.force

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem = pki.server.subsystem.ACMESubsystem(instance)

        if remove_logs:
            subsystem.remove_logs(force=force)

        if remove_conf:
            subsystem.remove_conf(force=force)

        subsystem.remove(force=force)


class ACMEDeployCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('deploy', 'Deploy ACME subsystem')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--wait',
            action='store_true')
        self.parser.add_argument(
            '--max-wait',
            type=int,
            default=60)
        self.parser.add_argument(
            '--timeout',
            type=int)
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
        self.parser.add_argument(
            'name',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server acme-deploy [OPTIONS] [name]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --wait                         Wait until started.')
        print('      --max-wait <seconds>           Maximum wait time (default: 60).')
        print('      --timeout <seconds>            Connection timeout.')
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
        wait = args.wait
        max_wait = args.max_wait
        timeout = args.timeout
        name = args.name

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        descriptor = os.path.join(pki.server.PKIServer.SHARE_DIR,
                                  'acme/conf/Catalina/localhost/acme.xml')
        doc_base = os.path.join(pki.server.PKIServer.SHARE_DIR,
                                'acme/webapps/acme')

        instance.deploy_webapp(
            name,
            descriptor,
            doc_base,
            wait=wait,
            max_wait=max_wait,
            timeout=timeout)


class ACMEUndeployCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('undeploy', 'Undeploy ACME subsystem')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--wait',
            action='store_true')
        self.parser.add_argument(
            '--max-wait',
            type=int,
            default=60)
        self.parser.add_argument(
            '--timeout',
            type=int)
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
        self.parser.add_argument(
            'name',
            nargs='?')

    def print_help(self):
        print('Usage: pki-server acme-undeploy [OPTIONS] [name]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --wait                         Wait until stopped.')
        print('      --max-wait <seconds>           Maximum wait time (default: 60).')
        print('      --timeout <seconds>            Connection timeout.')
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
        wait = args.wait
        max_wait = args.max_wait
        timeout = args.timeout
        name = args.name

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        instance.undeploy_webapp(
            name,
            wait=wait,
            max_wait=max_wait,
            timeout=timeout)


class ACMEMetadataCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('metadata', 'ACME metadata management commands')

        self.add_module(ACMEMetadataShowCLI())
        self.add_module(ACMEMetadataModifyCLI())


class ACMEMetadataShowCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('show', 'Show ACME metadata configuration')

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

    def print_help(self):
        print('Usage: pki-server acme-metadata-show [OPTIONS]')
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
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        acme_conf_dir = os.path.join(instance.conf_dir, 'acme')
        metadata_conf = os.path.join(acme_conf_dir, 'metadata.conf')
        config = {}

        if not os.path.exists(metadata_conf):
            source = '/usr/share/pki/acme/conf/metadata.conf'
        else:
            source = metadata_conf

        logger.info('Loading %s', source)
        pki.util.load_properties(source, config)

        terms_of_service = config.get('termsOfService')
        if terms_of_service:
            print('  Terms of Service: %s' % terms_of_service)

        website = config.get('website')
        if website:
            print('  Website: %s' % website)

        caa_identities = config.get('caaIdentities')
        if caa_identities:
            print('  CAA Identities: %s' % caa_identities)

        external_account_required = config.get('externalAccountRequired')
        if external_account_required:
            print('  External Account Required: %s' % external_account_required)


class ACMEMetadataModifyCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('mod', 'Modify ACME metadata configuration')

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

    def print_help(self):
        print('Usage: pki-server acme-metadata-mod [OPTIONS]')
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
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        acme_conf_dir = os.path.join(instance.conf_dir, 'acme')
        metadata_conf = os.path.join(acme_conf_dir, 'metadata.conf')
        config = {}

        if not os.path.exists(metadata_conf):
            source = '/usr/share/pki/acme/conf/metadata.conf'
        else:
            source = metadata_conf

        logger.info('Loading %s', source)
        pki.util.load_properties(source, config)

        print('The current value is displayed in the square brackets.')
        print('To keep the current value, simply press Enter.')
        print('To change the current value, enter the new value.')
        print('To remove the current value, enter a blank space.')

        print()
        print('Enter the location of the terms of service.')
        terms_of_service = config.get('termsOfService')
        terms_of_service = pki.util.read_text('  Terms of Service', default=terms_of_service)
        pki.util.set_property(config, 'termsOfService', terms_of_service)

        print()
        print('Enter the location of the website.')
        website = config.get('website')
        website = pki.util.read_text('  Website', default=website)
        pki.util.set_property(config, 'website', website)

        print()
        print('Enter the CAA identities.')
        caa_identities = config.get('caaIdentities')
        caa_identities = pki.util.read_text('  CAA Identities', default=caa_identities)
        pki.util.set_property(config, 'caaIdentities', caa_identities)

        print()
        print('Enter true/false whether an external account is required.')
        external_account_required = config.get('externalAccountRequired')
        external_account_required = pki.util.read_text(
            '  External Account Required', default=external_account_required)
        pki.util.set_property(config, 'externalAccountRequired', external_account_required)

        instance.store_properties(metadata_conf, config)


class ACMEDatabaseCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('database', 'ACME database management commands')

        self.add_module(ACMEDatabaseInitCLI())
        self.add_module(ACMEDatabaseShowCLI())
        self.add_module(ACMEDatabaseModifyCLI())

        self.add_module(ACMEDatabaseIndexCLI())


class ACMEDatabaseInitCLI(pki.cli.CLI):
    '''
    Initialize ACME database
    '''

    help = '''\
        Usage: pki-server acme-database-init [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
              --skip-reindex                 Skip database reindex.
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self):
        super().__init__(
            'init',
            inspect.cleandoc(self.__class__.__doc__).format())

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument(
            '--skip-reindex',
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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format())

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

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            raise Exception('No %s subsystem in instance %s' %
                            (subsystem_name.upper(), instance_name))

        subsystem.init_database(
            skip_reindex=args.skip_reindex)


class ACMEDatabaseShowCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('show', 'Show ACME database configuration')

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

    def print_help(self):
        print('Usage: pki-server acme-database-show [OPTIONS]')
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
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        acme_conf_dir = os.path.join(instance.conf_dir, 'acme')
        database_conf = os.path.join(acme_conf_dir, 'database.conf')
        config = {}

        logger.info('Loading %s', database_conf)
        pki.util.load_properties(database_conf, config)

        database_class = config.get('class')

        database_type = pki.server.subsystem.ACME_DATABASE_TYPES.get(database_class)
        print('  Database Type: %s' % database_type)

        if database_type in ['ds', 'ldap', 'openldap']:

            url = config.get('url')
            if url:
                print('  Server URL: %s' % url)

            auth_type = config.get('authType')
            if auth_type:
                print('  Authentication Type: %s' % auth_type)

            if auth_type == 'BasicAuth':

                bind_dn = config.get('bindDN')
                if bind_dn:
                    print('  Bind DN: %s' % bind_dn)

                password = config.get('bindPassword')
                if password:
                    print('  Bind Password: ********')

            elif auth_type == 'SslClientAuth':

                nickname = config.get('nickname')
                if nickname:
                    print('  Client Certificate: %s' % nickname)

            base_dn = config.get('basedn')
            if base_dn:
                logger.warning('The basedn parameter has been deprecated. Use baseDN instead.')
            else:
                base_dn = config.get('baseDN')

            if base_dn:
                print('  Base DN: %s' % base_dn)

        elif database_type == 'postgresql':

            url = config.get('url')
            if url:
                print('  Server URL: %s' % url)

            username = config.get('user')
            if username:
                print('  Username: %s' % username)

            password = config.get('password')
            if password:
                print('  Password: ********')


class ACMEDatabaseModifyCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('mod', 'Modify ACME database configuration')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--type')
        self.parser.add_argument(
            '-D',
            action='append')
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
        print('Usage: pki-server acme-database-mod [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --type <type>                  Database type: {0}'
              .format(', '.join(pki.server.subsystem.ACME_DATABASE_TYPES.values())))
        print('      -D<name>=<value>               Set property value.')
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

        database_type = args.type
        if database_type not in pki.server.subsystem.ACME_DATABASE_TYPES.values():
            raise Exception('Invalid database type: {0}'.format(database_type))

        props = {}
        for param in args.D:
            parts = param.split('=', 1)
            name = parts[0]
            value = parts[1]
            props[name] = value

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem = pki.server.subsystem.ACMESubsystem(instance)
        config = subsystem.get_database_config(database_type=database_type)

        # if --type or -D is specified, use silent mode
        if database_type or props:

            logger.info('Setting properties:')
            for name, value in props.items():
                logger.info('- %s: %s', name, value)
                pki.util.set_property(config, name, value)

            subsystem.update_database_config(config)
            return

        # otherwise, use interactive mode

        print('The current value is displayed in the square brackets.')
        print('To keep the current value, simply press Enter.')
        print('To change the current value, enter the new value.')
        print('To remove the current value, enter a blank space.')

        database_class = config.get('class')

        print()
        print(
            'Enter the type of the database. '
            'Available types: %s.' % ', '.join(pki.server.subsystem.ACME_DATABASE_TYPES.values()))
        database_type = pki.server.subsystem.ACME_DATABASE_TYPES.get(database_class)
        orig_database_type = database_type

        database_type = pki.util.read_text(
            '  Database Type',
            options=pki.server.subsystem.ACME_DATABASE_TYPES.values(),
            default=database_type,
            required=True)
        pki.util.set_property(
            config,
            'class',
            pki.server.subsystem.ACME_DATABASE_CLASSES.get(database_type))

        if orig_database_type != database_type:
            source = '/usr/share/pki/acme/database/{0}/database.conf'.format(database_type)
            logger.info('Loading %s', source)
            pki.util.load_properties(source, config)

        if database_type == 'in-memory':
            config.pop('url', None)
            config.pop('user', None)
            config.pop('password', None)

        elif database_type in ['ds', 'ldap', 'openldap']:

            print()
            print('Enter the location of the LDAP server '
                  '(e.g. ldap://localhost.localdomain:389).')
            url = config.get('url')
            url = pki.util.read_text('  Server URL', default=url, required=True)
            pki.util.set_property(config, 'url', url)

            print()
            print('Enter the authentication type. Available types: BasicAuth, SslClientAuth.')
            auth_type = config.get('authType')
            auth_type = pki.util.read_text(
                '  Authentication Type',
                options=['BasicAuth', 'SslClientAuth'],
                default=auth_type,
                required=True)
            pki.util.set_property(config, 'authType', auth_type)

            if auth_type == 'BasicAuth':

                print()
                print('Enter the bind DN.')
                bind_dn = config.get('bindDN')
                bind_dn = pki.util.read_text('  Bind DN', default=bind_dn, required=True)
                pki.util.set_property(config, 'bindDN', bind_dn)

                print()
                print('Enter the bind password.')
                password = config.get('bindPassword')
                password = pki.util.read_text(
                    '  Bind Password',
                    default=password,
                    password=True,
                    required=True)
                pki.util.set_property(config, 'bindPassword', password)

            elif auth_type == 'SslClientAuth':

                print()
                print('Enter the client certificate.')
                nickname = config.get('nickname')
                nickname = pki.util.read_text(
                    '  Client Certificate',
                    default=nickname,
                    required=True)
                pki.util.set_property(config, 'nickname', nickname)

            print()
            print('Enter the base DN for the ACME subtree.')

            base_dn = config.pop('basedn', None)
            if not base_dn:
                base_dn = config.get('baseDN')

            base_dn = pki.util.read_text('  Base DN', default=base_dn, required=True)
            pki.util.set_property(config, 'baseDN', base_dn)

        elif database_type == 'postgresql':

            print()
            print('Enter the location of the PostgreSQL database '
                  '(e.g. jdbc:postgresql://localhost.localdomain:5432/acme).')
            url = config.get('url')
            url = pki.util.read_text('  Server URL', default=url, required=True)
            pki.util.set_property(config, 'url', url)

            print()
            print('Enter the username for basic authentication.')
            username = config.get('user')
            username = pki.util.read_text('  Username', default=username, required=True)
            pki.util.set_property(config, 'user', username)

            print()
            print('Enter the password for basic authentication.')
            password = config.get('password')
            password = pki.util.read_text(
                '  Password', default=password, password=True, required=True)
            pki.util.set_property(config, 'password', password)

        subsystem.update_database_config(config)


class ACMEDatabaseIndexCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('index', 'ACME database index management commands')

        self.add_module(ACMEDatabaseIndexRebuildCLI())


class ACMEDatabaseIndexRebuildCLI(pki.cli.CLI):
    '''
    Rebuild ACME database indexes
    '''

    help = '''\
        Usage: pki-server acme-database-index-rebuild [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self):
        super().__init__(
            'rebuild',
            inspect.cleandoc(self.__class__.__doc__).format())

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format())

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

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            raise Exception('No %s subsystem in instance %s' %
                            (subsystem_name.upper(), instance_name))

        subsystem.rebuild_indexes()


class ACMEIssuerCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('issuer', 'ACME issuer management commands')

        self.add_module(ACMEIssuerShowCLI())
        self.add_module(ACMEIssuerModifyCLI())


class ACMEIssuerShowCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('show', 'Show ACME issuer configuration')

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

    def print_help(self):
        print('Usage: pki-server acme-issuer-show [OPTIONS]')
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
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        acme_conf_dir = os.path.join(instance.conf_dir, 'acme')
        issuer_conf = os.path.join(acme_conf_dir, 'issuer.conf')
        config = {}

        logger.info('Loading %s', issuer_conf)
        pki.util.load_properties(issuer_conf, config)

        issuer_class = config.get('class')

        issuer_type = pki.server.subsystem.ACME_ISSUER_TYPES.get(issuer_class)
        print('  Issuer Type: %s' % issuer_type)

        if issuer_type == 'nss':

            nickname = config.get('nickname')
            if nickname:
                print('  Signing Certificate: %s' % nickname)

            extensions = config.get('extensions')
            if extensions:
                print('  Certificate Extensions: %s' % extensions)

        elif issuer_type == 'pki':

            url = config.get('url')
            if url:
                print('  Server URL: %s' % url)

            nickname = config.get('nickname')
            if nickname:
                print('  Client Certificate: %s' % nickname)

            username = config.get('username')
            if username:
                print('  Agent Username: %s' % username)

            password = config.get('password')
            if password:
                print('  Agent Password: ********')

            password_file = config.get('passwordFile')
            if password_file:
                print('  Password file: %s' % password_file)

            profile = config.get('profile')
            if profile:
                print('  Certificate Profile: %s' % profile)

            authority_id = config.get('authority-id')
            if authority_id:
                print('  Authority ID: %s' % authority_id)

            authority_dn = config.get('authority-dn')
            if authority_dn:
                print('  Authority DN: %s' % authority_dn)


class ACMEIssuerModifyCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('mod', 'Modify ACME issuer configuration')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--type')
        self.parser.add_argument(
            '-D',
            action='append')
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
        print('Usage: pki-server acme-issuer-mod [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --type <type>                  Issuer type: {0}'
              .format(', '.join(pki.server.subsystem.ACME_ISSUER_TYPES.values())))
        print('      -D<name>=<value>               Set property value.')
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

        issuer_type = args.type
        if issuer_type not in pki.server.subsystem.ACME_ISSUER_TYPES.values():
            raise Exception('Invalid issuer type: {0}'.format(issuer_type))

        props = {}
        for param in args.D:
            parts = param.split('=', 1)
            name = parts[0]
            value = parts[1]
            props[name] = value

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem = pki.server.subsystem.ACMESubsystem(instance)
        config = subsystem.get_issuer_config(issuer_type=issuer_type)

        # if --type or -D is specified, use silent mode
        if issuer_type or props:

            logger.info('Setting properties:')
            for name, value in props.items():
                logger.info('- %s: %s', name, value)
                pki.util.set_property(config, name, value)

            subsystem.update_issuer_config(config)
            return

        # otherwise, use interactive mode

        print('The current value is displayed in the square brackets.')
        print('To keep the current value, simply press Enter.')
        print('To change the current value, enter the new value.')
        print('To remove the current value, enter a blank space.')

        issuer_class = config.get('class')

        print()
        print(
            'Enter the type of the certificate issuer. '
            'Available types: %s.' % ', '.join(pki.server.subsystem.ACME_ISSUER_TYPES.values()))
        issuer_type = pki.server.subsystem.ACME_ISSUER_TYPES.get(issuer_class)
        orig_issuer_type = issuer_type

        issuer_type = pki.util.read_text(
            '  Issuer Type',
            options=pki.server.subsystem.ACME_ISSUER_TYPES.values(),
            default=issuer_type,
            required=True)
        pki.util.set_property(
            config,
            'class',
            pki.server.subsystem.ACME_ISSUER_CLASSES.get(issuer_type))

        if orig_issuer_type != issuer_type:
            source = '/usr/share/pki/acme/issuer/{0}/issuer.conf'.format(issuer_type)
            logger.info('Loading %s', source)
            pki.util.load_properties(source, config)

        if issuer_type == 'nss':

            print()
            print('Enter the nickname of the signing certificate.')
            nickname = config.get('nickname')
            nickname = pki.util.read_text('  Signing Certificate', default=nickname)
            pki.util.set_property(config, 'nickname', nickname)

            print()
            print('Enter the certificate extension configuration.')
            extensions = config.get('extensions')
            extensions = pki.util.read_text('  Certificate Extensions', default=extensions)
            pki.util.set_property(config, 'extensions', extensions)

        elif issuer_type == 'pki':

            print()
            print('Enter the location of the PKI server '
                  '(e.g. https://localhost.localdomain:8443).')
            url = config.get('url')
            url = pki.util.read_text('  Server URL', default=url, required=True)
            pki.util.set_property(config, 'url', url)

            print()
            print('Enter the certificate nickname for client authentication.')
            print('This might be the CA agent certificate.')
            print('Enter blank to use basic authentication.')
            nickname = config.get('nickname')
            nickname = pki.util.read_text('  Client Certificate', default=nickname)
            pki.util.set_property(config, 'nickname', nickname)

            print()
            print('Enter the username of the CA agent for basic authentication.')
            print('Enter blank if a CA agent certificate is used for client authentication.')
            username = config.get('username')
            username = pki.util.read_text('  Agent Username', default=username)
            pki.util.set_property(config, 'username', username)

            print()
            print('Enter the CA agent password for basic authentication.')
            print('Enter blank if the password is already stored in a separate property file')
            print('or if a CA agent certificate is used for client authentication.')
            password = config.get('password')
            password = pki.util.read_text('  Agent Password', default=password, password=True)
            pki.util.set_property(config, 'password', password)

            if password:
                config.pop('passwordFile', None)
            else:
                print()
                print('Enter the property file that stores the CA agent password.')
                print('The password must be stored under acmeUserPassword property.')
                password_file = config.get('passwordFile')
                password_file = pki.util.read_text('  Password File', default=password_file)
                pki.util.set_property(config, 'passwordFile', password_file)

            print()
            print('Enter the certificate profile for issuing ACME certificates '
                  '(e.g. acmeServerCert).')
            profile = config.get('profile')
            profile = pki.util.read_text('  Certificate Profile', default=profile, required=True)
            pki.util.set_property(config, 'profile', profile)

            print()
            print('Enter ID of the authority for issuing ACME certificates '
                  '(empty for main CA, subCA ID otherwise).')
            authority_id = config.get('authority-id')
            authority_id = pki.util.read_text(
                '  Authority ID', default=authority_id, required=True)
            if authority_id:
                pki.util.set_property(config, 'authority-id', authority_id)

            if not authority_id:
                print()
                print('Enter DN of the authority for issuing ACME certificates '
                      '(empty for main CA, subCA DN otherwise).')
                authority_dn = config.get('authority-dn')
                authority_dn = pki.util.read_text(
                    '  Authority ID', default=authority_id, required=True)
                if authority_dn:
                    pki.util.set_property(config, 'authority-dn', authority_dn)

        subsystem.update_issuer_config(config)


class ACMERealmCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('realm', 'ACME realm management commands')

        self.add_module(ACMERealmInitCLI())
        self.add_module(ACMERealmShowCLI())
        self.add_module(ACMERealmModifyCLI())


class ACMERealmInitCLI(pki.cli.CLI):
    '''
    Initialize ACME realm
    '''

    help = '''\
        Usage: pki-server acme-realm-init [OPTIONS]

          -i, --instance <instance ID>       Instance ID (default: pki-tomcat)
          -v, --verbose                      Run in verbose mode.
              --debug                        Run in debug mode.
              --help                         Show help message.
    '''

    def __init__(self):
        super().__init__(
            'init',
            inspect.cleandoc(self.__class__.__doc__).format())

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

    def print_help(self):
        print(textwrap.dedent(self.__class__.help).format())

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

        instance = pki.server.PKIServerFactory.create(instance_name)
        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            raise Exception('No %s subsystem in instance %s' %
                            (subsystem_name.upper(), instance_name))

        subsystem.init_realm()


class ACMERealmShowCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('show', 'Show ACME realm configuration')

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

    def print_help(self):
        print('Usage: pki-server acme-realm-show [OPTIONS]')
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
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        acme_conf_dir = os.path.join(instance.conf_dir, 'acme')
        realm_conf = os.path.join(acme_conf_dir, 'realm.conf')
        config = {}

        logger.info('Loading %s', realm_conf)
        pki.util.load_properties(realm_conf, config)

        realm_class = config.get('class')

        realm_type = pki.server.subsystem.ACME_REALM_TYPES.get(realm_class)
        print('  Realm Type: %s' % realm_type)

        if realm_type == 'in-memory':
            username = config.get('username')
            if username:
                print('  Admin Username: %s' % username)

            password = config.get('password')
            if password:
                print('  Admin Password: ********')

        elif realm_type == 'ds':

            url = config.get('url')
            if url:
                print('  Server URL: %s' % url)

            auth_type = config.get('authType')
            if auth_type:
                print('  Authentication Type: %s' % auth_type)

            if auth_type == 'BasicAuth':

                bind_dn = config.get('bindDN')
                if bind_dn:
                    print('  Bind DN: %s' % bind_dn)

                password = config.get('bindPassword')
                if password:
                    print('  Bind Password: ********')

            elif auth_type == 'SslClientAuth':

                nickname = config.get('nickname')
                if nickname:
                    print('  Client Certificate: %s' % nickname)

            users_dn = config.get('usersDN')

            if users_dn:
                print('  Users DN: %s' % users_dn)

            groups_dn = config.get('groupsDN')

            if groups_dn:
                print('  Groups DN: %s' % groups_dn)

        elif realm_type == 'postgresql':

            url = config.get('url')
            if url:
                print('  Server URL: %s' % url)

            username = config.get('user')
            if username:
                print('  Username: %s' % username)

            password = config.get('password')
            if password:
                print('  Password: ********')


class ACMERealmModifyCLI(pki.cli.CLI):

    def __init__(self):
        super().__init__('mod', 'Modify ACME realm configuration')

    def create_parser(self, subparsers=None):

        self.parser = argparse.ArgumentParser(
            self.get_full_name(),
            add_help=False)
        self.parser.add_argument(
            '-i',
            '--instance',
            default='pki-tomcat')
        self.parser.add_argument('--type')
        self.parser.add_argument(
            '-D',
            action='append')
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
        print('Usage: pki-server acme-realm-mod [OPTIONS]')
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --type <type>                  Realm type: {0}'
              .format(', '.join(pki.server.subsystem.ACME_REALM_TYPES.values())))
        print('      -D<name>=<value>               Set property value.')
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

        realm_type = args.type
        if realm_type not in pki.server.subsystem.ACME_REALM_TYPES.values():
            raise Exception('Invalid realm type: {0}'.format(realm_type))

        props = {}
        for param in args.D:
            parts = param.split('=', 1)
            name = parts[0]
            value = parts[1]
            props[name] = value

        instance = pki.server.PKIServerFactory.create(instance_name)

        if not instance.exists():
            raise Exception('Invalid instance: %s' % instance_name)

        instance.load()

        subsystem = pki.server.subsystem.ACMESubsystem(instance)
        config = subsystem.get_realm_config(realm_type=realm_type)

        # if --type or -D is specified, use silent mode
        if realm_type or props:

            logger.info('Setting properties:')
            for name, value in props.items():
                logger.info('- %s: %s', name, value)
                pki.util.set_property(config, name, value)

            subsystem.update_realm_config(config)
            return

        # otherwise, use interactive mode

        print('The current value is displayed in the square brackets.')
        print('To keep the current value, simply press Enter.')
        print('To change the current value, enter the new value.')
        print('To remove the current value, enter a blank space.')

        realm_class = config.get('class')

        print()
        print(
            'Enter the type of the realm. '
            'Available types: %s.' % ', '.join(pki.server.subsystem.ACME_REALM_TYPES.values()))
        realm_type = pki.server.subsystem.ACME_REALM_TYPES.get(realm_class)
        orig_realm_type = realm_type

        realm_type = pki.util.read_text(
            '  Realm Type',
            options=pki.server.subsystem.ACME_REALM_TYPES.values(),
            default=realm_type,
            required=True)
        pki.util.set_property(
            config,
            'class',
            pki.server.subsystem.ACME_REALM_CLASSES.get(realm_type))

        if orig_realm_type != realm_type:
            source = '/usr/share/pki/acme/realm/{0}/realm.conf'.format(realm_type)
            logger.info('Loading %s', source)
            pki.util.load_properties(source, config)

        if realm_type == 'in-memory':

            print()
            print('Enter the admin username.')
            username = config.get('username')
            username = pki.util.read_text('  Admin Username', default=username, required=True)
            pki.util.set_property(config, 'username', username)

            print()
            print('Enter the admin password.')
            password = config.get('password')
            password = pki.util.read_text(
                '  Admin Password',
                default=password,
                password=True,
                required=True)
            pki.util.set_property(config, 'password', password)

        elif realm_type == 'ds':

            print()
            print('Enter the location of the LDAP server '
                  '(e.g. ldap://localhost.localdomain:389).')
            url = config.get('url')
            url = pki.util.read_text('  Server URL', default=url, required=True)
            pki.util.set_property(config, 'url', url)

            print()
            print('Enter the authentication type. Available types: BasicAuth, SslClientAuth.')
            auth_type = config.get('authType')
            auth_type = pki.util.read_text(
                '  Authentication Type',
                options=['BasicAuth', 'SslClientAuth'],
                default=auth_type,
                required=True)
            pki.util.set_property(config, 'authType', auth_type)

            if auth_type == 'BasicAuth':

                print()
                print('Enter the bind DN.')
                bind_dn = config.get('bindDN')
                bind_dn = pki.util.read_text('  Bind DN', default=bind_dn, required=True)
                pki.util.set_property(config, 'bindDN', bind_dn)

                print()
                print('Enter the bind password.')
                password = config.get('bindPassword')
                password = pki.util.read_text(
                    '  Bind Password',
                    default=password,
                    password=True,
                    required=True)
                pki.util.set_property(config, 'bindPassword', password)

            elif auth_type == 'SslClientAuth':

                print()
                print('Enter the client certificate.')
                nickname = config.get('nickname')
                nickname = pki.util.read_text(
                    '  Client Certificate',
                    default=nickname,
                    required=True)
                pki.util.set_property(config, 'nickname', nickname)

            print()
            print('Enter the subtree DN for the ACME users.')

            users_dn = config.get('usersDN')
            users_dn = pki.util.read_text('  Users DN', default=users_dn, required=True)
            pki.util.set_property(config, 'usersDN', users_dn)

            print()
            print('Enter the subtree DN for the ACME groups.')

            groups_dn = config.get('groupsDN')
            groups_dn = pki.util.read_text('  Groups DN', default=groups_dn, required=True)
            pki.util.set_property(config, 'groupsDN', groups_dn)

        elif realm_type == 'postgresql':

            print()
            print('Enter the location of the PostgreSQL realm '
                  '(e.g. jdbc:postgresql://localhost.localdomain:5432/acme).')
            url = config.get('url')
            url = pki.util.read_text('  Server URL', default=url, required=True)
            pki.util.set_property(config, 'url', url)

            print()
            print('Enter the username for basic authentication.')
            username = config.get('user')
            username = pki.util.read_text('  Username', default=username, required=True)
            pki.util.set_property(config, 'user', username)

            print()
            print('Enter the password for basic authentication.')
            password = config.get('password')
            password = pki.util.read_text(
                '  Password', default=password, password=True, required=True)
            pki.util.set_property(config, 'password', password)

        subsystem.update_realm_config(config)
