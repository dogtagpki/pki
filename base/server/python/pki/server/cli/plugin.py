from __future__ import absolute_import
from __future__ import print_function

import getopt
import logging
import sys

import pki.cli

logger = logging.getLogger(__name__)


class AuthPlugin(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPlugin, self).__init__(
            'auth', 'CA Auth plugin commands'
        )
        self.parent = parent
        self.add_module(AuthPluginCLI(self))


class AuthPluginCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginCLI, self).__init__(
            'plugin', 'CA Auth Plugin commands')

        self.parent = parent.parent
        self.add_module(AuthPluginAddCLI(self))
        self.add_module(AuthPluginDelCLI(self))
        self.add_module(AuthPluginShowCLI(self))
        self.add_module(AuthPluginFindCLI(self))
        self.add_module(AuthPluginRegisterCLI(self))

    @staticmethod
    def print_plugin(args, default=False):
        if default:
            print("  Default Plugins list")
            print("  ====================")
            print("    Plugin id \t\t\t Plugin Class")
            print("    --------- \t\t\t ------------")
            for key, val in args.items():
                if key.startswith("auths.impl"):
                    print("    {:<20} \t {val}".format(key.split('.')[2], val=val))
            print()
        for key, val in args.items():
            if not key.startswith("auths.impl"):
                print("  {:<60} {}".format(key, val))


class AuthPluginRegisterCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginRegisterCLI, self).__init__(
            'register', 'Register new auth plugin class'
        )

        self.parent = parent

    def print_help(self):
        print("Usages: pki-server %s-auth-plugin-register [OPTIONS]" % self.parent.parent.parent.name)
        print()
        print('  -t, --type                         Plugin type')
        print('  -c, --class                        Plugin class name')
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:t:c:', [
                'instance=', 'type=',
                'class=', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        plugin_class = ''
        plugin_type = ''
        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--help':
                self.print_help()
                sys.exit()

            elif o in ('-t', '--type'):
                plugin_type = a

            elif o in ('-c', '--class'):
                plugin_class = a
            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        if not plugin_class:
            print("ERROR: Plugin class required.")
            sys.exit(1)

        if not plugin_type:
            print("ERROR: Plugin type rquired")
            sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        subsystem.config['auths.impl.{}.class'.format(type)] = plugin_class
        subsystem.save()
        print("Auth plugin registered.")


class AuthPluginAddCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginAddCLI, self).__init__(
            'add', 'Add auth plugin'
        )

        self.parent = parent

    def print_help(self):
        print("Usages: pki-server %s-auth-plugin-add [OPTIONS]" % self.parent.parent.parent.name)
        print()
        # print('  -f, --file                                 Add plugin from file.')
        print('  -i, --instance <instance ID>               Instance ID (default: pki-tomcat).')
        print('      --help                                 Show help message.')
        print('  -n, --pluginName                           Plugin Instance name.')
        print('  -t, --pluginType                           Plugin Type')
        print()
        print("   Directory server based authentication Plugin required common attributes. ")
        print('  -h, --host                                 LDAP Host.')
        print('  -p, --port                                 LDAP Port.')
        print('      --dnPattern <pattern>                  DNPattern.')
        print('      --stringAttributes <attributes>        LDAP String Attributes. (Ex. mail)')
        print('      --byteAttributes <attributes>          LDAP Byte Attributes. (Ex. mail)')
        print('      --secureConn <True|False>              Secure Connection.')
        print('      --connVersion <version>                LDAP Connection Version.(default: 3)')
        print('      --ldapBaseDN  <base_dn>                LDAP Base DN.')
        print('      --minConn <conn_no>                    LDAP Min connections')
        print('      --maxConn <conn_no>                    LDAP Max connections')
        print()
        print('   Attributes for sharedToken and UidPwdDirPinAuth.')
        print('      --bindDN <bind_dn>                     LDAP Bind DN. (default cn=Directory manager)')
        print('      --password <password>                  LDAP Password.')
        print('      --pass-file <file>                     Password File.')
        print('      --authType <basicAuth|sslClientAuth>   Authentication Type. (default basicAuth)')
        print('      --clientCertNick <cert_nick>           LDAP Auth Client Cert Nick name.')
        print('      --attr <attribute>                     Set Attribute.')
        print()
        print('   Attributes for UidPwdDirPinAuth.')
        print('      --removePin                            Remove Pin. (default false)')
        print()
        print('   Attributes for UidPwdDirAuth.')
        print('      --ldapAttrName <attr_name>            LDAP Attribute name')
        print('      --ldapAttrDesc <attr_desc>            LDAP Attribute description')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:f:h:p:n:t:', [
                'instance=', 'file=', 'host=', 'port=', 'pluginName=', 'removePin=', 'dnPattern=',
                'stringAttributes=', 'byteAttributes=', 'secureConn=', 'connVersion=', 'bindDN=',
                'password=', 'pass-file=', 'clientCertNick=', 'authType=', 'minConn=', 'maxConn=',
                'pluginType=', 'ldapAttrName=', 'ldapAttrDesc=', 'attr=', 'ldapBaseDN=', 'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        file_name = ''
        host = ''
        port = ''
        plugin_name = ''
        remove_pin = False
        dn_pattern = ''
        string_attribute = ''
        byte_attribute = ''
        secure_conn = ''
        conn_version = 3
        bind_dn = ''
        password = ''
        pass_file = ''
        client_cert_nick = ''
        auth_type = ''
        min_conn = ''
        max_conn = ''
        plugin_type = ''
        pin_attr = ''
        base_dn = ''
        attr_desc = ''
        attr_name = ''

        configure_plugin = {}

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--help':
                self.print_help()
                sys.exit()

            elif o in ('-f', '--file-name'):
                print("This option is not yet implemented.")
                sys.exit(1)
            elif o in ('-n', '--pluginName'):
                plugin_name = a
            elif o in ('-t', '--pluginType'):
                plugin_type = a
            elif o in ('-h', '--host'):
                host = a
            elif o in ('-p', '--port'):
                port = a
            elif o == '--dnPattern':
                dn_pattern = a
            elif o == '--stringAttributes':
                string_attribute = a
            elif o == '--byteAttributes':
                byte_attribute = a
            elif o == '--secureConn':
                secure_conn = a
            elif o == '--connVersion':
                conn_version = a
            elif o == '--ldapBaseDN':
                base_dn = a
            elif o == '--minConn':
                min_conn = a
            elif o == '--maxConn':
                max_conn = a
            elif o == '--bindDN':
                bind_dn = a
            elif o == '--password' or o == '--pass-file':
                password = a
                if o == '--pass-file':
                    with open(a) as f:
                        password = f.read().strip()

            elif o == '--authType':
                if a.lower() in ['sslclientauth', 'basicauth']:
                    auth_type = a
                else:
                    print("ERROR: Invalid auth type: {}".format(a))
                    sys.exit(1)
            elif o == '--clientCertNick':
                client_cert_nick = a
            elif o == '--removePin':
                remove_pin = True
            elif o == '--attr':
                pin_attr = a
            elif o == '--ldapAttrName':
                attr_name = a
            elif o == '--ldapAttrDesc':
                attr_desc = a
            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            print('ERROR: No %s subsystem in instance %s.'
                  % (subsystem_name.upper(), instance_name))
            sys.exit(1)

        default_plugin_list = [i.split(".")[2].lower() for i, j in subsystem.config.items()
                               if i.startswith('auths.impl')]

        plugin_base = ''

        if not plugin_name:
            print("ERROR: Missing plugin name.")
            self.print_help()
            sys.exit(1)
        else:
            plugin_base = 'auths.instance.{}.'.format(plugin_name)

        if not plugin_type:
            print("ERROR: Missing plugin type.")
            self.print_help()
            sys.exit(1)
        else:
            if plugin_type.lower() not in default_plugin_list:
                print("ERROR: Not valid plugin type")
                sys.exit(1)
            configure_plugin[plugin_base + 'pluginName'] = plugin_type

        if plugin_type.lower() in ['uidpwddirauth', 'uidpwdpindirauth', 'sharedtoken']:

            if not host:
                print("ERROR: Missing ldap hostname.")
                self.print_help()
                sys.exit(1)
            else:
                configure_plugin[plugin_base + 'ldap.ldapconn.host'] = host

            if not port:
                print("ERROR: Missing ldap port.")
                self.print_help()
                sys.exit(1)
            else:
                configure_plugin[plugin_base + 'ldap.ldapconn.port'] = port

            if not dn_pattern:
                print("ERROR: Missing ldap DN Pattern.")
                self.print_help()
                sys.exit(1)
            else:
                configure_plugin[plugin_base + 'dnpattern'] = dn_pattern

            if not base_dn:
                print("ERROR: Missing ldap basedn")
                self.print_help()
                sys.exit(1)
            else:
                configure_plugin[plugin_base + 'ldap.basedn'] = base_dn

            if not secure_conn:
                configure_plugin[plugin_base + 'ldap.ldapconn.secureConn'] = 'false'
            else:
                configure_plugin[plugin_base + 'ldap.ldapconn.secureConn'] = 'true'

            if not conn_version:
                configure_plugin[plugin_base + 'ldap.ldapconn.version'] = 3
            else:
                configure_plugin[plugin_base + 'ldap.ldapconn.version'] = conn_version

            if not min_conn:
                configure_plugin[plugin_base + 'ldap.minConns'] = ''
            else:
                configure_plugin[plugin_base + 'ldap.minConns'] = min_conn

            if not max_conn:
                configure_plugin[plugin_base + 'ldap.maxConns'] = ''
            else:
                configure_plugin[plugin_base + 'ldap.maxConns'] = max_conn

            if not byte_attribute:
                configure_plugin[plugin_base + 'ldapByteAttributes'] = 'mail'
            else:
                configure_plugin[plugin_base + 'ldapByteAttributes'] = byte_attribute

            if not string_attribute:
                configure_plugin[plugin_base + 'ldapStringAttributes'] = 'mail'
            else:
                configure_plugin[plugin_base + 'ldapStringAttributes'] = string_attribute

            if plugin_type.lower() in ['sharedtoken', 'uidpwdpindirauth']:
                if not pin_attr:
                    configure_plugin[plugin_base + 'shrTokAttr'] = 'mail'
                else:
                    configure_plugin[plugin_base + 'shrTokAttr'] = pin_attr

                if not client_cert_nick:
                    configure_plugin[plugin_base + 'ldap.ldapauth.clientcertNickname'] = ''
                else:
                    configure_plugin[plugin_base + 'ldap.ldapauth.clientcertNickname'] = client_cert_nick

                if not auth_type:
                    configure_plugin[plugin_base + 'ldap.ldapauth.authType'] = 'basicAuth'
                else:
                    configure_plugin[plugin_base + 'ldap.ldapauth.authType'] = auth_type

                if not password:
                    configure_plugin[plugin_base + 'ldap.ldapauth.bindPWPrompt'] = ''
                else:
                    configure_plugin[plugin_base + 'ldap.ldapauth.bindPWPrompt'] = 'Rule {}'.format(plugin_name)

            if plugin_type.lower() == "sharedtoken":
                if not bind_dn:
                    print("ERROR: SharedToken required LDAP Bind DN.")
                    sys.exit(1)
                else:
                    configure_plugin[plugin_base + 'ldap.ldapauth.bindDN'] = bind_dn

            if plugin_type.lower() == 'uidpwdpindirauth':
                if not remove_pin:
                    configure_plugin[plugin_base + 'removePin'] = 'false'
                else:
                    configure_plugin[plugin_base + 'removePin'] = 'true'

            if plugin_type.lower() == 'uidpwddirauth':
                if not attr_name:
                    print("ERROR: UidPwdDirAuth required ldap.attrName")
                    self.print_help()
                    sys.exit(1)
                else:
                    configure_plugin[plugin_base + 'ldap.attrName'] = attr_name

                if not attr_desc:
                    configure_plugin[plugin_base + 'ldap.attrDesc'] = ''

                else:
                    configure_plugin[plugin_base + 'ldap.attrDesc'] = attr_desc
        subsystem.config.update(configure_plugin)
        subsystem.save()
        print("Added plugin {}".format(plugin_name))


class AuthPluginDelCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginDelCLI, self).__init__(
            'del', 'Delete added plugins'
        )
        self.parent = parent

    def print_help(self):
        print("Usages: pki-server %s-auth-plugin-del <plugin_name>" % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:', [
                'instance=', 'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        plugin_id = args[0].strip()

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            print('ERROR: No %s subsystem in instance %s.'
                  % (subsystem_name.upper(), instance_name))
            sys.exit(1)

        for key, val in subsystem.config.items():
            if key.lower().startswith("auths.instance.{}.".format(plugin_id.lower())):
                del subsystem.config[key]
        subsystem.save()
        print("Plugin {} removed from instance {}".format(plugin_id, instance_name))


class AuthPluginFindCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginFindCLI, self).__init__(
            'find', 'Find added plugins'
        )
        self.parent = parent

    def print_help(self):
        print("Usages: pki-server %s-auth-plugin-find [OPTIONS]" % self.parent.parent.parent.name)
        print()
        print('  -d, --default                      List the default available plugins')
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v:d', [
                'instance=', 'default',
                'verbose', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        show_default = False
        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--help':
                self.print_help()
                sys.exit()

            elif o in ('-d', '--default'):
                show_default = True

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            print('ERROR: No %s subsystem in instance %s.'
                  % (subsystem_name.upper(), instance_name))
            sys.exit(1)
        plugin_conf = {}

        print(" Available plugins:")
        print(" ==================")
        if show_default:
            for key, value in subsystem.config.items():
                if key.startswith('auths.impl'):
                    if not key.startswith('auths.impl._'):
                        plugin_conf[key] = value
            AuthPluginCLI.print_plugin(plugin_conf, default=True)
        print("  Configured Plugins")
        print("  ==================")
        for key, value in subsystem.config.items():
            if key.startswith("auths.instance"):
                plugin_conf[key] = value
        AuthPluginCLI.print_plugin(plugin_conf)


class AuthPluginShowCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginShowCLI, self).__init__(
            'show', 'Display plugin configuration')
        self.parent = parent

    def print_help(self):
        print('Usage: pki-server %s-plugin-show <plugin-name>' % self.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('  -o, --output <file_name>           Store in file')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:o:', [
                'instance=', 'output=', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        store = False
        file_name = ''
        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o in ('-o', '--output'):
                store = True
                file_name = a

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print('ERROR: unknown option ' + o)
                self.print_help()
                sys.exit(1)
        if len(args) < 1:
            logger.error('Missing plugin name.')
            self.print_help()
            sys.exit(1)

        plugin_id = args[0].strip()

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        if not subsystem:
            print('ERROR: No %s subsystem in instance %s.'
                  % (subsystem_name.upper(), instance_name))
            sys.exit(1)
        plugin_conf = {}
        default_plugin = None
        for key, value in subsystem.config.items():
            if key.startswith('auths.instance'):
                plugin_conf[key] = value
            if value.lower() == plugin_id.lower():
                default_plugin = key.split(".")[2]

        if default_plugin:
            print("  ")
            print("   Plugin attributes \t\t\t Plugin Values")
            print("   ================= \t\t\t =============")
            # print("    {:<25} \t {}".format("plugin.type", default_plugin))

            for key, value in plugin_conf.items():
                if default_plugin in key:
                    print("    {:<30} \t {val}".format(".".join(key.split(".")[3:]), val=value))

        if store:
            with open(file_name, 'w') as conf_file:
                for key, value in plugin_conf.items():
                    if default_plugin in key:
                        conf_file.write("{}={}\n".format(key, value))
            print("Plugin stored in {}.\n".format(file_name))
