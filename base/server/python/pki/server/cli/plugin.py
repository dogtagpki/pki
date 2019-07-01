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
        self.add_module(AuthManagerCLI(self))


class AuthManagerCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthManagerCLI, self).__init__(
            'manager', 'CA Auth plugin manager')
        self.parent = parent
        self.add_module(AuthPluginManagerAddCLI(self))
        self.add_module(AuthPluginManagerDelCLI(self))
        self.add_module(AuthPluginManagerFindCLI(self))


class AuthPluginCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginCLI, self).__init__(
            'plugin', 'CA Auth Plugin commands')

        self.parent = parent.parent
        self.add_module(AuthPluginAddCLI(self))
        self.add_module(AuthPluginDelCLI(self))
        self.add_module(AuthPluginShowCLI(self))
        self.add_module(AuthPluginFindCLI(self))

    @staticmethod
    def print_plugin(args):
        keys = args.keys()
        for key in keys:
            if not key.startswith("auths.impl."):
                nest_keys = args[key]
                print("    Instance Name: {}".format(key.split(".")[-1]))
                if nest_keys.get('pluginName', None):
                    print("    Plugin Name: {}".format(nest_keys['pluginName']))
                if nest_keys.get('agentGroup', None):
                    print("    Plugin Group: {}".format(nest_keys['agentGroup']))
                if nest_keys.get('authAttributes', None):
                    print("    Authentication Attributes: {}".format(nest_keys['authAttributes']))
                if nest_keys.get('deferOnFailure', None):
                    print("    Defer On Failure: {}".format(nest_keys['deferOnFailure']))
                if nest_keys.get('fileName', None):
                    print("    File name: {}".format(nest_keys['fileName']))
                if nest_keys.get('keyAttributes', None):
                    print("    Key Attributes: {}".format(nest_keys['keyAttributes']))
                if nest_keys.get('dnpattern', None):
                    print("    DN Pattern: {}".format(nest_keys['dnpattern']))
                if nest_keys.get('bindDN', None):
                    print("    Bind DN: {}".format(nest_keys['bindDN']))
                if nest_keys.get('bindPWPrompt', None):
                    print("    Bind PW Prompt: {}".format(nest_keys['bindPWPrompt']))
                if nest_keys.get('clientcertNickname', None):
                    print("    Client Cert Nick name: {}".format(nest_keys['clientcertNickname']))
                if nest_keys.get('host', None):
                    print("    Hostname: {}".format(nest_keys['host']))
                if nest_keys.get('port', None):
                    print("    Port: {}".format(nest_keys['port']))
                if nest_keys.get('secureConn', None):
                    print("    Secure Connection: {}".format(nest_keys['secureConn']))
                if nest_keys.get('version', None):
                    print("    Version: {}".format(nest_keys['version']))
                if nest_keys.get('maxConn', None):
                    print("    Max Connections: {}".format(nest_keys['maxConn']))
                if nest_keys.get('minConn', None):
                    print("    Min Connections: {}".format(nest_keys['minConn']))
                if nest_keys.get('basedn', None):
                    print("    Base DN: {}".format(nest_keys['basedn']))
                if nest_keys.get('authType', None):
                    print("    Auth Type: {}".format(nest_keys['authType']))
                if nest_keys.get('ldapByteAttributes', None):
                    print("    LDAP Bytes Attributes: {}".format(nest_keys['ldapByteAttributes']))
                if nest_keys.get('ldapStringAttributes', None):
                    print("    LDAP String Attributes: {}".format(
                        nest_keys['ldapStringAttributes']))
                if nest_keys.get('shrTokAttr', None):
                    print("    Shared Token Attribute: {}".format(nest_keys['shrTokAttr']))
                print()


class AuthPluginManagerAddCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginManagerAddCLI, self).__init__(
            'add', 'Register new auth plugin manager'
        )

        self.parent = parent

    def print_help(self):
        print("Usages: pki-server %s-auth-plugin-manager-add [OPTIONS]"
              % self.parent.parent.parent.name)
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
            print("ERROR: Plugin type required")
            sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        subsystem.config['auths.impl.{}.class'.format(plugin_type)] = plugin_class
        subsystem.save()
        print("Auth plugin Manager registered.")


class AuthPluginManagerDelCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginManagerDelCLI, self).__init__(
            'del', 'Remove auth plugin manager'
        )

        self.parent = parent

    def print_help(self):
        print("Usages: pki-server %s-auth-plugin-manager-del <manager_id>"
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:', [
                'instance=', 'help'])

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
        plugin_type = args[0].strip()
        if not plugin_type:
            print("ERROR: Plugin type required")
            sys.exit(1)

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)
        deleted = False
        for key in list(subsystem.config.keys()):
            if key.startswith('auths.impl.{}.'.format(plugin_type)):
                del subsystem.config[key]
                deleted = True
        subsystem.save()
        if deleted:
            print("Auth plugin manager {} deleted.".format(plugin_type))
        else:
            print("ERROR: Auth plugin manager {} not found.".format(plugin_type))
            sys.exit(1)


class AuthPluginManagerFindCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginManagerFindCLI, self).__init__(
            'find', 'Find auth plugin manager'
        )
        self.parent = parent

    def print_help(self):
        print("Usages: pki-server %s-auth-plugin-manager-find "
              % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:', [
                'instance=', 'help'])

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

        instance = pki.server.PKIInstance(instance_name)
        if not instance.is_valid():
            print('ERROR: Invalid instance %s.' % instance_name)
            sys.exit(1)

        instance.load()

        subsystem_name = self.parent.parent.parent.name
        subsystem = instance.get_subsystem(subsystem_name)

        print("  Configured Plugin Managers.")
        print("  ===========================")
        for key, val in subsystem.config.items():
            if key.startswith("auths.impl.") and not key.startswith('auths.impl._'):
                print("   Manager ID: {}".format(key.split('.')[2]))
                print("   Manager Class: {}".format(val))
                print()


class AuthPluginAddCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginAddCLI, self).__init__(
            'add', 'Add auth plugin instance'
        )

        self.parent = parent

    def print_help(self):
        print("Usages: pki-server %s-auth-plugin-add [OPTIONS]" % self.parent.parent.parent.name)
        print()
        # print('  -f, --file                                 Add plugin from file.')
        print('  -i, --instance <instance ID>               Instance ID (default: pki-tomcat).')
        print('      --help                                 Show help message.')
        print('  -n, --pluginName                           Plugin Instance name.')
        print('  -t, --pluginManager                        Plugin Manger Type')
        print()
        print("   Directory server based authentication Plugin required common attributes. ")
        print('  -h, --host                                 LDAP Host.')
        print('  -p, --port                                 LDAP Port.')
        print('      --dnPattern <pattern>                  DNPattern.')
        print('      --stringAttributes <attributes>        LDAP String Attributes. (Ex. mail)')
        print('      --byteAttributes <attributes>          LDAP Byte Attributes. (Ex. mail)')
        print('      --secureConn                           Enable Secure Connection.')
        print('      --connVersion <version>                LDAP Connection Version.(default: 3)')
        print('      --ldapBaseDN  <base_dn>                LDAP Base DN.')
        print('      --minConn <conn_no>                    LDAP Min connections')
        print('      --maxConn <conn_no>                    LDAP Max connections')
        print()
        print('   Attributes for sharedToken and UidPwdDirPinAuth.')
        print('      --bindDN <bind_dn>                     LDAP Bind DN. (default '
              'cn=Directory manager)')
        print('      --password <password>                  LDAP Password.')
        print('      --pass-file <file>                     Password File.')
        print('      --authType <basicAuth|sslClientAuth>   Authentication Type. '
              '(default basicAuth)')
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
        print('   Attributes for FlatFileAuth.')
        print('      --authAttrib                          Authentication Attributes. '
              '(Default PWD)')
        print('      --deferOnFail                         Defer on Failure. (Default False).')
        print('      --authFile                            Flat file name.')
        print('      --keyAttrib                           Key Attributes. (Default UID)')
        print()
        print('  Attributes for AgentCertAuth, raCertAuth')
        print('      --pluginGroup                         Plugin Group Name')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:f:h:p:n:t:', [
                'instance=', 'file=', 'host=', 'port=', 'pluginName=', 'removePin=', 'dnPattern=',
                'stringAttributes=', 'byteAttributes=', 'secureConn', 'connVersion=', 'bindDN=',
                'password=', 'pass-file=', 'clientCertNick=', 'authType=', 'minConn=', 'maxConn=',
                'pluginManger=', 'ldapAttrName=', 'ldapAttrDesc=', 'attr=', 'ldapBaseDN=',
                'authFile=', 'authAttrib=', 'keyAttrib=', 'pluginGroup=', 'verbose',
                'deferOnFail', 'help'])

        except getopt.GetoptError as e:
            print('ERROR: ' + str(e))
            self.print_help()
            sys.exit(1)

        instance_name = 'pki-tomcat'
        host = ''
        port = ''
        plugin_name = ''
        remove_pin = 'false'
        dn_pattern = ''
        string_attribute = ''
        byte_attribute = 'mail'
        secure_conn = 'false'
        conn_version = 3
        bind_dn = ''
        # password = ''
        client_cert_nick = ''
        auth_type = ''
        min_conn = 3
        max_conn = 3
        plugin_type = ''
        pin_attr = ''
        base_dn = ''
        attr_desc = ''
        attr_name = ''
        auth_attrib = 'PWD'
        auth_file = ''
        key_attrib = 'UID'
        deferOnFail = 'false'
        plugin_group = ''

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
                if a in ['', None]:
                    print("ERROR: Missing ldap hostname.")
                    self.print_help()
                    sys.exit(1)
                host = a
            elif o in ('-p', '--port'):
                if a in ['', None]:
                    print("ERROR: Missing ldap port.")
                    self.print_help()
                    sys.exit(1)
                port = a
            elif o == '--dnPattern':
                if a in ['', None]:
                    print("ERROR: Missing ldap DN Pattern.")
                    self.print_help()
                    sys.exit(1)
                dn_pattern = a
            elif o == '--stringAttributes':
                string_attribute = a
            elif o == '--byteAttributes':
                byte_attribute = a
            elif o == '--secureConn':
                secure_conn = 'true'
            elif o == '--connVersion':
                conn_version = a
            elif o == '--ldapBaseDN':
                if a in ['', None]:
                    print("ERROR: Missing ldap basedn")
                    self.print_help()
                    sys.exit(1)
                base_dn = a
            elif o == '--minConn':
                min_conn = a
            elif o == '--maxConn':
                max_conn = a
            elif o == '--bindDN':
                bind_dn = a
            # elif o == '--password' or o == '--pass-file':
            #     password = a
            #     if o == '--pass-file':
            #         with open(a) as f:
            #             password = f.read().strip()

            elif o == '--authType':
                if a in ['sslclientauth', 'basicauth']:
                    auth_type = a
                else:
                    print("ERROR: Invalid auth type: {}".format(a))
                    sys.exit(1)
            elif o == '--clientCertNick':
                client_cert_nick = a
            elif o == '--removePin':
                remove_pin = 'true'
            elif o == '--attr':
                pin_attr = a
            elif o == '--ldapAttrName':
                attr_name = a
            elif o == '--ldapAttrDesc':
                attr_desc = a
            elif o == '--authAttrib':
                if a not in ['', None] and a.startswith('--'):
                    print("ERROR: Invalid value for authAttrib")
                    self.print_help()
                    sys.exit(1)
                else:
                    auth_attrib = a
            elif o == '--authFile':
                if a not in ['', None] and a.startswith('--'):
                    print("ERROR: Invalid value for AuthFile.")
                    self.print_help()
                    sys.exit(1)
                else:
                    auth_file = a
            elif o == '--keyAttrib':
                if a not in ['', None] and a.startswith('--'):
                    print("ERROR:' Invalid value for keyAttrib.")
                    self.print_help()
                    sys.exit(1)
                else:
                    key_attrib = a
            elif o == '--pluginGroup':
                plugin_group = a
            elif o == '--deferOnFail':
                deferOnFail = True
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

        default_manager_list = [i.split(".")[2] for i in subsystem.config.keys()
                                if i.startswith('auths.impl.')]

        if not plugin_name:
            print("ERROR: Missing plugin name.")
            self.print_help()
            sys.exit(1)

        if subsystem.config.get('auths.instance.{}.pluginName'.format(plugin_name), None):
            manager_name = subsystem.config.get('auths.instance.{}.pluginName'.format(plugin_name))
            err_msg1 = "ERROR: Plugin name already exists."
            err_msg2 = "Plugin {} is instance of {} manager.".format(plugin_name, manager_name)
            print(err_msg1)
            print(err_msg2)
            sys.exit(1)
        else:
            plugin_base = 'auths.instance.{}.'.format(plugin_name)

        if not plugin_type:
            print("ERROR: Missing plugin type.")
            self.print_help()
            sys.exit(1)
        else:
            if plugin_type not in default_manager_list:
                print("ERROR: Not valid plugin type")
                sys.exit(1)
            configure_plugin[plugin_base + 'pluginName'] = plugin_type

        if plugin_type in ['UserPwdDirAuth', 'UidPwdPinDirAuth', 'SharedToken']:

            configure_plugin[plugin_base + 'ldap.ldapconn.host'] = host
            configure_plugin[plugin_base + 'ldap.ldapconn.port'] = port
            configure_plugin[plugin_base + 'dnpattern'] = dn_pattern
            configure_plugin[plugin_base + 'ldap.basedn'] = base_dn
            configure_plugin[plugin_base + 'ldap.ldapconn.secureConn'] = secure_conn
            configure_plugin[plugin_base + 'ldap.ldapconn.version'] = conn_version
            configure_plugin[plugin_base + 'ldap.minConns'] = min_conn
            configure_plugin[plugin_base + 'ldap.maxConns'] = max_conn
            configure_plugin[plugin_base + 'ldapByteAttributes'] = byte_attribute
            configure_plugin[plugin_base + 'ldapStringAttributes'] = string_attribute

            if plugin_type in ['SharedToken', 'UidPwdPinDirAuth']:
                configure_plugin[plugin_base + 'shrTokAttr'] = pin_attr
                configure_plugin[plugin_base +
                                 'ldap.ldapauth.clientcertNickname'] = client_cert_nick
                configure_plugin[plugin_base + 'ldap.ldapauth.authType'] = auth_type
                configure_plugin[plugin_base +
                                 'ldap.ldapauth.bindPWPrompt'] = 'Rule {}'.format(plugin_name)

            if plugin_type == "SharedToken":
                if not bind_dn:
                    print("ERROR: SharedToken required LDAP Bind DN.")
                    sys.exit(1)
                else:
                    configure_plugin[plugin_base + 'ldap.ldapauth.bindDN'] = bind_dn

            if plugin_type == 'UidPwdPinDirAuth':
                configure_plugin[plugin_base + 'removePin'] = remove_pin

            if plugin_type == 'UserPwdDirAuth':
                if not attr_name:
                    print("ERROR: UserPwdDirAuth required ldap.attrName")
                    self.print_help()
                    sys.exit(1)
                else:
                    configure_plugin[plugin_base + 'ldap.attrName'] = attr_name

                configure_plugin[plugin_base + 'ldap.attrDesc'] = attr_desc

        elif plugin_type in ['FlatFileAuth']:
            configure_plugin[plugin_base + 'authAttributes'] = auth_attrib
            configure_plugin[plugin_base + 'fileName'] = auth_file
            configure_plugin[plugin_base + 'keyAttributes'] = key_attrib
            configure_plugin[plugin_base + 'deferOnFailure'] = deferOnFail

        elif plugin_type in ['AgentCertAuth']:
            if not plugin_group:
                print("ERROR: {} required Group option.".format(plugin_type))
                self.print_help()
                sys.exit(1)
            configure_plugin[plugin_base + 'agentGroup'] = plugin_group

        else:
            print("Error: Invalid plugin manager.")
            sys.exit(1)
        subsystem.config.update(configure_plugin)
        subsystem.save()
        print("Added plugin {}".format(plugin_name))


class AuthPluginDelCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginDelCLI, self).__init__(
            'del', 'Delete auth plugin instance'
        )
        self.parent = parent

    def print_help(self):
        print("Usages: pki-server %s-auth-plugin-del <plugin_name>"
              % self.parent.parent.parent.name)
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

        for key in list(subsystem.config.keys()):
            if key.startswith("auths.instance.{}.".format(plugin_id)):
                subsystem.config.pop(key)
        subsystem.save()
        print("Plugin {} removed from instance {}".format(plugin_id, instance_name))


class AuthPluginFindCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginFindCLI, self).__init__(
            'find', 'Find added plugin instances'
        )
        self.parent = parent

    def print_help(self):
        print("Usages: pki-server %s-auth-plugin-find [OPTIONS]" % self.parent.parent.parent.name)
        print()
        print('  -i, --instance <instance ID>       Instance ID (default: pki-tomcat).')
        print('      --help                         Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, _ = getopt.gnu_getopt(argv, 'i:v:d', [
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

        print("  Configured Plugin.")
        print("  ==================")
        instances = []
        for i in subsystem.config.keys():
            if i.startswith('auths.instance.'):
                instances.append(i.split(".")[2].strip())
        for instance in instances:
            plugin_conf['auths.instance.{}'.format(instance)] = {}
            for key, value in subsystem.config.items():
                if key.startswith("auths.instance.{}".format(instance)):
                    plugin_conf['auths.instance.{}'.format(instance)][key.split(".")[-1]] = value

        AuthPluginCLI.print_plugin(plugin_conf)


class AuthPluginShowCLI(pki.cli.CLI):
    def __init__(self, parent):
        super(AuthPluginShowCLI, self).__init__(
            'show', 'Display plugin instance configuration')
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
        instances = []
        for i in subsystem.config.keys():
            if i.startswith('auths.instance.{}'.format(plugin_id)):
                instances.append(i.split(".")[2].strip())
        for instance in instances:
            plugin_conf['auths.instance.{}'.format(instance)] = {}
            for key, value in subsystem.config.items():
                if key.startswith("auths.instance.{}".format(instance)):
                    plugin_conf['auths.instance.{}'.format(instance)][key.split(".")[-1]] = value

        AuthPluginCLI.print_plugin(plugin_conf)

        if store:
            with open(file_name, 'w') as conf_file:
                for key, value in plugin_conf.items():
                    if isinstance(value, dict):
                        for k, v in value.items():
                            conf_file.write("{}.{}={}\n".format(key, k, v))
            print("    Plugin stored in {}.\n".format(file_name))
