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
# Copyright (C) 2015 Red Hat, Inc.
# All rights reserved.
#

from __future__ import absolute_import
from __future__ import print_function

import getopt
import logging
import os
import re
import sys

from lxml import etree

import pki.cli
import pki.nssdb
import pki.server.instance
import pki.util

logger = logging.getLogger(__name__)


class MigrateCLI(pki.cli.CLI):

    def __init__(self):
        super(MigrateCLI, self).__init__('migrate', 'Migrate system')

        self.parser = etree.XMLParser(remove_blank_text=True)

    def print_help(self):
        print('Usage: pki-server migrate [OPTIONS] [<instance ID>]')
        print()
        print('  -i, --instance <instance ID> Instance ID.')
        print('      --tomcat <version>       Use the specified Tomcat version.')
        print('  -v, --verbose                Run in verbose mode.')
        print('      --debug                  Show debug messages.')
        print('      --help                   Show help message.')
        print()

    def execute(self, argv):
        try:
            opts, args = getopt.gnu_getopt(argv, 'i:v', [
                'instance=',
                'tomcat=',
                'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            logger.error(e)
            self.print_help()
            sys.exit(1)

        instance_name = None
        tomcat_version = None

        for o, a in opts:
            if o in ('-i', '--instance'):
                instance_name = a

            elif o == '--tomcat':
                tomcat_version = pki.util.Version(a)

            elif o == '--debug':
                logging.getLogger().setLevel(logging.DEBUG)

            elif o in ('-v', '--verbose'):
                logging.getLogger().setLevel(logging.INFO)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                logger.error('Unknown option: %s', o)
                self.print_help()
                sys.exit(1)

        if not tomcat_version:
            tomcat_version = pki.server.Tomcat.get_version()

        if len(args) > 0:
            instance_name = args[0]

        if instance_name:

            instance = pki.server.instance.PKIInstance(instance_name)

            if not instance.exists():
                logger.error('Invalid instance %s.', instance_name)
                sys.exit(1)

            instance.load()

            self.migrate(instance, tomcat_version)

        else:
            instances = pki.server.instance.PKIInstance.instances()

            for instance in instances:
                self.migrate(instance, tomcat_version)

    def migrate(self, instance, tomcat_version):
        self.migrate_nssdb(instance)
        self.migrate_tomcat(instance, tomcat_version)
        self.migrate_subsystems(instance, tomcat_version)
        self.migrate_service(instance)

    def migrate_nssdb(self, instance):

        if not os.path.exists(instance.nssdb_dir):
            return

        logger.info('Migrating %s instance to NSS SQL database', instance.name)

        nssdb = instance.open_nssdb()

        try:
            # Only attempt to convert if target format is sql and DB is dbm
            if nssdb.needs_conversion():
                nssdb.convert_db()
        finally:
            nssdb.close()

        ca_path = os.path.join(instance.nssdb_dir, 'ca.crt')
        token = pki.nssdb.INTERNAL_TOKEN_NAME
        nickname = instance.get_sslserver_cert_nickname()
        if ':' in nickname:
            token = nickname.split(':', 1)[0]

        # Re-open NSS DB with correct token name
        nssdb = instance.open_nssdb(token=token)

        try:
            nssdb.extract_ca_cert(ca_path, nickname)
        finally:
            nssdb.close()

    def migrate_tomcat(self, instance, tomcat_version):

        logger.info('Migrating %s instance to Tomcat %s',
                    instance.name, tomcat_version)

        server_xml = os.path.join(instance.conf_dir, 'server.xml')
        self.migrate_server_xml(instance, server_xml, tomcat_version)

        root_context_xml = os.path.join(
            instance.conf_dir,
            'Catalina',
            'localhost',
            'ROOT.xml')
        self.migrate_context_xml(root_context_xml, tomcat_version)

        pki_context_xml = os.path.join(
            instance.conf_dir,
            'Catalina',
            'localhost',
            'pki.xml')
        self.migrate_context_xml(pki_context_xml, tomcat_version)

    def migrate_server_xml(self, instance, filename, tomcat_version):
        logger.info('Migrating %s', filename)

        document = etree.parse(filename, self.parser)

        if tomcat_version >= pki.util.Version('9.0.31'):
            self.migrate_server_xml_to_tomcat9031(instance, document)

        elif tomcat_version >= pki.util.Version('8.5.0'):
            self.migrate_server_xml_to_tomcat85(instance, document)

        elif tomcat_version >= pki.util.Version('8.0.0'):
            self.migrate_server_xml_to_tomcat80(instance, document)

        elif tomcat_version >= pki.util.Version('7.0.0'):
            self.migrate_server_xml_to_tomcat70(document)

        elif tomcat_version:
            logger.error('Unsupported Tomcat version %s', tomcat_version)
            self.print_help()
            sys.exit(1)

        with open(filename, 'wb') as f:
            # xml as UTF-8 encoded bytes
            document.write(f, pretty_print=True, encoding='utf-8')

    def migrate_server_xml_to_tomcat70(self, document):
        server = document.getroot()

        jasper_comment = etree.Comment(
            'Initialize Jasper prior to webapps are loaded. Documentation '
            'at /docs/jasper-howto.html ')

        jasper_listener = etree.Element('Listener')
        jasper_listener.set(
            'className',
            'org.apache.catalina.core.JasperListener')

        jmx_support_comment = etree.Comment(
            ' JMX Support for the Tomcat server. Documentation at '
            '/docs/non-existent.html ')

        excluded_comment1 = etree.Comment(
            ' The following class has been commented out because it ')
        excluded_comment2 = etree.Comment(
            ' has been EXCLUDED from the Tomcat 7 \'tomcat-lib\' RPM! ')

        server_lifecycle_comment = etree.Comment(
            ' Listener className="org.apache.catalina.mbeans.ServerLifecycleListener" ')

        global_resources_lifecycle_listener = None

        children = list(server)
        for child in children:
            if isinstance(child, etree._Comment):  # pylint: disable=protected-access
                if 'org.apache.catalina.security.SecurityListener' in child.text:
                    server.remove(child)
                elif 'Initialize Jasper prior to webapps are loaded.' in child.text:
                    jasper_comment = None
                elif 'JMX Support for the Tomcat server.' in child.text:
                    jmx_support_comment = None
                elif 'The following class has been commented out because it' in child.text:
                    excluded_comment1 = None
                elif 'has been EXCLUDED from the Tomcat 7 \'tomcat-lib\' RPM!' in child.text:
                    excluded_comment2 = None
                elif 'org.apache.catalina.mbeans.ServerLifecycleListener' in child.text:
                    server_lifecycle_comment = None
                if 'Prevent memory leaks due to use of particular java/javax APIs' in child.text:
                    server.remove(child)

            elif child.tag == 'Listener':
                class_name = child.get('className')

                if class_name in {
                        'org.apache.catalina.startup.VersionLoggerListener',
                        'org.apache.catalina.security.SecurityListener',
                        'org.apache.catalina.mbeans.ServerLifecycleListener',
                        'org.apache.catalina.core.JreMemoryLeakPreventionListener',
                        'org.apache.catalina.core.ThreadLocalLeakPreventionListener'}:

                    logger.debug('* removing %s', class_name)
                    server.remove(child)

                elif class_name == 'org.apache.catalina.core.JasperListener':
                    jasper_listener = None

                elif class_name == 'org.apache.catalina.mbeans.GlobalResourcesLifecycleListener':
                    global_resources_lifecycle_listener = child

        # add before GlobalResourcesLifecycleListener if exists
        if global_resources_lifecycle_listener is not None:
            index = list(server).index(global_resources_lifecycle_listener)

        else:
            index = 0

        if jasper_comment is not None:
            server.insert(index, jasper_comment)
            index += 1

        if jasper_listener is not None:
            logger.debug('* adding %s', jasper_listener.get('className'))
            server.insert(index, jasper_listener)
            index += 1

        if jmx_support_comment is not None:
            server.insert(index, jmx_support_comment)
            index += 1

        if excluded_comment1 is not None:
            server.insert(index, excluded_comment1)
            index += 1

        if excluded_comment2 is not None:
            server.insert(index, excluded_comment2)
            index += 1

        if server_lifecycle_comment is not None:
            server.insert(index, server_lifecycle_comment)
            index += 1

        logger.debug('* updating secure Connector')

        connectors = server.findall('Service/Connector')
        for connector in connectors:
            if connector.get('secure') == 'true':
                connector.set('protocol', 'HTTP/1.1')

        logger.debug('* updating AccessLogValve')

        valves = server.findall('Service/Engine/Host/Valve')
        for valve in valves:
            if valve.get('className') == 'org.apache.catalina.valves.AccessLogValve':
                valve.set('prefix', 'localhost_access_log.')

    def migrate_server_xml_to_tomcat80(self, instance, document):
        server = document.getroot()

        version_logger_listener = etree.Element('Listener')
        version_logger_listener.set(
            'className',
            'org.apache.catalina.startup.VersionLoggerListener')

        security_listener_comment = etree.Comment(''' Security listener. Documentation at /docs/config/listeners.html
  <Listener className="org.apache.catalina.security.SecurityListener" />
  ''')

        jre_memory_leak_prevention_listener = etree.Element('Listener')
        jre_memory_leak_prevention_listener.set(
            'className',
            'org.apache.catalina.core.JreMemoryLeakPreventionListener')

        global_resources_lifecycle_listener = None

        thread_local_leak_prevention_listener = etree.Element('Listener')
        thread_local_leak_prevention_listener.set(
            'className',
            'org.apache.catalina.core.ThreadLocalLeakPreventionListener')

        prevent_comment = etree.Comment(
            ' Prevent memory leaks due to use of particular java/javax APIs')

        children = list(server)
        for child in children:
            if isinstance(child, etree._Comment):  # pylint: disable=protected-access
                if 'org.apache.catalina.security.SecurityListener' in child.text:
                    security_listener_comment = None
                elif 'Initialize Jasper prior to webapps are loaded.' in child.text:
                    server.remove(child)
                elif 'JMX Support for the Tomcat server.' in child.text:
                    server.remove(child)
                elif 'The following class has been commented out because it' in child.text:
                    server.remove(child)
                elif 'has been EXCLUDED from the Tomcat 7 \'tomcat-lib\' RPM!' in child.text:
                    server.remove(child)
                elif 'org.apache.catalina.mbeans.ServerLifecycleListener' in child.text:
                    server.remove(child)
                elif 'Prevent memory leaks due to use of particular java/javax APIs' in child.text:
                    prevent_comment = None

            elif child.tag == 'Listener':
                class_name = child.get('className')

                if class_name == 'org.apache.catalina.core.JasperListener'\
                        or class_name == 'org.apache.catalina.mbeans.ServerLifecycleListener':
                    logger.debug('* removing %s', class_name)
                    server.remove(child)
                elif class_name == 'org.apache.catalina.startup.VersionLoggerListener':
                    version_logger_listener = None
                elif class_name == 'org.apache.catalina.core.JreMemoryLeakPreventionListener':
                    jre_memory_leak_prevention_listener = None
                elif class_name == 'org.apache.catalina.mbeans.GlobalResourcesLifecycleListener':
                    global_resources_lifecycle_listener = child
                elif class_name == 'org.apache.catalina.core.ThreadLocalLeakPreventionListener':
                    thread_local_leak_prevention_listener = None

        # add at the top
        index = 0

        if version_logger_listener is not None:
            logger.debug('* adding VersionLoggerListener')
            server.insert(index, version_logger_listener)
            index += 1

        if security_listener_comment is not None:
            server.insert(index, security_listener_comment)
            index += 1

        # add before GlobalResourcesLifecycleListener if exists
        if global_resources_lifecycle_listener is not None:
            index = list(server).index(global_resources_lifecycle_listener)

        if prevent_comment is not None:
            server.insert(index, prevent_comment)
            index += 1

        if jre_memory_leak_prevention_listener is not None:
            logger.debug('* adding JreMemoryLeakPreventionListener')
            server.insert(index, jre_memory_leak_prevention_listener)
            index += 1

        # add after GlobalResourcesLifecycleListener if exists
        if global_resources_lifecycle_listener is not None:
            index = list(server).index(global_resources_lifecycle_listener) + 1

        if thread_local_leak_prevention_listener is not None:
            logger.debug('* adding ThreadLocalLeakPreventionListener')
            server.insert(index, thread_local_leak_prevention_listener)
            index += 1

        logger.debug('* updating secure Connector')

        connectors = server.findall('Service/Connector')
        for connector in connectors:

            if connector.get('secure') != 'true':
                continue

            connector.set(
                'protocol',
                'org.dogtagpki.tomcat.Http11NioProtocol')

            connector.attrib.pop('sslImplementationName', None)

            connector.set('keystoreType', 'pkcs11')
            connector.set('keystoreProvider', 'Mozilla-JSS')
            connector.attrib.pop('keystoreFile', None)
            connector.attrib.pop('keystorePassFile', None)

            full_name = instance.get_sslserver_cert_nickname()
            connector.set('keyAlias', full_name)

            connector.set('trustManagerClassName', 'org.dogtagpki.tomcat.PKITrustManager')

        logger.debug('* updating AccessLogValve')

        valves = server.findall('Service/Engine/Host/Valve')
        for valve in valves:

            if valve.get(
                    'className') == 'org.apache.catalina.valves.AccessLogValve':
                valve.set('prefix', 'localhost_access_log')

    def migrate_server_xml_to_tomcat85(self, instance, document):

        self.migrate_server_xml_to_tomcat80(instance, document)

        server = document.getroot()

        services = server.findall('Service')
        for service in services:

            children = list(service)
            for child in children:
                if isinstance(child, etree._Comment):  # pylint: disable=protected-access
                    if 'Java HTTP Connector: /docs/config/http.html' in child.text:
                        child.text = child.text.replace(' (blocking & non-blocking)', '')
                    elif 'Shared Ports:  Agent, EE, and Admin Secure Port Connector' in child.text:
                        service.remove(child)
                    elif 'DO NOT REMOVE - Begin define PKI secure port' in child.text:
                        service.remove(child)
                    elif 'DO NOT REMOVE - End define PKI secure port' in child.text:
                        service.remove(child)
                    elif 'protocol="AJP/1.3"' in child.text:
                        child.text = re.sub(r'^ *([^ ]+)=',
                                            r'               \g<1>=',
                                            child.text,
                                            flags=re.MULTILINE)

        logger.debug('* adding SSLHostConfig')

        connectors = server.findall('Service/Connector')
        for connector in connectors:

            if connector.get('secure') != 'true':
                continue

            connector.set('sslImplementationName', 'org.dogtagpki.tomcat.JSSImplementation')
            connector.attrib.pop('sslProtocol', None)
            connector.attrib.pop('clientAuth', None)
            connector.attrib.pop('keystoreType', None)
            connector.attrib.pop('keystoreProvider', None)
            connector.attrib.pop('keyAlias', None)
            connector.attrib.pop('trustManagerClassName', None)

            sslHostConfigs = connector.findall('SSLHostConfig')
            if len(sslHostConfigs) > 0:
                sslHostConfig = sslHostConfigs[0]
            else:
                sslHostConfig = etree.SubElement(connector, 'SSLHostConfig')

            sslHostConfig.set('sslProtocol', 'SSL')
            sslHostConfig.set('certificateVerification', 'optional')
            sslHostConfig.attrib.pop('trustManagerClassName', None)

            certificates = sslHostConfig.findall('Certificate')
            if len(certificates) > 0:
                certificate = certificates[0]
            else:
                certificate = etree.SubElement(sslHostConfig, 'Certificate')

            certificate.set('certificateKeystoreType', 'pkcs11')
            certificate.set('certificateKeystoreProvider', 'Mozilla-JSS')

            full_name = instance.get_sslserver_cert_nickname()
            certificate.set('certificateKeyAlias', full_name)

    def migrate_server_xml_to_tomcat9031(self, instance, document):

        self.migrate_server_xml_to_tomcat85(instance, document)

        server = document.getroot()

        # Migrate requiredSecret -> secret on AJP connectors

        services = server.findall('Service')
        for service in services:

            children = list(service)
            for child in children:
                if isinstance(child, etree._Comment):  # pylint: disable=protected-access
                    if 'protocol="AJP/1.3"' in child.text:
                        child.text = re.sub(r'requiredSecret=',
                                            r'secret=',
                                            child.text,
                                            flags=re.MULTILINE)

        connectors = server.findall('Service/Connector')
        for connector in connectors:
            if connector.get('protocol') != 'AJP/1.3':
                # Only modify AJP connectors.
                continue
            if connector.get('secret'):
                # Nothing to migrate because the secret attribute already
                # exists.
                continue
            if connector.get('requiredSecret') is None:
                # No requiredSecret field either; nothing to do.
                continue

            connector.set('secret', connector.get('requiredSecret'))
            connector.attrib.pop('requiredSecret', None)

    def migrate_subsystems(self, instance, tomcat_version):
        for subsystem in instance.get_subsystems():
            self.migrate_subsystem(subsystem, tomcat_version)

    def migrate_subsystem(self, subsystem, tomcat_version):
        logger.info('Migrating %s/%s subsystem', subsystem.instance.name, subsystem.name)

        self.migrate_context_xml(subsystem.context_xml, tomcat_version)

    def migrate_context_xml(self, filename, tomcat_version):
        if not os.path.exists(filename):
            return

        logger.info('Migrating %s', filename)

        document = etree.parse(filename, self.parser)

        if tomcat_version.major == 7:
            self.migrate_context_xml_to_tomcat7(document)

        elif tomcat_version.major == 8 or tomcat_version.major == 9:
            self.migrate_context_xml_to_tomcat8(document)

        elif tomcat_version:
            logger.error('Invalid Tomcat version %s', tomcat_version)
            self.print_help()
            sys.exit(1)

        with open(filename, 'wb') as f:
            # xml as UTF-8 encoded bytes
            document.write(f, pretty_print=True, encoding='utf-8')

    def migrate_context_xml_to_tomcat7(self, document):
        context = document.getroot()
        context.set('allowLinking', 'true')

        resources = context.find('Resources')

        if resources is not None:

            logger.debug('* removing Resources')

            context.remove(resources)

    def migrate_context_xml_to_tomcat8(self, document):
        context = document.getroot()
        if 'allowLinking' in context.attrib:
            context.attrib.pop('allowLinking')

        resources = context.find('Resources')

        if resources is None:

            logger.debug('* adding Resources')

            resources = etree.Element('Resources')
            context.append(resources)

        resources.set('allowLinking', 'true')

    def create_link(self, instance, source, dest):

        logger.info('Creating %s', dest)

        os.symlink(source, dest)
        os.lchown(dest, instance.uid, instance.gid)

    def migrate_service(self, instance):
        self.migrate_service_java_home(instance)

    def migrate_service_java_home(self, instance):
        # When JAVA_HOME in the Tomcat service config differs from the
        # value in /usr/share/pki/etc/pki.conf, update the value in
        # the service config.

        if "JAVA_HOME" not in os.environ or not os.environ["JAVA_HOME"]:
            logger.debug("Refusing to migrate JAVA_HOME with missing environment variable")
            return

        comment = "JAVA_HOME should be set in /etc/pki/pki.conf instead."

        # Update in /etc/sysconfig/<instance>
        result = self.update_java_home_in_config(instance.service_conf, comment)
        self.write_config(instance.service_conf, result)

        # Update in /etc/pki/<instance>/tomcat.conf
        result = self.update_java_home_in_config(instance.tomcat_conf, comment)
        self.write_config(instance.tomcat_conf, result)

    def update_java_home_in_config(self, path, comment):
        result = []

        target = "JAVA_HOME="

        with open(path, 'r') as conf_fp:
            for line in conf_fp:
                if not line.startswith(target):
                    result.append(line)
                else:
                    comment_line = '# ' + comment + '\n'
                    result.append(comment_line)
                    new_line = '# ' + line
                    result.append(new_line)

        return result

    def write_config(self, path, output):
        with open(path, 'w') as conf_fp:
            for line in output:
                print(line, end='', file=conf_fp)
