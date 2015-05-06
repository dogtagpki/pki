#!/usr/bin/python
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

import getopt
import os
import sys

from lxml import etree

import pki.cli
import pki.server


class MigrateCLI(pki.cli.CLI):

    def __init__(self):
        super(MigrateCLI, self).__init__('migrate', 'Migrate system')

        self.parser = etree.XMLParser(remove_blank_text=True)

    def print_help(self):
        print 'Usage: pki-server migrate [OPTIONS]'
        print
        print '      --tomcat <version>       Use the specified Tomcat version.'
        print '  -v, --verbose                Run in verbose mode.'
        print '      --debug                  Show debug messages.'
        print '      --help                   Show help message.'
        print

    def execute(self, argv):

        try:
            opts, _ = getopt.getopt(argv, 'i:v', [
                'tomcat=', 'verbose', 'debug', 'help'])

        except getopt.GetoptError as e:
            print 'ERROR: ' + str(e)
            self.print_help()
            sys.exit(1)

        tomcat_version = None

        for o, a in opts:
            if o == '--tomcat':
                tomcat_version = a

            elif o in ('-v', '--verbose'):
                self.set_verbose(True)

            elif o == '--debug':
                self.set_verbose(True)
                self.set_debug(True)

            elif o == '--help':
                self.print_help()
                sys.exit()

            else:
                print 'ERROR: unknown option ' + o
                self.print_help()
                sys.exit(1)

        if not tomcat_version:
            print 'ERROR: missing Tomcat version'
            self.print_help()
            sys.exit(1)

        instances = pki.server.PKIServer.instances()

        for instance in instances:
            self.migrate(instance, tomcat_version)

        self.print_message('System migrated')

    def migrate(self, instance, tomcat_version):

        self.migrate_instance(instance, tomcat_version)
        self.migrate_subsystems(instance, tomcat_version)

    def migrate_instance(self, instance, tomcat_version):

        server_xml = os.path.join(instance.conf_dir, 'server.xml')
        self.migrate_server_xml(server_xml, tomcat_version)

        root_context_xml = os.path.join(instance.conf_dir, 'Catalina', 'localhost', 'ROOT.xml')
        self.migrate_context_xml(root_context_xml, tomcat_version)

        pki_context_xml = os.path.join(instance.conf_dir, 'Catalina', 'localhost', 'pki.xml')
        self.migrate_context_xml(pki_context_xml, tomcat_version)

        self.migrate_tomcat_libraries(instance)

    def migrate_server_xml(self, filename, tomcat_version):

        if self.verbose:
            print 'Migrating %s' % filename

        document = etree.parse(filename, self.parser)

        if tomcat_version == '7':
            self.migrate_server_xml_to_tomcat7(document)

        elif tomcat_version == '8':
            self.migrate_server_xml_to_tomcat8(document)

        elif tomcat_version:
            print 'ERROR: invalid Tomcat version %s' % tomcat_version
            self.print_help()
            sys.exit(1)

        with open(filename, 'w') as f:
            f.write(etree.tostring(document, pretty_print=True))

    def migrate_server_xml_to_tomcat7(self, document):

        server = document.getroot()

        jasper_comment = etree.Comment('Initialize Jasper prior to webapps are loaded. Documentation at /docs/jasper-howto.html ')

        jasper_listener = etree.Element('Listener')
        jasper_listener.set('className', 'org.apache.catalina.core.JasperListener')

        jmx_support_comment = etree.Comment(' JMX Support for the Tomcat server. Documentation at /docs/non-existent.html ')

        excluded_comment1 = etree.Comment(' The following class has been commented out because it ')
        excluded_comment2 = etree.Comment(' has been EXCLUDED from the Tomcat 7 \'tomcat-lib\' RPM! ')

        server_lifecycle_comment = etree.Comment(' Listener className="org.apache.catalina.mbeans.ServerLifecycleListener" ')

        global_resources_lifecycle_listener = None

        children = list(server)
        for child in children:

            if isinstance(child, etree._Comment): # pylint: disable=protected-access

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

                if class_name == 'org.apache.catalina.startup.VersionLoggerListener'\
                    or class_name == 'org.apache.catalina.security.SecurityListener'\
                    or class_name == 'org.apache.catalina.mbeans.ServerLifecycleListener'\
                    or class_name == 'org.apache.catalina.core.JreMemoryLeakPreventionListener'\
                    or class_name == 'org.apache.catalina.core.ThreadLocalLeakPreventionListener':

                    if self.debug:
                        print '* removing %s' % class_name

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
            if self.debug:
                print '* adding %s' % jasper_listener.get('className')
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

        if self.debug:
            print '* updating secure Connector'

        connectors = server.findall('Service/Connector')
        for connector in connectors:

            if connector.get('secure') == 'true':
                connector.set('protocol', 'HTTP/1.1')

        if self.debug:
            print '* updating AccessLogValve'

        valves = server.findall('Service/Engine/Host/Valve')
        for valve in valves:

            if valve.get('className') == 'org.apache.catalina.valves.AccessLogValve':
                valve.set('prefix', 'localhost_access_log.')

    def migrate_server_xml_to_tomcat8(self, document):

        server = document.getroot()

        version_logger_listener = etree.Element('Listener')
        version_logger_listener.set('className', 'org.apache.catalina.startup.VersionLoggerListener')

        security_listener_comment = etree.Comment(''' Security listener. Documentation at /docs/config/listeners.html
  <Listener className="org.apache.catalina.security.SecurityListener" />
  ''')

        jre_memory_leak_prevention_listener = etree.Element('Listener')
        jre_memory_leak_prevention_listener.set('className', 'org.apache.catalina.core.JreMemoryLeakPreventionListener')

        global_resources_lifecycle_listener = None

        thread_local_leak_prevention_listener = etree.Element('Listener')
        thread_local_leak_prevention_listener.set('className', 'org.apache.catalina.core.ThreadLocalLeakPreventionListener')

        prevent_comment = etree.Comment(' Prevent memory leaks due to use of particular java/javax APIs')

        children = list(server)
        for child in children:

            if isinstance(child, etree._Comment): # pylint: disable=protected-access

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

                    if self.debug:
                        print '* removing %s' % class_name

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
            if self.debug:
                print '* adding VersionLoggerListener'
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
            if self.debug:
                print '* adding JreMemoryLeakPreventionListener'
            server.insert(index, jre_memory_leak_prevention_listener)
            index += 1

        # add after GlobalResourcesLifecycleListener if exists
        if global_resources_lifecycle_listener is not None:
            index = list(server).index(global_resources_lifecycle_listener) + 1

        if thread_local_leak_prevention_listener is not None:
            if self.debug:
                print '* adding ThreadLocalLeakPreventionListener'
            server.insert(index, thread_local_leak_prevention_listener)
            index += 1

        if self.debug:
            print '* updating secure Connector'

        connectors = server.findall('Service/Connector')
        for connector in connectors:

            if connector.get('secure') == 'true':
                connector.set('protocol', 'org.apache.coyote.http11.Http11Protocol')

        if self.debug:
            print '* updating AccessLogValve'

        valves = server.findall('Service/Engine/Host/Valve')
        for valve in valves:

            if valve.get('className') == 'org.apache.catalina.valves.AccessLogValve':
                valve.set('prefix', 'localhost_access_log')

    def migrate_subsystems(self, instance, tomcat_version):

        for subsystem in instance.subsystems:
            self.migrate_subsystem(subsystem, tomcat_version)

    def migrate_subsystem(self, subsystem, tomcat_version):

        self.migrate_context_xml(subsystem.context_xml, tomcat_version)

    def migrate_context_xml(self, filename, tomcat_version):

        if not os.path.exists(filename):
            return

        if self.verbose:
            print 'Migrating %s' % filename

        document = etree.parse(filename, self.parser)

        if tomcat_version == '7':
            self.migrate_context_xml_to_tomcat7(document)

        elif tomcat_version == '8':
            self.migrate_context_xml_to_tomcat8(document)

        elif tomcat_version:
            print 'ERROR: invalid Tomcat version %s' % tomcat_version
            self.print_help()
            sys.exit(1)

        with open(filename, 'w') as f:
            f.write(etree.tostring(document, pretty_print=True))

    def migrate_context_xml_to_tomcat7(self, document):

        context = document.getroot()
        context.set('allowLinking', 'true')

        resources = context.find('Resources')

        if resources is not None:

            if self.debug:
                print '* removing Resources'

            context.remove(resources)

    def migrate_context_xml_to_tomcat8(self, document):

        context = document.getroot()
        if context.attrib.has_key('allowLinking'):
            context.attrib.pop('allowLinking')

        resources = context.find('Resources')

        if resources is None:

            if self.debug:
                print '* adding Resources'

            resources = etree.Element('Resources')
            context.append(resources)

        resources.set('allowLinking', 'true')

    def migrate_tomcat_libraries(self, instance):

        # remove old links
        for filename in os.listdir(instance.lib_dir):

            if not filename.endswith('.jar'):
                continue

            path = os.path.join(instance.lib_dir, filename)

            if self.verbose:
                print 'Removing %s' % path

            os.remove(path)

        tomcat_dir = '/usr/share/tomcat/lib'

        # create new links
        for filename in os.listdir(tomcat_dir):

            if not filename.endswith('.jar'):
                continue

            source = os.path.join(tomcat_dir, filename)
            dest = os.path.join(instance.lib_dir, filename)

            if self.verbose:
                print 'Creating %s' % dest

            os.symlink(source, dest)
            os.lchown(dest, instance.uid, instance.gid)
