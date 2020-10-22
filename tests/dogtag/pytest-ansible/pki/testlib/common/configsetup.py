#!/usr/bin/python
# -*- coding: UTF-8 -*-

"""
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Description: Common  Supporting functions for configuration &
#   Audit logs
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#   This is the library for Common supporting class and Functions.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Geetika Kapoor <gkapoor@redhat.com>
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2019 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
"""
import commands
import ConfigParser
import logging
import os
import re



log = logging.getLogger(__name__)

class Config(object):
    '''
    This class is written to create a configuration let it be CA/KRA/OCSP/TPS/TKS
    or LDAP.If there is a standard section as "DEFAULT" use the function default
    as written else try to use section function.
    '''

    def add_default(self, conf, **kwargs):
        if kwargs.keys() is not None:
            config = ConfigParser.RawConfigParser()
            config.optionxform = str
            for key in kwargs.iterkeys():
                config.set('DEFAULT', key, kwargs[key])
            with open(conf, 'w') as fileobj:
                config.write(fileobj)

    def add_section(self, conf, section, **kwargs):
        if kwargs.keys() is not None:
            config = ConfigParser.RawConfigParser()
            config.optionxform = str
            config.add_section('{}'.format(section))
            for key in kwargs.iterkeys():
                config.set('{}'.format(section), key, kwargs[key])
            with open(conf, 'a') as fileobj:
                config.write(fileobj)

    def search_replace_config(self, file, search='\[.*\]', replace='' ):
        '''
        This basically removes the searched string in a file and replace it with
        some other value.
        :param file: name of dile in which search is going to happen
        :param search:string to be searched for
        :param replace: string searched for it needs to be replace
        :return:it will just modify file
        '''
        if search is not None:
            list_append = []
            try:
                for text in open(file).readlines():
                    re.search(search, text)
                    list_append.append(re.sub(search,replace, text))
            except:
                print("Unable to search for pattern in file")
                sys.exit(1)
            else:
                open(file, 'w').writelines(list_append)


class AuditLogs(object):
    '''
    Check for audit logs after every step
    '''
    def audit_log(self, subsystem, filename, topology, folder = 'signedAudit'):
        '''

        :param subsystem: name of subsystem
        :param folder: name of the folder. default is signedAudit
        :param filename: name of the file where search will happen
        :param topology: depends on which topology operation needs to be executed
        :return: pass this location for searching params in files
        '''
        audit_location = "/var/log/pki/%s/%s/%s/%s" %(topology, subsystem, folder, filename)
        return audit_location

    def change_audit_location(self):
        '''
        Hooks for future enhancements.
        from CS.cfg change location to /tmp/.
        :return:
        '''
        pass

    def read_data(self,file, search):
        '''
        :param file: file whose data we are going to readdown
        :param search for some data
        :return: search a pattern
        '''
        if search is not None:
            try:
                for text in open(file).readlines():
                    re.search(search, text).group(0)
            except:
                print("Unable to search for pattern in file")
                raise
                sys.exit(1)

    def read_logs(self, infile, pattern):
        '''
        :param infile: file to search for pattern
        :param pattern: pattern that needs to be matched in list format
        :return: return data in list format so that number of occurrence
        can be checked and counted.
        '''
        search = []
        with open(infile) as fileobj:
            file = fileobj.readlines()
        for line in file:
            for phrase in pattern:
                if phrase in line:
                    search.append(line)
                    break
        return search


class SearchFunctions(object):

    def find(self, out, search, key='stdout'):
        '''
        This function will look for any keyword in either stdout or stderr
        in  ansible dict output.
        '''
        for values in out.itervalues():
            for items in [x.strip(' ') for x in values[key].splitlines()]:
                if items.startswith('{}'.format(search)):
                    req = items.strip('{}'.format(search))
                    return str(req)

    def assertOutputHelper(self, output, result='stdout'):
        for x in output.keys():
            var = output[x][result]
        return var
