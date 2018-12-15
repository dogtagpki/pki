#!/usr/bin/env python3

# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the Lesser GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public License
#  along with this program; if not, write to the Free Software Foundation,
# Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
# Copyright (C) 2018 Red Hat, Inc.
# All rights reserved.


import getopt
import logging
import os
import subprocess
import sys

import pki.server as server

from pki.keyring import Keyring

logger = logging.getLogger(__name__)

logging.basicConfig(format='%(levelname)s: %(message)s')

tags = set()
keyring = Keyring()


def split_entries(entry):
    return entry.split(',')


def print_help():
    print('Usage: nuxwdog [OPTIONS]')
    print()
    print('      --clear                Clear values stored in keyring.')
    print('      --help                 Show help message.')
    print()


try:
    opts, _ = getopt.gnu_getopt(sys.argv, '', ['clear', 'help'])

except getopt.GetoptError as e:
    logger.error(e)
    print_help()
    sys.exit(1)

for o, a in opts:

    if o == '--clear':
        pass
        # TODO: clear keyring

    elif o == '--help':
        print_help()
        sys.exit()

    else:
        logger.error('option %s not recognized', o)
        print_help()
        sys.exit(1)

# 1. Get <instance> name from env variable NAME set in systemd unit file
instance_name = os.getenv('NAME', 'pki-tomcat')

# 2. Gather list of passwords required
# cms.tokenList,cms.token cms.passwordList --> For each subsystem in the <instance>

# Load the instance
instance = server.PKIInstance(instance_name)
instance.load()

subsystems = instance.subsystems

for subsystem in subsystems:
    password_list = split_entries(subsystem.config['cms.passwordlist'])
    token = subsystem.config['cmc.token']
    tags.update(password_list)
    tags.add(token)

    if 'cmd.tokenList' in subsystem.config:
        tokenList = subsystem.config['cms.tokenList']
        tags.add('hardware-' + tokenList)

# 3a. Prompt the user using systemd-ask-password
# 3b. Put into the keyring using keyctl


for tag in sorted(iter(tags)):
    if tag.startswith('hardware-'):
        prompt_tag = tag[9:]
    else:
        prompt_tag = tag

    prompt = '[' + instance_name + '] Please provide the password for ' + prompt_tag + ': '

    cmd_ask_password = ['systemd-ask-password', prompt]

    entered_pass = subprocess.check_output(cmd_ask_password)

    key_name = instance_name + '/' + tag

    keyring.put_password(key_name=key_name, password=entered_pass)

    print("retrieved: " + key_name + " - " + keyring.get_password(key_name))
# Search the key and get the key ID
# cmd = ["keyctl", "search", "@p", "user", "nuxwdog:usertest"]
# p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
#
# keyID, errs = p.communicate()
#
# keyID = keyID.decode().strip()
#
# print("Python KeyID: " + keyID)
#
# if errs:
#     print("errors1: " + errs.decode())
#
#
# # Retrieve the value of the key
# cmd = ["keyctl", "print", keyID]
#
# p = subprocess.Popen(cmd, stdout=subprocess.PIPE)
#
# keyValue, errs = p.communicate()
#
# keyValue = keyValue.decode().strip()
#
# print("Python KeyValue: " + keyValue)
#
# if errs:
#     print("errors: " + errs.decode())
