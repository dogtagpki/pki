#!/usr/bin/python
# -*- coding: utf-8 -*-
# (c) 2016, Geetika Kapoor <gkapoor@redhat.com>
#
# This file is part of Ansible
#
# Ansible is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Ansible is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Ansible.  If not, see <http://www.gnu.org/licenses/>.

ANSIBLE_METADATA = {'metadata_version': '1.0',
                    'status': ['stableinterface'],
                    'supported_by': 'core'}

DOCUMENTATION = '''
---
module: pki
short_description: Execute dogtag "pki" commands remotely on any machine.
Point it to the host where you want them to run.
This utility supports all the authentication modes as mentioned in 
man pages of pki. Refer 'man pki' for supported options.

Usage: This can be added as mentioned in the example.
Authentication types supported:
1. Connection - Plain URI connection
2. Basic Authentication: username/password support
3. Client Authentication: certificate authentication support
conn_args: Name assigned to variable that has common arguments
needed for all types of connection.
auth_args: Name assigned to authentication commands that are run using pki.
cli_args: Name assigned to sub-cli-commands that are run underneath 
pki command.

Example:
- name: Call pki command
  pki: cli='ca-cert-find' authType='connection'

'''

import datetime
import glob
import shlex
import os

if os.path.isfile('/tmp/test_dir/constants.py'):
    import sys
    sys.path.append('/tmp/test_dir')
    import constants
else:
    from pki.testlib.common import constants
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six import b


def main():

    # the command module is the one ansible module that does not take key=value args
    # hence don't copy this one if you are looking to build others!
    module = AnsibleModule(
        argument_spec=dict(
            raw_params = dict(default='pki'),
	    port = dict(default=''),
	    cli = dict(default='--help'),
	    extra_args = dict(default=''),
	    certnick = dict(default="'PKI CA Administrator for Example.Org'"),
	    username = dict(default='caadmin'),
	    userpassword = dict(default='Secret123'),
	    userpwdfile = dict(default='Secret123'),
	    dbpassword = dict(default='Secret123'),
	    nssdb = dict(default='/opt/pkitest/certdb'),
	    protocol = dict(default='http'),
	    hostname = dict(default='localhost'),
	    authType = dict(default='clientAuth', choices=['connection', 'basicAuth', 'clientAuth'])
        )
    )
    if module.params['port']:
	port = module.params['port']
    else:
    	Subsystem=map(lambda x: {"True" if x in module.params['cli'] else False: x } ,["ca", "kra", "ocsp", "tks", "tps"])
    	for idx, val in enumerate(Subsystem):
		for key, value in val.iteritems():
			if key == 'True':
				sub = value
    	port = '_'.join([sub.upper(), module.params['protocol'].upper(), "PORT"])
        port = getattr(constants, port)
    conn_args = [module.params['raw_params'], '-d', module.params['nssdb'], '-P', module.params['protocol'], '-p', '%s' %(port), '-h', module.params['hostname'], '-c', module.params['dbpassword']]
    cli_args = [module.params['cli'], module.params['extra_args']]

    if module.params['authType'] == 'clientAuth':
        auth_args = ['-n', module.params['certnick']]
        args = ' '.join(conn_args + auth_args + cli_args)

    if module.params['authType'] == 'basicAuth':
	auth_args = ['-u', module.params['username'], '-w', module.params['userpassword']]
        args = ' '.join(conn_args + auth_args + cli_args)

    if module.params['authType'] == 'connection':
         args = ' '.join(conn_args)

    rc, out, err = module.run_command(args)

    result = dict(
        cmd      = args,
        stdout   = out.rstrip(b("\r\n")),
        stderr   = err.rstrip(b("\r\n")),
        rc       = rc,
        changed  = True,
    )

    if rc != 0:
        module.fail_json(msg='non-zero return code', **result)

    module.exit_json(**result)


if __name__ == '__main__':
    main()

