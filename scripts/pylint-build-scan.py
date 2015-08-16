#!/usr/bin/python

# Authors:
#     Christian Heimes <cheimes@redhat.com>
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

from __future__ import absolute_import
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import os
import pprint
import re
import subprocess
import sys

from distutils.sysconfig import get_python_lib  # pylint: disable=F0401


SCRIPTPATH = os.path.dirname(os.path.abspath(__file__))
PYLINTRC = os.path.join(SCRIPTPATH, 'dogtag.pylintrc')
FILENAMES = [
    os.path.abspath(__file__),
    '{sitepackages}/pki',
    '{bin}/pki',
    '{sbin}/pkispawn',
    '{sbin}/pkidestroy',
    '{sbin}/pki-upgrade',
    '{sbin}/pki-server',
    '{sbin}/pki-server-upgrade',
]
UPGRADE_SCRIPT = re.compile('^[0-9]+-.*')


def tox_env(args):
    """Paths for tox environment"""
    prefix = args.prefix
    env = {
        'bin': os.path.join(prefix, 'bin'),
        'sbin': os.path.join(prefix, 'bin'),
        'sharepki': os.path.join(prefix, 'share', 'pki'),
        'sitepackages': get_python_lib()
    }
    return env


def rpm_env(args):
    """Paths for RPM build environment"""
    prefix = args.prefix
    relative = get_python_lib().lstrip(os.sep)
    env = {
        'bin': os.path.join(prefix, 'usr', 'bin'),
        'sbin': os.path.join(prefix, 'usr', 'sbin'),
        'sharepki': os.path.join(prefix, 'usr', 'share', 'pki'),
        'sitepackages': os.path.join(prefix, relative),
    }
    return env


def find_upgrades(root):
    """Find upgrade scripts"""
    for dirpath, _, filenames in os.walk(root):
        for filename in filenames:
            if UPGRADE_SCRIPT.match(filename):
                yield os.path.join(dirpath, filename)


def main():
    """Dogtag pylint script"""
    parser = argparse.ArgumentParser(
        description=main.__doc__,
        epilog="Additional arguments can be passed to pylint with: "
               "'-- --arg1 --arg2 ...'",
    )
    parser.add_argument('--verbose', action='store_true')
    subparsers = parser.add_subparsers(dest='command')
    subparsers.required = True

    toxparser = subparsers.add_parser('tox', help='tox in-tree tests')
    toxparser.add_argument('--prefix', dest='prefix', default=sys.prefix)
    toxparser.add_argument('pylint_args', nargs=argparse.REMAINDER)
    toxparser.set_defaults(get_env=tox_env)

    rpmparser = subparsers.add_parser('rpm', help='RPM source tree tests')
    rpmparser.add_argument('--prefix', dest='prefix', required=True)
    rpmparser.add_argument('pylint_args', nargs=argparse.REMAINDER)
    rpmparser.set_defaults(get_env=rpm_env)

    args = parser.parse_args()
    env = args.get_env(args)
    if args.verbose:
        pprint.pprint(env)
    # sanity check
    for key, path in env.items():
        if not os.path.exists(path):
            raise RuntimeError('{} ({}) does not exist'.format(key, path))

    if args.pylint_args and args.pylint_args[0] == '--':
        extra_args = args.pylint_args[1:]
    else:
        extra_args = args.pylint_args

    if not os.path.isfile(PYLINTRC):
        raise IOError('{} not found'.format(PYLINTRC))

    pylint = [
        'pylint',
        '--rcfile={}'.format(PYLINTRC)
    ]
    pylint.extend(extra_args)
    pylint.extend(filename.format(**env) for filename in FILENAMES)
    pylint.extend(find_upgrades('{sharepki}/upgrade'.format(**env)))
    pylint.extend(find_upgrades('{sharepki}/server/upgrade'.format(**env)))
    if args.verbose:
        pprint.pprint(pylint)

    return subprocess.call(pylint, cwd=env['sitepackages'])

if __name__ == '__main__':
    sys.exit(main())
