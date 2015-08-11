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
#

import os
import re
from distutils.core import setup


UPGRADE_SCRIPT = re.compile('^[0-9]+-.*')

def find_upgrade(origroot, destroot):
    upgrades = {}
    for dirpath, dirnames, filenames in os.walk(origroot):
        for filename in filenames:
            if UPGRADE_SCRIPT.match(filename):
                version = os.path.basename(dirpath)
                orig = os.path.join(dirpath, filename)
                dest = os.path.join(destroot, version)
                upgrades.setdefault(dest, []).append(orig)
    return upgrades

upgrades = {}
upgrades.update(find_upgrade('base/common/upgrade',
                             'share/pki/upgrade'))
upgrades.update(find_upgrade('base/server/upgrade',
                             'share/pki/server/upgrade'))

setup(
    author='Dogtag Certificate System Team',
    author_email='pki-devel@redhat.com',
    name='Dogtag PKI',
    version='10',
    description='Dogtag Certificate System',
    license='GPL',
    keywords='pki',
    url='http://pki.fedoraproject.org/',
    package_dir={
        'pki': 'base/common/python/pki',
        'pki.server': 'base/server/python/pki/server'
    },
    packages=[
        'pki',
        'pki.cli',
        'pki.server',
        'pki.server.cli',
        'pki.server.deployment',
        'pki.server.deployment.scriptlets',
    ],
    scripts=[
        'base/common/sbin/pki-upgrade',
        'base/server/sbin/pkidestroy',
        'base/server/sbin/pki-server',
        'base/server/sbin/pki-server-upgrade',
        'base/server/sbin/pkispawn',
        'base/java-tools/bin/pki',
    ],
    data_files=upgrades.items(),
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Environment :: Web Environment',
        'Intended Audience :: System Administrators',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.7',
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
    ],
)
