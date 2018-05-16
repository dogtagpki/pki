#!/bin/bash
#
# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
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
# Copyright (C) 2018 Red Hat, Inc.
# All rights reserved.
#

# Copy the built RPMS to host machine
echo "Copying binary packages into ${HOST_RPMS}"

mkdir -p ${HOST_RPMS}
docker cp ${CONTAINER}:${BUILDER_RPMS}/. ${HOST_RPMS}
ls -la ${HOST_RPMS}

# IPA related installs
pip install --upgrade pip
pip3 install --upgrade pip
pip install pep8

# Install the ipa-docker-test-runner tool
pip3 install git+https://github.com/freeipa/ipa-docker-test-runner@release-0-3-1
