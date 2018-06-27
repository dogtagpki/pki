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

pyenv global system 3.6

docker pull ${IMAGE_REPO:-dogtagpki/pki-ci}:${IMAGE}

docker run \
    --detach \
    --name=${CONTAINER} \
    --hostname='pki.test' \
    --privileged \
    --tmpfs /tmp \
    --tmpfs /run \
    -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
    -v $(pwd):${BUILDDIR}/pki \
    -e BUILDUSER_UID=$(id -u) \
    -e BUILDUSER_GID=$(id -g) \
    -e TRAVIS=${TRAVIS} \
    -e TRAVIS_JOB_NUMBER=${TRAVIS_JOB_NUMBER} \
    -i \
    ${IMAGE_REPO:-dogtagpki/pki-ci}:${IMAGE}

docker exec -i ${CONTAINER} /bin/ls -la ${BUILDDIR}
docker exec -i ${CONTAINER} ${SCRIPTDIR}/pki-init.sh
