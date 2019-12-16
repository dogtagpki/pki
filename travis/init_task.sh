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
set -e

docker pull ${BASE_IMAGE}
docker run \
    --detach \
    --name=${CONTAINER} \
    --hostname='master.pki.test' \
    --privileged \
    --tmpfs /tmp \
    --tmpfs /run \
    -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
    -v $(pwd):/tmp/workdir/pki \
    -e BUILDUSER_UID=$(id -u) \
    -e BUILDUSER_GID=$(id -g) \
    -e BUILDDIR="/tmp/workdir" \
    -e BUILDUSER="builduser" \
    -e TRAVIS=${TRAVIS} \
    -e TRAVIS_JOB_NUMBER=${TRAVIS_JOB_NUMBER} \
    -e PKI_VERSION=${PKI_VERSION} \
    -e IPA_VERSION=${IPA_VERSION} \
    -e container=docker \
    -e test_set="${test_set}" \
    --expose=389 \
    --expose=8080 \
    --expose=8443 \
    -i \
    ${BASE_IMAGE} "/usr/sbin/init"

# Check whether the container is up
docker ps -a

docker exec -i ${CONTAINER} /bin/ls -la /tmp/workdir
docker exec -i ${CONTAINER} ${SCRIPTDIR}/00-init
docker exec -i ${CONTAINER} ${SCRIPTDIR}/01-install-dependencies pki-core
docker exec -i ${CONTAINER} ${SCRIPTDIR}/10-compose-rpms compose_pki_core_packages