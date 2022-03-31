#!/bin/bash -ex
#
# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

# list the available images
docker images

docker run \
    --detach \
    --name=${NAME} \
    --hostname=${HOSTNAME} \
    --privileged \
    --tmpfs /tmp \
    --tmpfs /run \
    -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
    -v ${GITHUB_WORKSPACE}:${PKIDIR} \
    -e BUILDUSER_UID=$(id -u) \
    -e BUILDUSER_GID=$(id -g) \
    -e PKIDIR="${PKIDIR}" \
    -e BUILDUSER="builduser" \
    -e GITHUB_ACTIONS=${GITHUB_ACTIONS} \
    -e GITHUB_RUN_NUMBER=${GITHUB_RUN_NUMBER} \
    -e container=docker \
    --expose=389 \
    --expose=8080 \
    --expose=8443 \
    -i \
    ${IMAGE} "/usr/sbin/init"

# Check whether the container is up
docker ps -a

# Pause 5 seconds to let the container start up.
# The container uses /usr/sbin/init as its entrypoint which requires few seconds
# to startup. This avoids the following error:
# [Errno 2] No such file or directory: '/var/cache/dnf/metadata_lock.pid'
sleep 5
