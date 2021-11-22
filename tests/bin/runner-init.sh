#!/bin/bash -ex
#
# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

NAME=$1

if [ "$NAME" == "" ]
then
    echo "Usage: runner-init.sh <name>"
    exit 1
fi

if [ "$IMAGE" == "" ]
then
    IMAGE=pki-runner
fi

docker run \
    --detach \
    --name=${NAME} \
    --hostname=${HOSTNAME} \
    --privileged \
    --tmpfs /tmp \
    --tmpfs /run \
    -v ${GITHUB_WORKSPACE}:${SHARED} \
    -e BUILDUSER_UID=$(id -u) \
    -e BUILDUSER_GID=$(id -g) \
    -e SHARED="${SHARED}" \
    -e BUILDUSER="builduser" \
    -e GITHUB_ACTIONS=${GITHUB_ACTIONS} \
    -e GITHUB_RUN_NUMBER=${GITHUB_RUN_NUMBER} \
    -e container=docker \
    --expose=389 \
    --expose=8080 \
    --expose=8443 \
    -i \
    ${IMAGE} "/usr/sbin/init"

# Pause 5 seconds to let the container start up.
# The container uses /usr/sbin/init as its entrypoint which requires few seconds
# to startup. This avoids the following error:
# [Errno 2] No such file or directory: '/var/cache/dnf/metadata_lock.pid'
sleep 5
