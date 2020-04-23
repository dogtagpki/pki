#!/bin/bash -ex
#
# Authors:
#     Dinesh Prasanth M K <dmoluguw@redhat.com>
#
# Copyright Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later
#

docker pull ${IMAGE}

docker run \
    --detach \
    --name=${CONTAINER} \
    --hostname='master.pki.test' \
    --privileged \
    --tmpfs /tmp \
    --tmpfs /run \
    -v /sys/fs/cgroup:/sys/fs/cgroup:ro \
    -v ${GITHUB_WORKSPACE}:${PKIDIR} \
    -e BUILDUSER_UID=$(id -u) \
    -e BUILDUSER_GID=$(id -g) \
    -e BUILDDIR="${BUILDDIR}" \
    -e PKIDIR="${PKIDIR}" \
    -e BUILDUSER="builduser" \
    -e GITHUB_ACTIONS=${GITHUB_ACTIONS} \
    -e GITHUB_RUN_NUMBER=${GITHUB_RUN_NUMBER} \
    -e COPR_REPO="${COPR_REPO}" \
    -e container=docker \
    -e test_set="${test_set}" \
    -e LOGS="${LOGS}" \
    --expose=389 \
    --expose=8080 \
    --expose=8443 \
    -i \
    ${IMAGE} "/usr/sbin/init"

# Check whether the container is up
docker ps -a
