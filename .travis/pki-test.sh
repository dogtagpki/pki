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
# Copyright (C) 2017 Red Hat, Inc.
# All rights reserved.
#
set -e

# First install pki-core packges as it's the dependency for other packages
docker exec -i ${CONTAINER} ${SCRIPTDIR}/20-install-rpms || exit $?

# Install deps, generate RPMS for all other packages and install them (in order)
docker exec -i ${CONTAINER} ${SCRIPTDIR}/01-install-dependencies dogtag-pki-theme   # meta
docker exec -i ${CONTAINER} ${SCRIPTDIR}/01-install-dependencies pki-console
docker exec -i ${CONTAINER} ${SCRIPTDIR}/01-install-dependencies dogtag-pki

docker exec -i ${CONTAINER} ${SCRIPTDIR}/10-compose-rpms compose_dogtag_pki_theme_packages
docker exec -i ${CONTAINER} ${SCRIPTDIR}/20-install-rpms || exit $?

docker exec -i ${CONTAINER} ${SCRIPTDIR}/10-compose-rpms compose_pki_console_packages
docker exec -i ${CONTAINER} ${SCRIPTDIR}/20-install-rpms || exit $?

docker exec -i ${CONTAINER} ${SCRIPTDIR}/10-compose-rpms compose_dogtag_pki_meta_packages
docker exec -i ${CONTAINER} ${SCRIPTDIR}/20-install-rpms || exit $?

docker exec -i ${CONTAINER} ${SCRIPTDIR}/30-setup-389ds
# Test whether pki subsystem works correctly
docker exec -i ${CONTAINER} ${SCRIPTDIR}/40-spawn-ca
docker exec -i ${CONTAINER} ${SCRIPTDIR}/50-spawn-kra
docker exec -i ${CONTAINER} ${SCRIPTDIR}/99-destroy
# copy pki.server for Python 3
docker exec -i ${CONTAINER} ${SCRIPTDIR}/py3rewrite
docker exec -i ${CONTAINER} ${SCRIPTDIR}/30-setup-389ds
docker exec -i ${CONTAINER} ${SCRIPTDIR}/40-spawn-ca
docker exec -i ${CONTAINER} ${SCRIPTDIR}/50-spawn-kra
docker exec -i ${CONTAINER} ${SCRIPTDIR}/99-destroy
