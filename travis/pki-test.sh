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

# Install PKI build dependencies
docker exec -i ${CONTAINER} ${SCRIPTDIR}/01-install-dependencies dogtag-pki-theme
docker exec -i ${CONTAINER} ${SCRIPTDIR}/01-install-dependencies pki-console
docker exec -i ${CONTAINER} ${SCRIPTDIR}/01-install-dependencies dogtag-pki

# Build and install PKI packages
docker exec -i ${CONTAINER} ${SCRIPTDIR}/10-compose-rpms compose_dogtag_pki_theme_packages
docker exec -i ${CONTAINER} ${SCRIPTDIR}/20-install-rpms || exit $?

docker exec -i ${CONTAINER} ${SCRIPTDIR}/10-compose-rpms compose_pki_console_packages
docker exec -i ${CONTAINER} ${SCRIPTDIR}/20-install-rpms || exit $?

docker exec -i ${CONTAINER} ${SCRIPTDIR}/10-compose-rpms compose_dogtag_pki_meta_packages
docker exec -i ${CONTAINER} ${SCRIPTDIR}/20-install-rpms || exit $?

# Test basic PKI installations
docker exec -i ${CONTAINER} ${SCRIPTDIR}/ds-create.sh
docker exec -i ${CONTAINER} ${SCRIPTDIR}/ca-create.sh
docker exec -i ${CONTAINER} ${SCRIPTDIR}/kra-create.sh
docker exec -i ${CONTAINER} ${SCRIPTDIR}/ocsp-create.sh
docker exec -i ${CONTAINER} ${SCRIPTDIR}/tks-create.sh
docker exec -i ${CONTAINER} ${SCRIPTDIR}/remove-all.sh
