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


usage() { echo "Usage: $0 [-v <+1|-1>] [-m <message>]" 1>&2; exit 1; }
if [[ -n "${GERRIT_URL}" ]]
then
    CMD="ssh -p 29418 "${GERRIT_URL}" -o StrictHostKeyChecking=no gerrit review ${TRAVIS_COMMIT}"
    while getopts ":v:m:" o; do
        case "${o}" in
            v)
                v=${OPTARG}
                ((v == +1 || v == -1)) || usage
                CMD="$CMD --verified $v"
                ;;
            m)
                m=${OPTARG}
                CMD="$CMD --message  \"'$m'\""
                ;;
            *)
                usage
                ;;
        esac
    done
    shift "$((OPTIND-1))"
    # For debugging purpose
    echo "${CMD}"
    eval "${CMD}"
else
    echo "Skip setting label..."
fi