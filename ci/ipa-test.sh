#!/bin/bash -eEx
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

# Print the version of installed components
rpm -qa tomcat* pki-* freeipa-* nss* 389-ds* jss* | sort

# Disable IPV6
sysctl net.ipv6.conf.lo.disable_ipv6=0

# Define constants
server_password="Secret.123"

# Install IPA-server
echo "Installing IPA ..."
ipa-server-install -U \
    --domain example.com \
    --realm EXAMPLE.COM \
    -p ${server_password} \
    -a ${server_password} \
    --setup-kra \
    --no-host-dns

# Test whether IPA server is reachable
echo ${server_password} | kinit admin && ipa ping

# Setup environment to run tests
cp -r /etc/ipa/* ~/.ipa/
echo ${server_password} > ~/.ipa/.dmpw
echo 'wait_for_dns=5' >> ~/.ipa/default.conf

# Make a list of IPA tests to run
cert_test_file_loc=""
for test_files in ${test_set}; do
    cert_test_file_loc="${cert_test_file_loc} test_xmlrpc/${test_files}"
done
echo "Following IPA tests are scheduled to run: "
echo ${cert_test_file_loc}

echo "Running IPA tests"

ipa-run-tests \
--ignore test_integration \
--ignore test_webui \
--ignore test_ipapython/test_keyring.py \
-k-test_dns_soa \
--verbose \
${cert_test_file_loc} 2>&1

# TODO: Re-enable ipa-healthcheck test once the following issue is fixed.
# https://github.com/freeipa/freeipa-healthcheck/issues/163
#ipa-healthcheck --debug

echo "Test complete"

# Uninstall ipa-server
ipa-server-install --uninstall -U
