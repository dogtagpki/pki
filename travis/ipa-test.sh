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
set -eE

exit_handler() {

    # Save systemd journal
    journalctl -b --no-pager > systemd_journal.txt
    curl -k -w "\n" --upload systemd_journal.txt https://transfer.sh/systemd_journal.txt >> ${BUILDDIR}/pki/logs.txt

    # Save other logs
    LOGS_TAR_NAME="var_log.tar"
    journalctl -b --no-pager > systemd_journal.txt
    tar --ignore-failed-read -cvf /tmp/${LOGS_TAR_NAME} \
        /var/log/dirsrv \
        /var/log/httpd \
        /var/log/ipa* \
        /var/log/krb5kdc.log \
        /var/log/pki

    chown ${BUILDUSER_UID}:${BUILDUSER_GID} /tmp/${LOGS_TAR_NAME}
    curl -k -w "\n" --upload /tmp/${LOGS_TAR_NAME} https://transfer.sh/${LOGS_TAR_NAME} >> ${BUILDDIR}/pki/logs.txt
}


# Print the version of installed components
rpm -qa tomcat* pki-* freeipa-* nss* 389-ds* jss*| sort

# Disable IPV6
sysctl net.ipv6.conf.lo.disable_ipv6=0

# Define constants
server_password="Secret.123"

# Install IPA-server
echo "Installing IPA ..."
ipa-server-install -U --domain pki.test --realm PKI.TEST -p ${server_password} -a ${server_password} --setup-dns --setup-kra --auto-forwarders

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

# Run ipa-tests
ipa-run-tests-3 \
--ignore test_integration \
--ignore test_webui \
--ignore test_ipapython/test_keyring.py \
-k-test_dns_soa \
--verbose \
${cert_test_file_loc}

# Uninstall ipa-server
ipa-server-install --uninstall -U

trap "exit_handler" EXIT
