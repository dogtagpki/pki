#!/bin/sh
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/PKI_TEST_USER_ID
#   Description: Dogtag-10/CS-9 testing
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# Libraries Included:
#	rhcs-shared.sh pki-user-cli-lib.sh rhcs-install-shared.sh
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Copyright (c) 2013 Red Hat, Inc. All rights reserved.
#
#   This copyrighted material is made available to anyone wishing
#   to use, modify, copy, or redistribute it subject to the terms
#   and conditions of the GNU General Public License version 2.
#
#   This program is distributed in the hope that it will be
#   useful, but WITHOUT ANY WARRANTY; without even the implied
#   warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR
#   PURPOSE. See the GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public
#   License along with this program; if not, write to the Free
#   Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
#   Boston, MA 02110-1301, USA.
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/rhcs-install-shared.sh
. /opt/rhqa_pki/pki-user-cli-lib.sh
. /opt/rhqa_pki/env.sh
. /opt/rhqa_pki/saving_codecoverage_results.sh

# Include tests
. ./topologies.sh
. ./acceptance/quickinstall/rhcs-set-time.sh
. ./acceptance/quickinstall/rhcs-install.sh
. ./acceptance/cli-tests/pki-tests-setup/create-role-users.sh
. ./acceptance/cli-tests/pki-tests-setup/cleanup-role-users.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-add-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-show-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-mod-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-find-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-del-ca.sh
. ./dev_java_tests/run_junit_tests.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-membership-add-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-membership-find-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-membership-del-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-find-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-add-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-show-ca.sh
. ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-delete-ca.sh
. ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-add-kra.sh
. ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-show-kra.sh
. ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-mod-kra.sh
. ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-find-kra.sh
. ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-del-kra.sh
. ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-membership-add-kra.sh
. ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-membership-find-kra.sh
. ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-membership-del-kra.sh
. ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-cert-find-kra.sh
. ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-cert-add-kra.sh
. ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-cert-show-kra.sh
. ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-cert-delete-kra.sh
. ./acceptance/cli-tests/pki-user-cli/ocsp/pki-user-cli-user-add-ocsp.sh
. ./acceptance/cli-tests/pki-user-cli/ocsp/pki-user-cli-user-show-ocsp.sh
. ./acceptance/cli-tests/pki-user-cli/ocsp/pki-user-cli-user-mod-ocsp.sh
. ./acceptance/cli-tests/pki-user-cli/ocsp/pki-user-cli-user-find-ocsp.sh
. ./acceptance/cli-tests/pki-user-cli/ocsp/pki-user-cli-user-del-ocsp.sh
. ./acceptance/cli-tests/pki-user-cli/ocsp/pki-user-cli-user-membership-add-ocsp.sh
. ./acceptance/cli-tests/pki-user-cli/ocsp/pki-user-cli-user-membership-find-ocsp.sh
. ./acceptance/cli-tests/pki-user-cli/ocsp/pki-user-cli-user-membership-del-ocsp.sh
. ./acceptance/cli-tests/pki-user-cli/ocsp/pki-user-cli-user-cert-find-ocsp.sh
. ./acceptance/cli-tests/pki-user-cli/ocsp/pki-user-cli-user-cert-add-ocsp.sh
. ./acceptance/cli-tests/pki-user-cli/ocsp/pki-user-cli-user-cert-show-ocsp.sh
. ./acceptance/cli-tests/pki-user-cli/ocsp/pki-user-cli-user-cert-delete-ocsp.sh
. ./acceptance/cli-tests/pki-user-cli/tks/pki-user-cli-user-add-tks.sh
. ./acceptance/cli-tests/pki-user-cli/tks/pki-user-cli-user-show-tks.sh
. ./acceptance/cli-tests/pki-user-cli/tks/pki-user-cli-user-mod-tks.sh
. ./acceptance/cli-tests/pki-user-cli/tks/pki-user-cli-user-find-tks.sh
. ./acceptance/cli-tests/pki-user-cli/tks/pki-user-cli-user-del-tks.sh
. ./acceptance/cli-tests/pki-user-cli/tks/pki-user-cli-user-membership-add-tks.sh
. ./acceptance/cli-tests/pki-user-cli/tks/pki-user-cli-user-membership-find-tks.sh
. ./acceptance/cli-tests/pki-user-cli/tks/pki-user-cli-user-membership-del-tks.sh
. ./acceptance/cli-tests/pki-user-cli/tks/pki-user-cli-user-cert-find-tks.sh
. ./acceptance/cli-tests/pki-user-cli/tks/pki-user-cli-user-cert-add-tks.sh
. ./acceptance/cli-tests/pki-user-cli/tks/pki-user-cli-user-cert-show-tks.sh
. ./acceptance/cli-tests/pki-user-cli/tks/pki-user-cli-user-cert-delete-tks.sh
. ./acceptance/cli-tests/pki-user-cli/tps/pki-user-cli-user-add-tps.sh
. ./acceptance/cli-tests/pki-user-cli/tps/pki-user-cli-user-show-tps.sh
. ./acceptance/cli-tests/pki-user-cli/tps/pki-user-cli-user-mod-tps.sh
. ./acceptance/cli-tests/pki-user-cli/tps/pki-user-cli-user-find-tps.sh
. ./acceptance/cli-tests/pki-user-cli/tps/pki-user-cli-user-del-tps.sh
. ./acceptance/cli-tests/pki-user-cli/tps/pki-user-cli-user-membership-add-tps.sh
. ./acceptance/cli-tests/pki-user-cli/tps/pki-user-cli-user-membership-find-tps.sh
. ./acceptance/cli-tests/pki-user-cli/tps/pki-user-cli-user-membership-del-tps.sh
. ./acceptance/cli-tests/pki-user-cli/tps/pki-user-cli-user-cert-find-tps.sh
. ./acceptance/cli-tests/pki-user-cli/tps/pki-user-cli-user-cert-add-tps.sh
. ./acceptance/cli-tests/pki-user-cli/tps/pki-user-cli-user-cert-show-tps.sh
. ./acceptance/cli-tests/pki-user-cli/tps/pki-user-cli-user-cert-delete-tps.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-show.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-request-show.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-bigInt.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-revoke.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-release-hold.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-hold.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-submit-ca.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-profile-find-ca.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-profile-show-ca.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-review-ca.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-find-ca.sh
. ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-find-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-cert-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-show-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-show-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-revoke-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-release-hold-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-cert-hold-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-submit-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-profile-find-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-show-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-review-ca.sh
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-find-ca.sh 
. ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-find-ca.sh
. ./acceptance/cli-tests/pki-group-cli/ca/pki-group-cli-group-add-ca.sh
. ./acceptance/cli-tests/pki-group-cli/ca/pki-group-cli-group-show-ca.sh
. ./acceptance/cli-tests/pki-group-cli/ca/pki-group-cli-group-find-ca.sh
. ./acceptance/cli-tests/pki-group-cli/ca/pki-group-cli-group-mod-ca.sh
. ./acceptance/cli-tests/pki-group-cli/ca/pki-group-cli-group-del-ca.sh
. ./acceptance/cli-tests/pki-group-cli/ca/pki-group-cli-group-member-add-ca.sh
. ./acceptance/cli-tests/pki-group-cli/ca/pki-group-cli-group-member-find-ca.sh
. ./acceptance/cli-tests/pki-group-cli/ca/pki-group-cli-group-member-del-ca.sh
. ./acceptance/cli-tests/pki-group-cli/ca/pki-group-cli-group-member-show-ca.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-add.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-show.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-find.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-del.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-membership-add.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-membership-find.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-membership-del.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-mod.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert-add.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert-find.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert-show.sh
. ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert-delete.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-add.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-mod.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-find.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-show.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-del.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-add.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-show.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-find.sh
. ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-del.sh
. ./acceptance/cli-tests/pki-group-cli/kra/pki-group-cli-group-show-kra.sh
. ./acceptance/cli-tests/pki-group-cli/kra/pki-group-cli-group-find-kra.sh
. ./acceptance/cli-tests/pki-group-cli/kra/pki-group-cli-group-mod-kra.sh
. ./acceptance/cli-tests/pki-group-cli/kra/pki-group-cli-group-del-kra.sh
. ./acceptance/cli-tests/pki-group-cli/kra/pki-group-cli-group-member-add-kra.sh
. ./acceptance/cli-tests/pki-group-cli/kra/pki-group-cli-group-member-find-kra.sh
. ./acceptance/cli-tests/pki-group-cli/kra/pki-group-cli-group-member-del-kra.sh
. ./acceptance/cli-tests/pki-group-cli/kra/pki-group-cli-group-member-show-kra.sh
. ./acceptance/cli-tests/pki-group-cli/ocsp/pki-group-cli-group-add-ocsp.sh
. ./acceptance/cli-tests/pki-group-cli/ocsp/pki-group-cli-group-show-ocsp.sh
. ./acceptance/cli-tests/pki-group-cli/ocsp/pki-group-cli-group-find-ocsp.sh
. ./acceptance/cli-tests/pki-group-cli/ocsp/pki-group-cli-group-mod-ocsp.sh
. ./acceptance/cli-tests/pki-group-cli/ocsp/pki-group-cli-group-del-ocsp.sh
. ./acceptance/cli-tests/pki-group-cli/ocsp/pki-group-cli-group-member-add-ocsp.sh
. ./acceptance/cli-tests/pki-group-cli/ocsp/pki-group-cli-group-member-find-ocsp.sh
. ./acceptance/cli-tests/pki-group-cli/ocsp/pki-group-cli-group-member-del-ocsp.sh
. ./acceptance/cli-tests/pki-group-cli/ocsp/pki-group-cli-group-member-show-ocsp.sh
. ./acceptance/cli-tests/pki-group-cli/tks/pki-group-cli-group-add-tks.sh
. ./acceptance/cli-tests/pki-group-cli/tks/pki-group-cli-group-show-tks.sh
. ./acceptance/cli-tests/pki-group-cli/tks/pki-group-cli-group-find-tks.sh
. ./acceptance/cli-tests/pki-group-cli/tks/pki-group-cli-group-mod-tks.sh
. ./acceptance/cli-tests/pki-group-cli/tks/pki-group-cli-group-del-tks.sh
. ./acceptance/cli-tests/pki-group-cli/tks/pki-group-cli-group-member-add-tks.sh
. ./acceptance/cli-tests/pki-group-cli/tks/pki-group-cli-group-member-find-tks.sh
. ./acceptance/cli-tests/pki-group-cli/tks/pki-group-cli-group-member-del-tks.sh
. ./acceptance/cli-tests/pki-group-cli/tks/pki-group-cli-group-member-show-tks.sh
. ./acceptance/cli-tests/pki-group-cli/tps/pki-group-cli-group-add-tps.sh
. ./acceptance/cli-tests/pki-group-cli/tps/pki-group-cli-group-show-tps.sh
. ./acceptance/cli-tests/pki-group-cli/tps/pki-group-cli-group-find-tps.sh
. ./acceptance/cli-tests/pki-group-cli/tps/pki-group-cli-group-mod-tps.sh
. ./acceptance/cli-tests/pki-group-cli/tps/pki-group-cli-group-del-tps.sh
. ./acceptance/cli-tests/pki-group-cli/tps/pki-group-cli-group-member-add-tps.sh
. ./acceptance/cli-tests/pki-group-cli/tps/pki-group-cli-group-member-find-tps.sh
. ./acceptance/cli-tests/pki-group-cli/tps/pki-group-cli-group-member-del-tps.sh
. ./acceptance/cli-tests/pki-group-cli/tps/pki-group-cli-group-member-show-tps.sh
. ./acceptance/cli-tests/pki-ocsp-group-cli/pki-ocsp-group-cli-ocsp-group-add.sh
. ./acceptance/cli-tests/pki-ocsp-group-cli/pki-ocsp-group-cli-ocsp-group-mod.sh
. ./acceptance/cli-tests/pki-ocsp-group-cli/pki-ocsp-group-cli-ocsp-group-find.sh
. ./acceptance/cli-tests/pki-ocsp-group-cli/pki-ocsp-group-cli-ocsp-group-show.sh
. ./acceptance/cli-tests/pki-ocsp-group-cli/pki-ocsp-group-cli-ocsp-group-del.sh
. ./acceptance/cli-tests/pki-ocsp-group-cli/pki-ocsp-group-cli-ocsp-group-member-add.sh
. ./acceptance/cli-tests/pki-ocsp-group-cli/pki-ocsp-group-cli-ocsp-group-member-show.sh
. ./acceptance/cli-tests/pki-ocsp-group-cli/pki-ocsp-group-cli-ocsp-group-member-find.sh
. ./acceptance/cli-tests/pki-ocsp-group-cli/pki-ocsp-group-cli-ocsp-group-member-del.sh
. ./acceptance/cli-tests/pki-tks-group-cli/pki-tks-group-cli-tks-group-add.sh
. ./acceptance/cli-tests/pki-tks-group-cli/pki-tks-group-cli-tks-group-mod.sh
. ./acceptance/cli-tests/pki-tks-group-cli/pki-tks-group-cli-tks-group-find.sh
. ./acceptance/cli-tests/pki-tks-group-cli/pki-tks-group-cli-tks-group-show.sh
. ./acceptance/cli-tests/pki-tks-group-cli/pki-tks-group-cli-tks-group-del.sh
. ./acceptance/cli-tests/pki-tks-group-cli/pki-tks-group-cli-tks-group-member-add.sh
. ./acceptance/cli-tests/pki-tks-group-cli/pki-tks-group-cli-tks-group-member-show.sh
. ./acceptance/cli-tests/pki-tks-group-cli/pki-tks-group-cli-tks-group-member-find.sh
. ./acceptance/cli-tests/pki-tks-group-cli/pki-tks-group-cli-tks-group-member-del.sh
. ./acceptance/cli-tests/pki-tps-group-cli/pki-tps-group-cli-tps-group-add.sh
. ./acceptance/cli-tests/pki-tps-group-cli/pki-tps-group-cli-tps-group-mod.sh
. ./acceptance/cli-tests/pki-tps-group-cli/pki-tps-group-cli-tps-group-find.sh
. ./acceptance/cli-tests/pki-tps-group-cli/pki-tps-group-cli-tps-group-show.sh
. ./acceptance/cli-tests/pki-tps-group-cli/pki-tps-group-cli-tps-group-del.sh
. ./acceptance/cli-tests/pki-tps-group-cli/pki-tps-group-cli-tps-group-member-add.sh
. ./acceptance/cli-tests/pki-tps-group-cli/pki-tps-group-cli-tps-group-member-show.sh
. ./acceptance/cli-tests/pki-tps-group-cli/pki-tps-group-cli-tps-group-member-find.sh
. ./acceptance/cli-tests/pki-tps-group-cli/pki-tps-group-cli-tps-group-member-del.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-generate-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-find-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-template-find-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-template-show-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-request-find-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-show-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-request-show-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-mod-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-archive-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-recover-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-retrieve-kra.sh
. ./acceptance/cli-tests/pki-key-cli/pki-key-cli-request-review-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-generate-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-find-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-template-show-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-template-find-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-request-find-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-show-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-request-show-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-mod-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-archive-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-recover-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-retrieve-kra.sh
. ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-request-review-kra.sh
. ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-add.sh
. ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-show.sh
. ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-find.sh
. ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-mod.sh
. ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-del.sh
. ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-membership-add.sh
. ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-membership-find.sh
. ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-membership-del.sh
. ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-cert.sh
. ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-cert-add.sh
. ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-cert-find.sh
. ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-cert-show.sh
. ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-cert-delete.sh
. ./acceptance/cli-tests/pki-ocsp-user-cli/pki-ocsp-user-cli-ocsp-user-add.sh
. ./acceptance/cli-tests/pki-ocsp-user-cli/pki-ocsp-user-cli-ocsp-user-find.sh
. ./acceptance/cli-tests/pki-ocsp-user-cli/pki-ocsp-user-cli-ocsp-user-show.sh
. ./acceptance/cli-tests/pki-ocsp-user-cli/pki-ocsp-user-cli-ocsp-user-mod.sh
. ./acceptance/cli-tests/pki-ocsp-user-cli/pki-ocsp-user-cli-ocsp-user-del.sh
. ./acceptance/cli-tests/pki-ocsp-user-cli/pki-ocsp-user-cli-ocsp-user-membership-add.sh
. ./acceptance/cli-tests/pki-ocsp-user-cli/pki-ocsp-user-cli-ocsp-user-membership-find.sh
. ./acceptance/cli-tests/pki-ocsp-user-cli/pki-ocsp-user-cli-ocsp-user-membership-del.sh
. ./acceptance/cli-tests/pki-ocsp-user-cli/pki-ocsp-user-cli-ocsp-user-cert-add.sh
. ./acceptance/cli-tests/pki-ocsp-user-cli/pki-ocsp-user-cli-ocsp-user-cert.sh
. ./acceptance/cli-tests/pki-ocsp-user-cli/pki-ocsp-user-cli-ocsp-user-cert-find.sh
. ./acceptance/cli-tests/pki-ocsp-user-cli/pki-ocsp-user-cli-ocsp-user-cert-show.sh
. ./acceptance/cli-tests/pki-ocsp-user-cli/pki-ocsp-user-cli-ocsp-user-cert-delete.sh
. ./acceptance/cli-tests/pki-tks-user-cli/pki-tks-user-cli-tks-user-add.sh
. ./acceptance/cli-tests/pki-tks-user-cli/pki-tks-user-cli-tks-user-find.sh
. ./acceptance/cli-tests/pki-tks-user-cli/pki-tks-user-cli-tks-user-show.sh
. ./acceptance/cli-tests/pki-tks-user-cli/pki-tks-user-cli-tks-user-mod.sh
. ./acceptance/cli-tests/pki-tks-user-cli/pki-tks-user-cli-tks-user-del.sh
. ./acceptance/cli-tests/pki-tks-user-cli/pki-tks-user-cli-tks-user-membership-add.sh
. ./acceptance/cli-tests/pki-tks-user-cli/pki-tks-user-cli-tks-user-membership-find.sh
. ./acceptance/cli-tests/pki-tks-user-cli/pki-tks-user-cli-tks-user-membership-del.sh
. ./acceptance/cli-tests/pki-tks-user-cli/pki-tks-user-cli-tks-user-cert-add.sh
. ./acceptance/cli-tests/pki-tks-user-cli/pki-tks-user-cli-tks-user-cert.sh
. ./acceptance/cli-tests/pki-tks-user-cli/pki-tks-user-cli-tks-user-cert-find.sh
. ./acceptance/cli-tests/pki-tks-user-cli/pki-tks-user-cli-tks-user-cert-show.sh
. ./acceptance/cli-tests/pki-tks-user-cli/pki-tks-user-cli-tks-user-cert-delete.sh
. ./acceptance/cli-tests/pki-tps-user-cli/pki-tps-user-cli-tps-user-add.sh
. ./acceptance/cli-tests/pki-tps-user-cli/pki-tps-user-cli-tps-user-find.sh
. ./acceptance/cli-tests/pki-tps-user-cli/pki-tps-user-cli-tps-user-show.sh
. ./acceptance/cli-tests/pki-tps-user-cli/pki-tps-user-cli-tps-user-mod.sh
. ./acceptance/cli-tests/pki-tps-user-cli/pki-tps-user-cli-tps-user-del.sh
. ./acceptance/cli-tests/pki-tps-user-cli/pki-tps-user-cli-tps-user-membership-add.sh
. ./acceptance/cli-tests/pki-tps-user-cli/pki-tps-user-cli-tps-user-membership-find.sh
. ./acceptance/cli-tests/pki-tps-user-cli/pki-tps-user-cli-tps-user-membership-del.sh
. ./acceptance/cli-tests/pki-tps-user-cli/pki-tps-user-cli-tps-user-cert-add.sh
. ./acceptance/cli-tests/pki-tps-user-cli/pki-tps-user-cli-tps-user-cert.sh
. ./acceptance/cli-tests/pki-tps-user-cli/pki-tps-user-cli-tps-user-cert-find.sh
. ./acceptance/cli-tests/pki-tps-user-cli/pki-tps-user-cli-tps-user-cert-show.sh
. ./acceptance/cli-tests/pki-tps-user-cli/pki-tps-user-cli-tps-user-cert-delete.sh
. ./acceptance/cli-tests/pki-kra-group-cli/pki-kra-group-cli-kra-group-add.sh
. ./acceptance/cli-tests/pki-kra-group-cli/pki-kra-group-cli-kra-group-mod.sh
. ./acceptance/cli-tests/pki-kra-group-cli/pki-kra-group-cli-kra-group-find.sh
. ./acceptance/cli-tests/pki-kra-group-cli/pki-kra-group-cli-kra-group-show.sh
. ./acceptance/cli-tests/pki-kra-group-cli/pki-kra-group-cli-kra-group-del.sh
. ./acceptance/cli-tests/pki-kra-group-cli/pki-kra-group-cli-kra-group-member-add.sh
. ./acceptance/cli-tests/pki-kra-group-cli/pki-kra-group-cli-kra-group-member-show.sh
. ./acceptance/cli-tests/pki-kra-group-cli/pki-kra-group-cli-kra-group-member-find.sh
. ./acceptance/cli-tests/pki-kra-group-cli/pki-kra-group-cli-kra-group-member-del.sh
. ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli.sh
. ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-show.sh
. ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-enable.sh
. ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-disable.sh
. ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-del.sh
. ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-find.sh
. ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-add.sh
. ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-mod.sh
. ./acceptance/legacy/ca-tests/usergroups/pki-ca-usergroups.sh
. ./acceptance/legacy/ca-tests/profiles/ca-ag-profiles.sh
. ./acceptance/legacy/ca-tests/profiles/ca-ad-profiles.sh
. ./acceptance/legacy/ca-tests/internaldb/ca-admin-internaldb.sh
. ./acceptance/legacy/ca-tests/acls/ca-admin-acl.sh
. ./acceptance/legacy/ca-tests/authplugin/ca-admin-authplugins.sh
. ./acceptance/legacy/ca-tests/logs/ca-ad-logs.sh
. ./acceptance/legacy/ca-tests/cert-enrollment/ca-ee-enrollments.sh
. ./acceptance/legacy/ca-tests/cert-enrollment/ca-ag-requests.sh
. ./acceptance/legacy/ca-tests/cert-enrollment/ca-ee-retrieval.sh
. ./acceptance/legacy/ca-tests/crlissuingpoint/ca-admin-crlissuingpoints.sh
. ./acceptance/legacy/ca-tests/crls/ca-agent-crls.sh
. ./acceptance/legacy/ca-tests/publishing/ca-admin-publishing.sh
. ./acceptance/legacy/ca-tests/cert-enrollment/ca-ag-certificates.sh
. ./acceptance/legacy/ca-tests/ocsp/ca-ee-ocsp.sh
. ./acceptance/legacy/ca-tests/renewal/renew_manual.sh
. ./acceptance/legacy/ca-tests/renewal/renew_DirAuthUserCert.sh
. ./acceptance/legacy/ca-tests/renewal/renew_caSSLClientCert.sh
. ./acceptance/legacy/ca-tests/scep_tests/scep-enroll.sh
. ./acceptance/legacy/subca-tests/usergroups/subca-usergroups.sh
. ./acceptance/legacy/subca-tests/acls/subca-ad-acls.sh
. ./acceptance/legacy/subca-tests/internaldb/subca-ad-internaldb.sh
. ./acceptance/legacy/subca-tests/authplugin/subca-ad-authplugin.sh
. ./acceptance/legacy/subca-tests/crlissuingpoint/subca-ad-crlissuingpoints.sh
. ./acceptance/legacy/subca-tests/publishing/subca-ad-publishing.sh
. ./acceptance/legacy/subca-tests/crls/subca-ag-crls.sh
. ./acceptance/legacy/subca-tests/cert-enrollment/subca-ag-certificates.sh
. ./acceptance/legacy/subca-tests/cert-enrollment/subca-ag-requests.sh
. ./acceptance/legacy/subca-tests/cert-enrollment/subca-ee-enrollments.sh
. ./acceptance/legacy/subca-tests/cert-enrollment/subca-ee-retrieval.sh
. ./acceptance/legacy/subca-tests/profiles/subca-ad-profiles.sh
. ./acceptance/legacy/subca-tests/profiles/subca-ag-profiles.sh
. ./acceptance/legacy/subca-tests/logs/subca-ad-logs.sh
. ./acceptance/legacy/subca-tests/scep_tests/subca-scep-enroll.sh
. ./acceptance/legacy/drm-tests/acls/drm-ad-acls.sh
. ./acceptance/legacy/drm-tests/agent/drm-ag-tests.sh
. ./acceptance/legacy/drm-tests/internaldb/drm-ad-internaldb.sh
. ./acceptance/legacy/drm-tests/usergroups/drm-ad-usergroups.sh
. ./acceptance/legacy/drm-tests/logs/drm-ad-logs.sh
. ./acceptance/legacy/ocsp-tests/usergroups/ocsp-ad-usergroups.sh
. ./acceptance/legacy/ocsp-tests/acls/ocsp-ad-acls.sh
. ./acceptance/legacy/ocsp-tests/logs/ocsp-ad-logs.sh
. ./acceptance/legacy/ocsp-tests/internaldb/ocsp-ad-internaldb.sh
. ./acceptance/legacy/ocsp-tests/agent/ocsp-ag-tests.sh
. ./acceptance/legacy/tks-tests/usergroups/tks-ad-usergroups.sh
. ./acceptance/legacy/tks-tests/acls/tks-ad-acls.sh
. ./acceptance/legacy/tks-tests/logs/tks-ad-logs.sh
. ./acceptance/legacy/tks-tests/internaldb/tks-ad-internaldb.sh
. ./acceptance/legacy/ipa-tests/ipa_backend_plugin.sh
. ./acceptance/legacy/tps-tests/tps-enrollments.sh
. ./acceptance/legacy/clone_drm_tests/clone_drm_agent_tests.sh
. ./acceptance/legacy/clone_ca_tests/clone_tests.sh
. ./acceptance/install-tests/ca-installer.sh
. ./acceptance/install-tests/kra-installer.sh
. ./acceptance/install-tests/ocsp-installer.sh
. ./acceptance/install-tests/tks-installer.sh
. ./acceptance/install-tests/tps-installer.sh
. ./acceptance/bugzilla/bug_setup.sh
. ./acceptance/bugzilla/bug_uninstall.sh
. ./acceptance/bugzilla/tomcatjss-bugs/bug-1058366.sh
. ./acceptance/bugzilla/tomcatjss-bugs/bug-1084224.sh
. ./acceptance/bugzilla/pki-core-bugs/giant-debug-log.sh
. ./acceptance/bugzilla/pki-core-bugs/CSbackup-bug.sh
. ./acceptance/bugzilla/jss-bugs/bug-1133718.sh
. ./acceptance/bugzilla/jss-bugs/bug-1040640.sh
. ./acceptance/bugzilla/pki-core-bugs/bug-790924.sh
. ./acceptance/cli-tests/pki-ca-selftest-cli/pki-ca-selftest-cli.sh
. ./acceptance/cli-tests/pki-ca-selftest-cli/pki-ca-selftest-cli-find.sh
. ./acceptance/cli-tests/pki-ca-selftest-cli/pki-ca-selftest-cli-run.sh
. ./acceptance/cli-tests/pki-ca-selftest-cli/pki-ca-selftest-cli-show.sh
. ./acceptance/cli-tests/pki-ca-selftest-cli/pki-ca-selftest-admin.sh
. ./acceptance/cli-tests/pki-kra-selftest-cli/pki-kra-selftest-cli-find.sh
. ./acceptance/cli-tests/pki-kra-selftest-cli/pki-kra-selftest-cli-run.sh
. ./acceptance/cli-tests/pki-kra-selftest-cli/pki-kra-selftest-cli-show.sh
. ./acceptance/cli-tests/pki-kra-selftest-cli/pki-kra-selftest-cli.sh
. ./acceptance/cli-tests/pki-kra-selftest-cli/pki-kra-selftest-admin.sh
. ./acceptance/cli-tests/pki-ocsp-selftest-cli/pki-ocsp-selftest-cli-find.sh
. ./acceptance/cli-tests/pki-ocsp-selftest-cli/pki-ocsp-selftest-cli-run.sh
. ./acceptance/cli-tests/pki-ocsp-selftest-cli/pki-ocsp-selftest-cli-show.sh
. ./acceptance/cli-tests/pki-ocsp-selftest-cli/pki-ocsp-selftest-cli.sh
. ./acceptance/cli-tests/pki-tks-selftest-cli/pki-tks-selftest-cli-find.sh
. ./acceptance/cli-tests/pki-tks-selftest-cli/pki-tks-selftest-cli-run.sh
. ./acceptance/cli-tests/pki-tks-selftest-cli/pki-tks-selftest-cli-show.sh
. ./acceptance/cli-tests/pki-tks-selftest-cli/pki-tks-selftest-cli.sh
. ./acceptance/cli-tests/pki-tps-selftest-cli/pki-tps-selftest-cli-find.sh
. ./acceptance/cli-tests/pki-tps-selftest-cli/pki-tps-selftest-cli-run.sh
. ./acceptance/cli-tests/pki-tps-selftest-cli/pki-tps-selftest-cli-show.sh
. ./acceptance/cli-tests/pki-tps-selftest-cli/pki-tps-selftest-cli.sh


# Make sure TESTORDER is initialized or multihost may have issues
TESTORDER=1
dir1="/opt/rhqa_pki/CodeCoveragePKIhtml"
cmd1="python -m SimpleHTTPServer"
dir2="/opt/rhqa_pki/"
cmd2="ant report"

if   [ $(echo "$MASTER" | grep $(hostname -s)|wc -l) -gt 0 ] ; then
        MYROLE=MASTER
elif [ $(echo "$CLONE1"  | grep $(hostname -s)|wc -l) -gt 0 ] ; then
        MYROLE=CLONE1
elif [ $(echo "$CLONE2" | grep $(hostname -s)|wc -l) -gt 0 ] ; then
        MYROLE=CLONE2
elif [ $(echo "$SUBCA1" | grep $(hostname -s)|wc -l) -gt 0 ] ; then
        MYROLE=SUBCA1
elif [ $(echo "$SUBCA2" | grep $(hostname -s)| wc -l) -gt 0 ] ; then
        MYROLE=SUBCA2
else
        MYROLE=UNKNOWN
fi

rlJournalStart
    rlPhaseStartSetup "list files in /opt/rhqa_pki"
	rlRun "ls /opt/rhqa_pki" 0 "Listing files in /opt/rhqa_pki"
        rlRun "env|sort"
    rlPhaseEnd

    rlPhaseStartSetup "RHCS tests"
	TEST_ALL_UPPERCASE=$(echo $TEST_ALL | tr [a-z] [A-Z])
	QUICKINSTALL_UPPERCASE=$(echo $QUICKINSTALL | tr [a-z] [A-Z])
	TOPO1_UPPERCASE=$(echo $TOPO1 | tr [a-z] [A-Z])
	TOPO2_UPPERCASE=$(echo $TOPO2 | tr [a-z] [A-Z])
	TOPO3_UPPERCASE=$(echo $TOPO3 | tr [a-z] [A-Z])
	TOPO4_UPPERCASE=$(echo $TOPO4 | tr [a-z] [A-Z])
	TOPO5_UPPERCASE=$(echo $TOPO5 | tr [a-z] [A-Z])
	TOPO6_UPPERCASE=$(echo $TOPO6 | tr [a-z] [A-Z])
	TOPO7_UPPERCASE=$(echo $TOPO7 | tr [a-z] [A-Z])
	TOPO8_UPPERCASE=$(echo $TOPO8 | tr [a-z] [A-Z])
	TOPO9_UPPERCASE=$(echo $TOPO9 | tr [a-z] [A-Z])

	get_topo_stack $MYROLE /tmp/topo_file
	CA_INST=$(cat /tmp/topo_file | grep MY_CA | cut -d= -f2)
	KRA_INST=$(cat /tmp/topo_file | grep MY_KRA | cut -d= -f2)
	OCSP_INST=$(cat /tmp/topo_file | grep MY_OCSP | cut -d= -f2)
        TKS_INST=$(cat /tmp/topo_file | grep MY_TKS | cut -d= -f2)
	TPS_INST=$(cat /tmp/topo_file | grep MY_TPS | cut -d= -f2)

        if [ "$QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ] ; then
		run_rhcs_set_time 
		run_rhcs_install_set_vars
		run_rhcs_install_quickinstall
		SUBCA_INST=$(cat /tmp/topo_file | grep MY_SUBCA | cut -d= -f2)
                CLONECA_INST=$(cat /tmp/topo_file | grep MY_CLONE_CA | cut -d= -f2)
                CLONEKRA_INST=$(cat /tmp/topo_file | grep MY_CLONE_KRA | cut -d= -f2)
                CLONEOCSP_INST=$(cat /tmp/topo_file | grep MY_CLONE_OCSP | cut -d= -f2)
                CLONETKS_INST=$(cat /tmp/topo_file | grep MY_CLONE_TKS | cut -d= -f2)
                CLONETPS_INST=$(cat /tmp/topo_file | grep MY_CLONE_TPS | cut -d= -f2)
        elif [ "$TOPO1_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_1
        elif [ "$TOPO2_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_2
        elif [ "$TOPO3_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_3
        elif [ "$TOPO4_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_4
        elif [ "$TOPO5_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_5
        elif [ "$TOPO6_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_6
        elif [ "$TOPO7_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_7
        elif [ "$TOPO8_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_8
	elif [ "$TOPO9_UPPERCASE" = "TRUE" ] ; then
                run_rhcs_install_set_vars
                run_rhcs_install_topo_9
        fi
	PKI_CA_QUICKINSTALL_UPPERCASE=$(echo $PKI_CA_QUICKINSTALL | tr [a-z] [A-Z])
	if [ "$PKI_CA_QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ]; then
		BEAKERMASTER=$MASTER
		CA=ROOTCA
		run_rhcs_set_time
		run_rhcs_install_set_vars
		run_rhcs_install_packages
		run_install_subsystem_RootCA
		run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi
	PKI_SUBCA_QUICKINSTALL_UPPERCASE=$(echo $PKI_SUBCA_QUICKINSTALL | tr [a-z] [A-Z])
	if [ "$PKI_SUBCA_QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ]; then
		BEAKERMASTER=$MASTER
		CA=ROOTCA
		number=3
		SUBCA_number=1
		run_rhcs_set_time
		run_rhcs_install_set_vars
		run_rhcs_install_packages
		run_install_subsystem_RootCA
		run_install_subsystem_subca $SUBCA_number $BEAKERMASTER $CA
		run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
		run_rhcs_add_to_env "SUBCA1_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$SUBCA1_ADMIN_CERT_NICKNAME.p12"
	fi
	PKI_KRA_QUICKINSTALL_UPPERCASE=$(echo $PKI_KRA_QUICKINSTALL | tr [a-z] [A-Z])
	if [ "$PKI_KRA_QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ]; then
		BEAKERMASTER=$MASTER
		CA=ROOTCA
		number=3
		MASTER_KRA=KRA3
		run_rhcs_set_time
		run_rhcs_install_set_vars
		run_rhcs_install_packages
		run_install_subsystem_RootCA
		run_install_subsystem_kra $number $BEAKERMASTER $CA
		run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi
	PKI_OCSP_QUICKINSTALL_UPPERCASE=$(echo $PKI_OCSP_QUICKINSTALL | tr [a-z] [A-Z])
	if [ "$PKI_OCSP_QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ]; then
		BEAKERMASTER=$MASTER
		CA=ROOTCA
		number=3
		MASTER_OCSP=OCSP3
		run_rhcs_set_time
		run_rhcs_install_set_vars
		run_rhcs_install_packages
		run_install_subsystem_RootCA
		run_install_subsystem_ocsp $number $BEAKERMASTER $CA
		run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi
	PKI_TKS_QUICKINSTALL_UPPERCASE=$(echo $PKI_TKS_QUICKINSTALL | tr [a-z] [A-Z])
	if [ "$PKI_TKS_QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ]; then
		BEAKERMASTER=$MASTER
		CA=ROOTCA
		number=3
		TKS_number=1
		MASTER_KRA=KRA3
		run_rhcs_set_time
		run_rhcs_install_set_vars
		run_rhcs_install_packages
		run_install_subsystem_RootCA
		run_install_subsystem_kra $number $BEAKERMASTER $CA
		run_install_subsystem_tks $TKS_number $BEAKERMASTER $CA $MASTER_KRA
		run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi
	PKI_TPS_QUICKINSTALL_UPPERCASE=$(echo $PKI_TPS_QUICKINSTALL | tr [a-z] [A-Z])
	if [ "$PKI_TPS_QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ]; then
		BEAKERMASTER=$MASTER
		CA=ROOTCA
		number=3
		TKS_number=1
		TPS_number=1
		MASTER_TKS=TKS1
		MASTER_KRA=KRA3
		run_rhcs_set_time
		run_rhcs_install_set_vars
		run_rhcs_install_packages
		run_install_subsystem_RootCA
		run_install_subsystem_kra $number $BEAKERMASTER $CA
		run_install_subsystem_tks $TKS_number $BEAKERMASTER $CA $MASTER_KRA
		run_install_subsystem_tps $TPS_number $BEAKERMASTER $CA $MASTER_KRA $MASTER_TKS
		run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi
	PKI_CLONECA_QUICKINSTALL_UPPERCASE=$(echo $PKI_CLONECA_QUICKINSTALL | tr [a-z] [A-Z])
	if [ "$PKI_CLONECA_QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ]; then
		BEAKERMASTER=$MASTER
		CA=ROOTCA
		number=3
		CLONE_number=1
		run_rhcs_set_time
		run_rhcs_install_set_vars
		run_rhcs_install_packages
		run_install_subsystem_RootCA
		run_install_subsystem_cloneCA $CLONE_number $BEAKERMASTER $CA
		run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi
	PKI_CLONEKRA_QUICKINSTALL_UPPERCASE=$(echo $PKI_CLONEKRA_QUICKINSTALL | tr [a-z] [A-Z])
	if [ "$PKI_CLONEKRA_QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ]; then
		BEAKERMASTER=$MASTER
		CA=ROOTCA
		number=3
		CLONE_number=1
		MASTER_KRA=KRA3
		run_rhcs_set_time
		run_rhcs_install_set_vars
		run_rhcs_install_packages
		run_install_subsystem_RootCA
		run_install_subsystem_kra $number $BEAKERMASTER $CA
		run_install_subsystem_cloneKRA $CLONE_number $BEAKERMASTER $CA $MASTER_KRA
		run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi
	PKI_CLONETKS_QUICKINSTALL_UPPERCASE=$(echo $PKI_CLONETKS_QUICKINSTALL | tr [a-z] [A-Z])
	if [ "$PKI_CLONETKS_QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ]; then
		BEAKERMASTER=$MASTER
		CA=ROOTCA
		number=3
		TKS_number=1
		CLONE_number=1
		MASTER_KRA=KRA3
		MASTER_TKS=TKS1
		run_rhcs_set_time
		run_rhcs_install_set_vars
		run_rhcs_install_packages
		run_install_subsystem_RootCA
		run_install_subsystem_kra $number $BEAKERMASTER $CA
		run_install_subsystem_tks $TKS_number $BEAKERMASTER $CA
		run_install_subsystem_cloneTKS $CLONE_number $BEAKERMASTER $CA
		run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi
	PKI_CLONETPS_QUICKINSTALL_UPPERCASE=$(echo $PKI_CLONETPS_QUICKINSTALL | tr [a-z] [A-Z])
	if [ "$PKI_CLONETPS_QUICKINSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL" = "TRUE" ]; then
		BEAKERMASTER=$MASTER
		CA=ROOTCA
		number=3
		TKS_number=1
		TPS_number=1
		CLONE_number=1
		MASTER_TKS=TKS1
		run_rhcs_set_time
		run_rhcs_install_set_vars
		run_rhcs_install_packages
		run_install_subsystem_RootCA
		run_install_subsystem_kra $number $BEAKERMASTER $CA
		run_install_subsystem_tks $TKS_number $BEAKERMASTER $CA
		run_install_subsystem_tps $TPS_number $BEAKERMASTER $CA $MASTER_KRA $MASTER_TKS
		run_install_subsystem_cloneTPS $CLONE_number $BEAKERMASTER $CA $MASTER_KRA $MASTER_TKS
		run_rhcs_add_to_env "ROOTCA_ADMIN_CERT_LOCATION" "$CLIENT_DIR/$ROOTCA_ADMIN_CERT_NICKNAME.p12"
	fi
	######## CREATE ROLE USERS #############
        PKI_CREATE_CA_ROLE_USER_UPPERCASE=$(echo $PKI_CREATE_CA_ROLE_USER | tr [a-z] [A-Z])
        if [ "$PKI_CREATE_CA_ROLE_USER_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Create CA role users
                  run_pki-user-cli-role-user-create-tests $CA_INST ca $MYROLE
        fi
        PKI_CREATE_KRA_ROLE_USER_UPPERCASE=$(echo $PKI_CREATE_KRA_ROLE_USER | tr [a-z] [A-Z])
        if [ "$PKI_CREATE_KRA_ROLE_USER_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Create KRA role users
                  run_pki-user-cli-role-user-create-tests $KRA_INST kra $MYROLE
        fi
        PKI_CREATE_OCSP_ROLE_USER_UPPERCASE=$(echo $PKI_CREATE_OCSP_ROLE_USER | tr [a-z] [A-Z])
        if [ "$PKI_CREATE_OCSP_ROLE_USER_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Create OCSP role users
                  run_pki-user-cli-role-user-create-tests $OCSP_INST ocsp $MYROLE
        fi
        PKI_CREATE_TKS_ROLE_USER_UPPERCASE=$(echo $PKI_CREATE_TKS_ROLE_USER | tr [a-z] [A-Z])
        if [ "$PKI_CREATE_TKS_ROLE_USER_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Create TKS role users
                  run_pki-user-cli-role-user-create-tests $TKS_INST tks $MYROLE
        fi
        PKI_CREATE_TPS_ROLE_USER_UPPERCASE=$(echo $PKI_CREATE_TPS_ROLE_USER | tr [a-z] [A-Z])
        if [ "$PKI_CREATE_TPS_ROLE_USER_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Create TPS role users
                  run_pki-user-cli-role-user-create-tests $TPS_INST tps $MYROLE
        fi
        PKI_CREATE_SUBCA_ROLE_USER_UPPERCASE=$(echo $PKI_CREATE_SUBCA_ROLE_USER | tr [a-z] [A-Z])
        if [ "$PKI_CREATE_SUBCA_ROLE_USER_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Create SUBCA role users
                  run_pki-user-cli-role-user-create-tests $SUBCA_INST ca $MYROLE
        fi
        PKI_CREATE_CLONECA_ROLE_USER_UPPERCASE=$(echo $PKI_CREATE_CLONECA_ROLE_USER | tr [a-z] [A-Z])
        if [ "$PKI_CREATE_CLONECA_ROLE_USER_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Create CLONE CA role users
                  run_pki-user-cli-role-user-create-tests $CLONECA_INST ca $MYROLE
        fi
        PKI_CREATE_CLONEKRA_ROLE_USER_UPPERCASE=$(echo $PKI_CREATE_CLONEKRA_ROLE_USER | tr [a-z] [A-Z])
        if [ "$PKI_CREATE_CLONEKRA_ROLE_USER_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Create CLONE KRA role users
                  run_pki-user-cli-role-user-create-tests $CLONEKRA_INST kra $MYROLE
        fi
        PKI_CREATE_CLONEOCSP_ROLE_USER_UPPERCASE=$(echo $PKI_CREATE_CLONEOCSP_ROLE_USER | tr [a-z] [A-Z])
        if [ "$PKI_CREATE_CLONEOCSP_ROLE_USER_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Create CLONE OCSP role users
                  run_pki-user-cli-role-user-create-tests $CLONEOCSP_INST ocsp $MYROLE
        fi
        PKI_CREATE_CLONETKS_ROLE_USER_UPPERCASE=$(echo $PKI_CREATE_CLONETKS_ROLE_USER | tr [a-z] [A-Z])
        if [ "$PKI_CREATE_CLONETKS_ROLE_USER_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Create CLONE TKS role users
                  run_pki-user-cli-role-user-create-tests $CLONETKS_INST tks $MYROLE
        fi
        PKI_CREATE_CLONETPS_ROLE_USER_UPPERCASE=$(echo $PKI_CREATE_CLONETPS_ROLE_USER | tr [a-z] [A-Z])
        if [ "$PKI_CREATE_CLONETPS_ROLE_USER_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Create CLONE TPS role users
                  run_pki-user-cli-role-user-create-tests $CLONETPS_INST tps $MYROLE
        fi
	######## PKI USER CA TESTS ############
	PKI_USER_CA_UPPERCASE=$(echo $PKI_USER_CA | tr [a-z] [A-Z])
        if [ "$PKI_USER_CA_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-add-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-show-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-mod-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-find-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-del-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-membership-add-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-membership-find-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-membership-del-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-cert-add-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-cert-find-ca_tests $subsystemId $subsystemType $MYROLE
                  run_pki-user-cli-user-cert-show-ca_tests $subsystemId $subsystemType $MYROLE
		  run_pki-user-cli-user-cert-delete-ca_tests $subsystemId $subsystemType $MYROLE
        fi
	USER_ADD_CA_UPPERCASE=$(echo $USER_ADD_CA | tr [a-z] [A-Z])
        if [ "$USER_ADD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-add-ca_tests $subsystemId $subsystemType $MYROLE
        fi
	USER_SHOW_CA_UPPERCASE=$(echo $USER_SHOW_CA | tr [a-z] [A-Z])
        if [ "$USER_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-show-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-show-ca_tests $subsystemId $subsystemType $MYROLE
        fi
	USER_MOD_CA_UPPERCASE=$(echo $USER_MOD_CA | tr [a-z] [A-Z])
	if [ "$USER_MOD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-mod-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-mod-ca_tests $subsystemId $subsystemType $MYROLE
	fi
	USER_FIND_CA_UPPERCASE=$(echo $USER_FIND_CA | tr [a-z] [A-Z])
        if [ "$USER_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-find-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
		  run_pki-user-cli-user-find-ca_tests $subsystemId $subsystemType $MYROLE
        fi
	USER_DEL_CA_UPPERCASE=$(echo $USER_DEL_CA | tr [a-z] [A-Z])
        if [ "$USER_DEL_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-del-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
		  run_pki-user-cli-user-del-ca_tests $subsystemId $subsystemType $MYROLE
        fi
	USER_MEMBERSHIP_ADD_CA_UPPERCASE=$(echo $USER_MEMBERSHIP_ADD_CA | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_ADD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-add-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-membership-add-ca_tests $subsystemId $subsystemType $MYROLE
        fi
        USER_MEMBERSHIP_FIND_CA_UPPERCASE=$(echo $USER_MEMBERSHIP_FIND_CA | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-find-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-membership-find-ca_tests $subsystemId $subsystemType $MYROLE
        fi
        USER_MEMBERSHIP_DEL_CA_UPPERCASE=$(echo $USER_MEMBERSHIP_DEL_CA | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_DEL_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-del-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-membership-del-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
	USER_CERT_ADD_CA_UPPERCASE=$(echo $USER_CERT_ADD_CA | tr [a-z] [A-Z])
        if [ "$USER_CERT_ADD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-add-ca tests 
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-cert-add-ca_tests  $subsystemId $subsystemType $MYROLE
		  run_pki-user-cert  $subsystemId $subsystemType $MYROLE
        fi
        USER_CERT_FIND_CA_UPPERCASE=$(echo $USER_CERT_FIND_CA | tr [a-z] [A-Z])
        if [ "$USER_CERT_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-find-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-cert-find-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
        USER_CERT_SHOW_CA_UPPERCASE=$(echo $USER_CERT_SHOW_CA | tr [a-z] [A-Z])
        if [ "$USER_CERT_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-show-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-cert-show-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
	USER_CERT_DEL_CA_UPPERCASE=$(echo $USER_CERT_DEL_CA | tr [a-z] [A-Z])
        if [ "$USER_CERT_DEL_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-del-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-user-cli-user-cert-delete-ca_tests  $subsystemId $subsystemType $MYROLE
        fi

	######## PKI USER KRA TESTS ############
        PKI_USER_KRA_UPPERCASE=$(echo $PKI_USER_KRA | tr [a-z] [A-Z])
        if [ "$PKI_USER_KRA_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-kra tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
		  caId=$CA_INST
		  run_pki-user-cli-user-add-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-show-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-mod-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
		  run_pki-user-cli-user-del-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-find-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-membership-add-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-membership-find-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-membership-del-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-add-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-find-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-show-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-delete-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	USER_ADD_KRA_UPPERCASE=$(echo $USER_ADD_KRA | tr [a-z] [A-Z])
        if [ "$USER_ADD_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-kra tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-user-cli-user-add-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_SHOW_KRA_UPPERCASE=$(echo $USER_SHOW_KRA | tr [a-z] [A-Z])
        if [ "$USER_SHOW_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-show-kra tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-user-cli-user-show-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi	
        USER_MOD_KRA_UPPERCASE=$(echo $USER_MOD_KRA | tr [a-z] [A-Z])
        if [ "$USER_MOD_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-mod-kra tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
		  caId=$CA_INST
                  run_pki-user-cli-user-mod-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	USER_DEL_KRA_UPPERCASE=$(echo $USER_DEL_KRA | tr [a-z] [A-Z])
        if [ "$USER_DEL_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-del-kra tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-user-cli-user-del-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_FIND_KRA_UPPERCASE=$(echo $USER_FIND_KRA | tr [a-z] [A-Z])
        if [ "$USER_FIND_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-find-kra tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-user-cli-user-find-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_MEMBERSHIP_ADD_KRA_UPPERCASE=$(echo $USER_MEMBERSHIP_ADD_KRA | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_ADD_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-add-kra tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-user-cli-user-membership-add-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_MEMBERSHIP_FIND_KRA_UPPERCASE=$(echo $USER_MEMBERSHIP_FIND_KRA | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_FIND_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-find-kra tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-user-cli-user-membership-find-kra_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_MEMBERSHIP_DEL_KRA_UPPERCASE=$(echo $USER_MEMBERSHIP_DEL_KRA | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_DEL_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-del-kra tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-user-cli-user-membership-del-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	USER_CERT_ADD_KRA_UPPERCASE=$(echo $USER_CERT_ADD_KRA | tr [a-z] [A-Z])
        if [ "$USER_CERT_ADD_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-add-kra tests 
                  subsystemId=$KRA_INST
                  subsystemType=kra
		  caId=$CA_INST
                  run_pki-user-cli-user-cert-add-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_FIND_KRA_UPPERCASE=$(echo $USER_CERT_FIND_KRA | tr [a-z] [A-Z])
        if [ "$USER_CERT_FIND_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-find-kra tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
		  caId=$CA_INST
                  run_pki-user-cli-user-cert-find-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_SHOW_KRA_UPPERCASE=$(echo $USER_CERT_SHOW_KRA | tr [a-z] [A-Z])
        if [ "$USER_CERT_SHOW_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-show-kra tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
		  caId=$CA_INST
                  run_pki-user-cli-user-cert-show-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_DEL_KRA_UPPERCASE=$(echo $USER_CERT_DEL_KRA | tr [a-z] [A-Z])
        if [ "$USER_CERT_DEL_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-del-kra tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
		  caId=$CA_INST
                  run_pki-user-cli-user-cert-delete-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	######## PKI USER OCSP TESTS ############
        PKI_USER_OCSP_UPPERCASE=$(echo $PKI_USER_OCSP | tr [a-z] [A-Z])
        if [ "$PKI_USER_OCSP_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-ocsp tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-user-cli-user-add-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-show-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-mod-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-del-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-find-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-membership-add-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-membership-find-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-membership-del-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-add-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-find-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-show-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-delete-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_ADD_OCSP_UPPERCASE=$(echo $USER_ADD_OCSP | tr [a-z] [A-Z])
        if [ "$USER_ADD_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-ocsp tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-user-cli-user-add-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_SHOW_OCSP_UPPERCASE=$(echo $USER_SHOW_OCSP | tr [a-z] [A-Z])
        if [ "$USER_SHOW_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-show-ocsp tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-user-cli-user-show-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_MOD_OCSP_UPPERCASE=$(echo $USER_MOD_OCSP | tr [a-z] [A-Z])
        if [ "$USER_MOD_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-mod-ocsp tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-user-cli-user-mod-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	USER_DEL_OCSP_UPPERCASE=$(echo $USER_DEL_OCSP | tr [a-z] [A-Z])
        if [ "$USER_DEL_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-del-ocsp tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-user-cli-user-del-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_FIND_OCSP_UPPERCASE=$(echo $USER_FIND_OCSP | tr [a-z] [A-Z])
        if [ "$USER_FIND_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-find-ocsp tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-user-cli-user-find-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_MEMBERSHIP_ADD_OCSP_UPPERCASE=$(echo $USER_MEMBERSHIP_ADD_OCSP | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_ADD_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-add-ocsp tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-user-cli-user-membership-add-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_MEMBERSHIP_FIND_OCSP_UPPERCASE=$(echo $USER_MEMBERSHIP_FIND_OCSP | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_FIND_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-find-ocsp tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-user-cli-user-membership-find-ocsp_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_MEMBERSHIP_DEL_OCSP_UPPERCASE=$(echo $USER_MEMBERSHIP_DEL_OCSP | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_DEL_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-del-ocsp tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-user-cli-user-membership-del-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	USER_CERT_ADD_OCSP_UPPERCASE=$(echo $USER_CERT_ADD_OCSP | tr [a-z] [A-Z])
        if [ "$USER_CERT_ADD_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-add-ocsp tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-user-cli-user-cert-add-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_FIND_OCSP_UPPERCASE=$(echo $USER_CERT_FIND_OCSP | tr [a-z] [A-Z])
        if [ "$USER_CERT_FIND_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-find-ocsp tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-user-cli-user-cert-find-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_SHOW_OCSP_UPPERCASE=$(echo $USER_CERT_SHOW_OCSP | tr [a-z] [A-Z])
        if [ "$USER_CERT_SHOW_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-show-ocsp tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-user-cli-user-cert-show-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_DEL_OCSP_UPPERCASE=$(echo $USER_CERT_DEL_OCSP | tr [a-z] [A-Z])
        if [ "$USER_CERT_DEL_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-del-ocsp tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-user-cli-user-cert-delete-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	######## PKI USER TKS TESTS ############
        PKI_USER_TKS_UPPERCASE=$(echo $PKI_USER_TKS | tr [a-z] [A-Z])
        if [ "$PKI_USER_TKS_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-tks tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-user-cli-user-add-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-show-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-mod-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-del-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-find-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-membership-add-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-membership-find-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-membership-del-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-add-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-find-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-show-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-delete-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi

        USER_ADD_TKS_UPPERCASE=$(echo $USER_ADD_TKS | tr [a-z] [A-Z])
        if [ "$USER_ADD_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-tks tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-user-cli-user-add-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_SHOW_TKS_UPPERCASE=$(echo $USER_SHOW_TKS | tr [a-z] [A-Z])
        if [ "$USER_SHOW_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-show-tks tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-user-cli-user-show-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	USER_MOD_TKS_UPPERCASE=$(echo $USER_MOD_TKS | tr [a-z] [A-Z])
        if [ "$USER_MOD_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-mod-tks tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-user-cli-user-mod-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_DEL_TKS_UPPERCASE=$(echo $USER_DEL_TKS | tr [a-z] [A-Z])
        if [ "$USER_DEL_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-del-tks tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-user-cli-user-del-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_FIND_TKS_UPPERCASE=$(echo $USER_FIND_TKS | tr [a-z] [A-Z])
        if [ "$USER_FIND_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-find-tks tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-user-cli-user-find-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_MEMBERSHIP_ADD_TKS_UPPERCASE=$(echo $USER_MEMBERSHIP_ADD_TKS | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_ADD_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-add-tks tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-user-cli-user-membership-add-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_MEMBERSHIP_FIND_TKS_UPPERCASE=$(echo $USER_MEMBERSHIP_FIND_TKS | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_FIND_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-find-tks tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-user-cli-user-membership-find-tks_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	USER_MEMBERSHIP_DEL_TKS_UPPERCASE=$(echo $USER_MEMBERSHIP_DEL_TKS | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_DEL_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-del-tks tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-user-cli-user-membership-del-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_ADD_TKS_UPPERCASE=$(echo $USER_CERT_ADD_TKS | tr [a-z] [A-Z])
        if [ "$USER_CERT_ADD_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-add-tks tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-user-cli-user-cert-add-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_FIND_TKS_UPPERCASE=$(echo $USER_CERT_FIND_TKS | tr [a-z] [A-Z])
        if [ "$USER_CERT_FIND_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-find-tks tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-user-cli-user-cert-find-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_SHOW_TKS_UPPERCASE=$(echo $USER_CERT_SHOW_TKS | tr [a-z] [A-Z])
        if [ "$USER_CERT_SHOW_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-show-tks tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-user-cli-user-cert-show-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_DEL_TKS_UPPERCASE=$(echo $USER_CERT_DEL_TKS | tr [a-z] [A-Z])
        if [ "$USER_CERT_DEL_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-del-tks tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-user-cli-user-cert-delete-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	######## PKI USER TPS TESTS ############
        PKI_USER_TPS_UPPERCASE=$(echo $PKI_USER_TPS | tr [a-z] [A-Z])
        if [ "$PKI_USER_TPS_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-tps tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-user-cli-user-add-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-show-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-mod-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-del-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-find-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-membership-add-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-membership-find-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-membership-del-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-add-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-find-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-show-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-user-cli-user-cert-delete-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi

        USER_ADD_TPS_UPPERCASE=$(echo $USER_ADD_TPS | tr [a-z] [A-Z])
        if [ "$USER_ADD_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-add-tps tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-user-cli-user-add-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_SHOW_TPS_UPPERCASE=$(echo $USER_SHOW_TPS | tr [a-z] [A-Z])
        if [ "$USER_SHOW_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-show-tps tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-user-cli-user-show-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	USER_MOD_TPS_UPPERCASE=$(echo $USER_MOD_TPS | tr [a-z] [A-Z])
        if [ "$USER_MOD_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-mod-tps tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-user-cli-user-mod-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_DEL_TPS_UPPERCASE=$(echo $USER_DEL_TPS | tr [a-z] [A-Z])
        if [ "$USER_DEL_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-del-tps tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-user-cli-user-del-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_FIND_TPS_UPPERCASE=$(echo $USER_FIND_TPS | tr [a-z] [A-Z])
        if [ "$USER_FIND_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-find-tps tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-user-cli-user-find-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_MEMBERSHIP_ADD_TPS_UPPERCASE=$(echo $USER_MEMBERSHIP_ADD_TPS | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_ADD_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-add-tps tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-user-cli-user-membership-add-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_MEMBERSHIP_FIND_TPS_UPPERCASE=$(echo $USER_MEMBERSHIP_FIND_TPS | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_FIND_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-find-tps tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-user-cli-user-membership-find-tps_tests $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	USER_MEMBERSHIP_DEL_TPS_UPPERCASE=$(echo $USER_MEMBERSHIP_DEL_TPS | tr [a-z] [A-Z])
        if [ "$USER_MEMBERSHIP_DEL_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-membership-del-tps tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-user-cli-user-membership-del-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_ADD_TPS_UPPERCASE=$(echo $USER_CERT_ADD_TPS | tr [a-z] [A-Z])
        if [ "$USER_CERT_ADD_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-add-tps tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-user-cli-user-cert-add-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_FIND_TPS_UPPERCASE=$(echo $USER_CERT_FIND_TPS | tr [a-z] [A-Z])
        if [ "$USER_CERT_FIND_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-find-tps tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-user-cli-user-cert-find-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_SHOW_TPS_UPPERCASE=$(echo $USER_CERT_SHOW_TPS | tr [a-z] [A-Z])
        if [ "$USER_CERT_SHOW_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-show-tps tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-user-cli-user-cert-show-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        USER_CERT_DEL_TPS_UPPERCASE=$(echo $USER_CERT_DEL_TPS | tr [a-z] [A-Z])
        if [ "$USER_CERT_DEL_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cert-del-tps tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-user-cli-user-cert-delete-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	######## PKI CA_USER TESTS ############
	PKI_CA_USER_UPPERCASE=$(echo $PKI_CA_USER | tr [a-z] [A-Z])
        if [ "$PKI_CA_USER_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-add_tests $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-show_tests $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-find_tests $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-del_tests $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-membership-add_tests $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-membership-find_tests $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-membership-del_tests $subsystemId $subsystemType $MYROLE
		  run_pki-ca-user-cli-ca-user-mod_tests  $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-user-cert-add_tests  $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-cert-find_tests  $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-cert-show_tests  $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cli-ca-user-cert-delete_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_ADD_UPPERCASE=$(echo $CA_USER_ADD | tr [a-z] [A-Z])
        if [ "$CA_USER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-add tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-add_tests $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_SHOW_UPPERCASE=$(echo $CA_USER_SHOW | tr [a-z] [A-Z])
        if [ "$CA_USER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-show tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-show_tests $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_FIND_UPPERCASE=$(echo $CA_USER_FIND | tr [a-z] [A-Z])
        if [ "$CA_USER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-find-ca tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-find_tests $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_DEL_UPPERCASE=$(echo $CA_USER_DEL | tr [a-z] [A-Z])
        if [ "$CA_USER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-del tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-del_tests $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_MEMBERSHIP_ADD_UPPERCASE=$(echo $CA_USER_MEMBERSHIP_ADD | tr [a-z] [A-Z])
        if [ "$CA_USER_MEMBERSHIP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-membership-add tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-membership-add_tests $subsystemId $subsystemType $MYROLE
        fi
	CA_USER_MEMBERSHIP_FIND_UPPERCASE=$(echo $CA_USER_MEMBERSHIP_FIND | tr [a-z] [A-Z])
        if [ "$CA_USER_MEMBERSHIP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-membership-find tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-membership-find_tests $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_MEMBERSHIP_DEL_UPPERCASE=$(echo $CA_USER_MEMBERSHIP_DEL | tr [a-z] [A-Z])
        if [ "$CA_USER_MEMBERSHIP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-membership-del tests
		  subsystemId=$CA_INST
		  subsystemType=ca
                  run_pki-ca-user-cli-ca-user-membership-del_tests $subsystemId $subsystemType $MYROLE
        fi
	CA_USER_MOD_UPPERCASE=$(echo $CA_USER_MOD | tr [a-z] [A-Z])
        if [ "$CA_USER_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-mod tests
                  subsystemId=$CA_INST
                subsystemType=ca
                  run_pki-ca-user-cli-ca-user-mod_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_CERT_ADD_UPPERCASE=$(echo $CA_USER_CERT_ADD | tr [a-z] [A-Z])
        if [ "$CA_USER_CERT_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-cert-add tests
                  subsystemId=$CA_INST
                subsystemType=ca
                  run_pki-ca-user-cli-user-cert-add_tests  $subsystemId $subsystemType $MYROLE
                  run_pki-ca-user-cert  $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_CERT_FIND_UPPERCASE=$(echo $CA_USER_CERT_FIND | tr [a-z] [A-Z])
        if [ "$CA_USER_CERT_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-cert-find tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-user-cli-ca-user-cert-find_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_CERT_SHOW_UPPERCASE=$(echo $CA_USER_CERT_SHOW | tr [a-z] [A-Z])
        if [ "$CA_USER_CERT_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-cert-show tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-user-cli-ca-user-cert-show_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_USER_CERT_DEL_UPPERCASE=$(echo $CA_USER_CERT_DEL | tr [a-z] [A-Z])
        if [ "$CA_USER_CERT_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-cert-del tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-user-cli-ca-user-cert-delete_tests  $subsystemId $subsystemType $MYROLE
        fi
	######## PKI CERT TESTS ############
	CERT_TEST_UPPERCASE=$(echo $CERT_TEST | tr [a-z] [A-Z])
        if [ "$CERT_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki cert tests
		 subsystemType=ca
                 run_pki-cert-request-show-ca_tests $subsystemType $MYROLE
                 run_pki-cert-show-ca_tests $subsystemType $MYROLE
		 run_pki-cert-request-submit_tests $subsystemType $MYROLE
		 run_pki-cert-request-profile-find-ca_tests $subsystemType $MYROLE
		 run_pki-cert-request-profile-show-ca_tests $subsystemType $MYROLE
		 run_pki-cert-request-review-ca_tests $subsystemType $MYROLE
		 run_pki-cert-request-find-ca_tests $subsystemType $MYROLE
                 run_pki-cert-revoke-ca_tests $subsystemType $MYROLE
                 run_pki-cert-release-hold-ca_tests $subsystemType $MYROLE
                 run_pki-cert-hold-ca_tests $subsystemType $MYROLE
	         run_pki-cert-find-ca_tests $subsystemType $MYROLE
                 run_pki-cert-ca_tests 
        fi
        CERT_CONFIG_CA_UPPERCASE=$(echo $CERT_CONFIG_CA | tr [a-z] [A-Z])
        if [ "$CERT_CONFIG_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert tests
                  run_pki-cert-ca_tests
        fi
        CERT_SHOW_CA_UPPERCASE=$(echo $CERT_SHOW_CA | tr [a-z] [A-Z])
        if [ "$CERT_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-show tests
		  subsystemType=ca
                  run_pki-cert-show-ca_tests $subsystemType $MYROLE
        fi
        CERT_REQUEST_SHOW_CA_UPPERCASE=$(echo $CERT_REQUEST_SHOW_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-show tests
		  subsystemType=ca 
                  run_pki-cert-request-show-ca_tests $subsystemType $MYROLE
        fi
        CERT_REVOKE_CA_UPPERCASE=$(echo $CERT_REVOKE_CA | tr [a-z] [A-Z])
        if [ "$CERT_REVOKE_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-revoke tests
		  subsystemType=ca
		  run_pki-cert-revoke-ca_tests $subsystemType $MYROLE
        fi
        CERT_RELEASE_HOLD_CA_UPPERCASE=$(echo $CERT_RELEASE_HOLD_CA | tr [a-z] [A-Z])
        if [ "$CERT_RELEASE_HOLD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-release-hold tests
		  subsystemType=ca
                  run_pki-cert-release-hold-ca_tests $subsystemType $MYROLE
        fi
        CERT_HOLD_CA_UPPERCASE=$(echo $CERT_HOLD_CA | tr [a-z] [A-Z])
        if [ "$CERT_HOLD_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-hold tests
		  subsystemType=ca
                  run_pki-cert-hold-ca_tests $subsystemType $MYROLE
        fi
	CERT_REQUEST_SUBMIT_CA_UPPERCASE=$(echo $CERT_REQUEST_SUBMIT_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_SUBMIT_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-hold tests
		  subsystemType=ca
                  run_pki-cert-request-submit_tests $subsystemType $MYROLE
        fi
        CERT_REQUEST_PROFILE_FIND_CA_UPPERCASE=$(echo $CERT_REQUEST_PROFILE_FIND_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_PROFILE_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-profile-find tests
		  subsystemType=ca
                  run_pki-cert-request-profile-find-ca_tests $subsystemType $MYROLE
        fi
        CERT_REQUEST_PROFILE_SHOW_CA_UPPERCASE=$(echo $CERT_REQUEST_PROFILE_SHOW_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_PROFILE_SHOW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-profile-show tests
		  subsystemType=ca
                  run_pki-cert-request-profile-show-ca_tests $subsystemType $MYROLE
        fi
        CERT_REQUEST_REVIEW_CA_UPPERCASE=$(echo $CERT_REQUEST_REVIEW_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_REVIEW_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-review tests
		  subsystemType=ca
                  run_pki-cert-request-review-ca_tests $subsystemType $MYROLE
        fi
        CERT_REQUEST_FIND_CA_UPPERCASE=$(echo $CERT_REQUEST_FIND_CA | tr [a-z] [A-Z])
        if [ "$CERT_REQUEST_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-request-find tests
		  subsystemType=ca
                  run_pki-cert-request-find-ca_tests $subsystemType $MYROLE
        fi
        CERT_FIND_CA_UPPERCASE=$(echo $CERT_FIND_CA | tr [a-z] [A-Z])
        if [ "$CERT_FIND_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki cert-find tests
		  subsystemType=ca
                  run_pki-cert-find-ca_tests $subsystemType $MYROLE
        fi
        ######## PKI CA CERT TESTS ############
        PKI_CA_CERT_TEST_UPPERCASE=$(echo $PKI_CA_CERT_TEST | tr [a-z] [A-Z])
        if [ "$PKI_CA_CERT_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki cert tests
                 subsystemType=ca
                 run_pki-ca-cert-request-show-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-show-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-request-submit_tests $subsystemType $MYROLE
                 run_pki-ca-cert-request-profile-find-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-request-profile-show-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-request-review-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-request-find-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-revoke-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-release-hold-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-hold-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-find-ca_tests $subsystemType $MYROLE
                 run_pki-ca-cert-ca_tests

        fi
        CA_CERT_CONFIG_UPPERCASE=$(echo $CA_CERT_CONFIG | tr [a-z] [A-Z])
        if [ "$CA_CERT_CONFIG_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert tests
                  run_pki-ca-cert-ca_tests
        fi
        CA_CERT_SHOW_UPPERCASE=$(echo $CA_CERT_SHOW | tr [a-z] [A-Z])
        if [ "$CA_CERT_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-show tests
                  subsystemType=ca
                  run_pki-ca-cert-show-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_REQUEST_SHOW_UPPERCASE=$(echo $CA_CERT_REQUEST_SHOW | tr [a-z] [A-Z])
        if [ "$CA_CERT_REQUEST_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-request-show tests
                  subsystemType=ca
                  run_pki-ca-cert-request-show-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_REVOKE_UPPERCASE=$(echo $CA_CERT_REVOKE | tr [a-z] [A-Z])
        if [ "$CA_CERT_REVOKE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-revoke tests
                  subsystemType=ca
                  run_pki-ca-cert-revoke-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_RELEASE_HOLD_UPPERCASE=$(echo $CA_CERT_RELEASE_HOLD | tr [a-z] [A-Z])
        if [ "$CA_CERT_RELEASE_HOLD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-release-hold tests
                  subsystemType=ca
                  run_pki-ca-cert-release-hold-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_HOLD_UPPERCASE=$(echo $CA_CERT_HOLD | tr [a-z] [A-Z])
        if [ "$CA_CERT_HOLD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-hold tests
                  subsystemType=ca
                  run_pki-ca-cert-hold-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_REQUEST_SUBMIT_UPPERCASE=$(echo $CA_CERT_REQUEST_SUBMIT | tr [a-z] [A-Z])
        if [ "$CA_CERT_REQUEST_SUBMIT_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-request-submit tests
                  subsystemType=ca
                  run_pki-ca-cert-request-submit_tests $subsystemType $MYROLE
        fi
        CA_CERT_REQUEST_PROFILE_FIND_UPPERCASE=$(echo $CA_CERT_REQUEST_PROFILE_FIND | tr [a-z] [A-Z])
        if [ "$CA_CERT_REQUEST_PROFILE_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-request-profile-find tests
                  subsystemType=ca
                  run_pki-ca-cert-request-profile-find-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_REQUEST_PROFILE_SHOW_UPPERCASE=$(echo $CA_CERT_REQUEST_PROFILE_SHOW | tr [a-z] [A-Z])
        if [ "$CA_CERT_REQUEST_PROFILE_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-request-profile-show tests
                  subsystemType=ca
                  run_pki-ca-cert-request-profile-show-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_REQUEST_REVIEW_UPPERCASE=$(echo $CA_CERT_REQUEST_REVIEW | tr [a-z] [A-Z])
        if [ "$CA_CERT_REQUEST_REVIEW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-request-review tests
                  subsystemType=ca
                  run_pki-ca-cert-request-review-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_REQUEST_FIND_UPPERCASE=$(echo $CA_CERT_REQUEST_FIND | tr [a-z] [A-Z])
        if [ "$CA_CERT_REQUEST_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-request-find tests
                  subsystemType=ca
                  run_pki-ca-cert-request-find-ca_tests $subsystemType $MYROLE
        fi
        CA_CERT_FIND_UPPERCASE=$(echo $CA_CERT_FIND | tr [a-z] [A-Z])
        if [ "$CA_CERT_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-cert-find tests
                  subsystemType=ca
                  run_pki-ca-cert-find-ca_tests $subsystemType $MYROLE
        fi
	######## PKI GROUP CA TESTS ############
	PKI_GROUP_CA_TEST_UPPERCASE=$(echo $PKI_GROUP_CA_TEST | tr [a-z] [A-Z])
        if [ "$PKI_GROUP_CA_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki group tests for ca
		subsystemId=$CA_INST
                subsystemType=ca
		run_pki-group-cli-group-add-ca_tests  $subsystemId $subsystemType $MYROLE
                run_pki-group-cli-group-show-ca_tests  $subsystemId $subsystemType $MYROLE
                run_pki-group-cli-group-find-ca_tests  $subsystemId $subsystemType $MYROLE
                run_pki-group-cli-group-mod-ca_tests  $subsystemId $subsystemType $MYROLE
                run_pki-group-cli-group-del-ca_tests  $subsystemId $subsystemType $MYROLE
                run_pki-group-cli-group-member-add-ca_tests  $subsystemId $subsystemType $MYROLE
                run_pki-group-cli-group-member-find-ca_tests  $subsystemId $subsystemType $MYROLE
	fi
	GROUP_ADD_UPPERCASE=$(echo $GROUP_ADD | tr [a-z] [A-Z])
        if [ "$GROUP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-add-ca tests
		  subsystemId=$CA_INST
                subsystemType=ca
		  run_pki-group-cli-group-add-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
	GROUP_SHOW_UPPERCASE=$(echo $GROUP_SHOW | tr [a-z] [A-Z])
        if [ "$GROUP_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-show-ca tests
		  subsystemId=$CA_INST
                subsystemType=ca
                  run_pki-group-cli-group-show-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
	GROUP_FIND_UPPERCASE=$(echo $GROUP_FIND | tr [a-z] [A-Z])
        if [ "$GROUP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-find-ca tests
		  subsystemId=$CA_INST
                subsystemType=ca
                  run_pki-group-cli-group-find-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
	GROUP_MOD_UPPERCASE=$(echo $GROUP_MOD | tr [a-z] [A-Z])
        if [ "$GROUP_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-mod-ca tests
		  subsystemId=$CA_INST
                subsystemType=ca
                  run_pki-group-cli-group-mod-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
	GROUP_DEL_UPPERCASE=$(echo $GROUP_DEL | tr [a-z] [A-Z])
        if [ "$GROUP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-del-ca tests
		  subsystemId=$CA_INST
                subsystemType=ca
                  run_pki-group-cli-group-del-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
	GROUP_MEMBER_ADD_UPPERCASE=$(echo $GROUP_MEMBER_ADD | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-add-ca tests
		  subsystemId=$CA_INST
                subsystemType=ca
                  run_pki-group-cli-group-member-add-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
	GROUP_MEMBER_FIND_UPPERCASE=$(echo $GROUP_MEMBER_FIND | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-find-ca tests
		  subsystemId=$CA_INST
                subsystemType=ca
                  run_pki-group-cli-group-member-find-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
	GROUP_MEMBER_DEL_UPPERCASE=$(echo $GROUP_MEMBER_DEL | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-del-ca tests
		  subsystemId=$CA_INST
                subsystemType=ca
                  run_pki-group-cli-group-member-del-ca_tests  $subsystemId $subsystemType $MYROLE
        fi
	GROUP_MEMBER_SHOW_UPPERCASE=$(echo $GROUP_MEMBER_SHOW | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-show-ca tests
		  subsystemId=$CA_INST
                subsystemType=ca
                  run_pki-group-cli-group-member-show-ca_tests  $subsystemId $subsystemType $MYROLE
        fi

	######## PKI GROUP KRA TESTS ############
        PKI_GROUP_KRA_TEST_UPPERCASE=$(echo $PKI_GROUP_KRA_TEST | tr [a-z] [A-Z])
        if [ "$PKI_GROUP_KRA_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki group tests for kra
                subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                run_pki-group-cli-group-add-kra_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-group-cli-group-show-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-find-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-mod-kra_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-group-cli-group-del-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-add-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-find-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
		run_pki-group-cli-group-member-show-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
		run_pki-group-cli-group-member-del-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_ADD_KRA_UPPERCASE=$(echo $GROUP_ADD_KRA | tr [a-z] [A-Z])
        if [ "$GROUP_ADD_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-add-kra tests
                  subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                  run_pki-group-cli-group-add-kra_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
	GROUP_SHOW_KRA_UPPERCASE=$(echo $GROUP_SHOW_KRA | tr [a-z] [A-Z])
        if [ "$GROUP_SHOW_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-show-kra tests
                  subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                  run_pki-group-cli-group-show-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_FIND_KRA_UPPERCASE=$(echo $GROUP_FIND_KRA | tr [a-z] [A-Z])
        if [ "$GROUP_FIND_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-find-kra tests
                  subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                  run_pki-group-cli-group-find-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MOD_KRA_UPPERCASE=$(echo $GROUP_MOD_KRA | tr [a-z] [A-Z])
        if [ "$GROUP_MOD_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-mod-kra tests
                  subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                  run_pki-group-cli-group-mod-kra_tests  $subsystemId $subsystemType $MYROLE $caId 
        fi
        GROUP_DEL_KRA_UPPERCASE=$(echo $GROUP_DEL_KRA | tr [a-z] [A-Z])
        if [ "$GROUP_DEL_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-del-kra tests
                  subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                  run_pki-group-cli-group-del-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	GROUP_MEMBER_ADD_KRA_UPPERCASE=$(echo $GROUP_MEMBER_ADD_KRA | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_ADD_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-add-kra tests
                  subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                  run_pki-group-cli-group-member-add-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_FIND_KRA_UPPERCASE=$(echo $GROUP_MEMBER_FIND_KRA | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_FIND_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-find-kra tests
                  subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                  run_pki-group-cli-group-member-find-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_DEL_KRA_UPPERCASE=$(echo $GROUP_MEMBER_DEL_KRA | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_DEL_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-del-kra tests
                  subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                  run_pki-group-cli-group-member-del-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_SHOW_KRA_UPPERCASE=$(echo $GROUP_MEMBER_SHOW_KRA | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_SHOW_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-show-kra tests
                  subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                  run_pki-group-cli-group-member-show-kra_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	######## PKI CA GROUP TESTS ############
        PKI_CA_GROUP_TEST_UPPERCASE=$(echo $PKI_CA_GROUP_TEST | tr [a-z] [A-Z])
        if [ "$PKI_CA_GROUP_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki ca-group tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-add_tests  $subsystemId $subsystemType $MYROLE
                run_pki-ca-group-cli-ca-group-mod_tests  $subsystemId $subsystemType $MYROLE
                run_pki-ca-group-cli-ca-group-find_tests  $subsystemId $subsystemType $MYROLE
                run_pki-ca-group-cli-ca-group-show_tests  $subsystemId $subsystemType $MYROLE
                run_pki-ca-group-cli-ca-group-del_tests  $subsystemId $subsystemType $MYROLE
                run_pki-ca-group-cli-ca-group-member-add_tests  $subsystemId $subsystemType $MYROLE
                run_pki-ca-group-cli-ca-group-member-show_tests  $subsystemId $subsystemType $MYROLE
                run_pki-ca-group-cli-ca-group-member-find_tests  $subsystemId $subsystemType $MYROLE
                run_pki-ca-group-cli-ca-group-member-del_tests  $subsystemId $subsystemType $MYROLE
        fi

        CA_GROUP_ADD_UPPERCASE=$(echo $CA_GROUP_ADD | tr [a-z] [A-Z])
        if [ "$CA_GROUP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-add tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-add_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_GROUP_MOD_UPPERCASE=$(echo $CA_GROUP_MOD | tr [a-z] [A-Z])
        if [ "$CA_GROUP_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-mod tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-mod_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_GROUP_FIND_UPPERCASE=$(echo $CA_GROUP_FIND | tr [a-z] [A-Z])
        if [ "$CA_GROUP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-find tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-find_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_GROUP_SHOW_UPPERCASE=$(echo $CA_GROUP_SHOW | tr [a-z] [A-Z])
        if [ "$CA_GROUP_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-show tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-show_tests  $subsystemId $subsystemType $MYROLE
	fi
        CA_GROUP_DEL_UPPERCASE=$(echo $CA_GROUP_DEL | tr [a-z] [A-Z])
        if [ "$CA_GROUP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-del tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-del_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_GROUP_MEMBER_ADD_UPPERCASE=$(echo $CA_GROUP_MEMBER_ADD | tr [a-z] [A-Z])
        if [ "$CA_GROUP_MEMBER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-member-add tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-member-add_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_GROUP_MEMBER_SHOW_UPPERCASE=$(echo $CA_GROUP_MEMBER_SHOW | tr [a-z] [A-Z])
        if [ "$CA_GROUP_MEMBER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-member-show tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-member-show_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_GROUP_MEMBER_FIND_UPPERCASE=$(echo $CA_GROUP_MEMBER_FIND | tr [a-z] [A-Z])
        if [ "$CA_GROUP_MEMBER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-member-find tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-member-find_tests  $subsystemId $subsystemType $MYROLE
        fi
        CA_GROUP_MEMBER_DEL_UPPERCASE=$(echo $CA_GROUP_MEMBER_DEL | tr [a-z] [A-Z])
        if [ "$CA_GROUP_MEMBER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-group-member-del tests
                subsystemId=$CA_INST
                subsystemType=ca
                run_pki-ca-group-cli-ca-group-member-del_tests  $subsystemId $subsystemType $MYROLE
        fi

	BIG_INT_UPPERCASE=$(echo $BIG_INT | tr [a-z] [A-Z])
	if [ "$BIG_INT_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		#Execute pki bigInt tests
		run_pki_big_int
		run_pki_cert
		run_pki_cert_show
		run_pki_cert_request_show
	fi

	######## PKI BUG VERIFICATIONS ############
	BUG_VERIFICATION_UPPERCASE=$(echo $BUG_VERIFICATION | tr [a-z] [A-Z])
        if [ "$BUG_VERIFICATION_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		#Execute bug verification
                run_bug_verification_setup
                run_CS-backup-bug-verification
                run_pki-core-bug-verification
                run_tomcatjss-bug-verification
                run_bug-1058366-verification
                run_bug-1133718-verification
                run_bug-1040640-verification
                run_bug-uninstall
		run_bug_790924
        fi
	
	######## PKI KEY KRA TESTS ############
	PKI_KEY_KRA_TESTS_UPPERCASE=$(echo $PKI_KEY_KRA_TESTS | tr [a-z] [A-Z])
        if [ "$PKI_KEY_KRA_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		subsystemType=kra
		run_pki-key-kra_tests
		run_pki-key-generate-kra_tests $subsystemType $MYROLE
		run_pki-key-find-kra_tests $subsystemType $MYROLE
		run_pki-key-template-find-kra_tests
		run_pki-key-template-show-kra_tests
		run_pki-key-request-find-kra_tests $subsystemType $MYROLE
		run_pki-key-show-kra_tests $subsystemType $MYROLE
		run_pki-key-request-show-kra_tests $subsystemType $MYROLE
		run_pki-key-mod-kra_tests $subsystemType $MYROLE
		run_pki-key-recover-kra_tests $subsystemType $MYROLE
		run_pki-key-archive-kra_tests $subsystemType $MYROLE
		run_pki-key-retrieve-kra_tests $subsystemType $MYROLE
		run_pki-key-request-review-kra_tests $subsystemType $MYROLE

	fi
	KEY_CONFIG_KRA_UPPERCASE=$(echo $KEY_CONFIG_KRA | tr [a-z] [A-Z]) 
	if [ "$KEY_CONFIG_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key config tests
		 run_pki-key-kra_tests
	fi
	KEY_GENERATE_KRA_UPPERCASE=$(echo $KEY_GENERATE_KRA | tr [a-z] [A-Z])
	if [ "$KEY_GENERATE_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key generate tests
		  subsystemType=kra
		  run_pki-key-generate-kra_tests $subsystemType $MYROLE
	fi
	KEY_FIND_KRA_UPPERCASE=$(echo $KEY_FIND_KRA | tr [a-z] [A-Z])
	if [ "$KEY_FIND_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key find tests
		  subsystemType=kra
		  run_pki-key-find-kra_tests $subsystemType $MYROLE
	fi
	KEY_TEMPLATE_FIND_KRA_UPPERCASE=$(echo $KEY_TEMPLATE_FIND_KRA | tr [a-z] [A-Z])
	if [ "$KEY_TEMPLATE_FIND_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key template-find tests
		 run_pki-key-template-find-kra_tests
	fi
	KEY_TEMPLATE_SHOW_KRA_UPPERCASE=$(echo $KEY_TEMPLATE_SHOW_KRA | tr [a-z] [A-Z])
	if [ "$KEY_TEMPLATE_SHOW_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key template-show tests
		 run_pki-key-template-show-kra_tests
	fi
	KEY_REQUEST_FIND_KRA_UPPERCASE=$(echo $KEY_REQUEST_FIND_KRA | tr [a-z] [A-Z])
	if [ "$KEY_REQUEST_FIND_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key request-find tests 
		  subsystemType=kra
		  run_pki-key-request-find-kra_tests $subsystemType $MYROLE
	fi
	KEY_SHOW_KRA_UPPERCASE=$(echo $KEY_SHOW_KRA | tr [a-z] [A-Z])
	if [ "$KEY_SHOW_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-show tests 
		  subsystemType=kra
		  run_pki-key-show-kra_tests $subsystemType $MYROLE
	fi
	KEY_REQUEST_SHOW_KRA_UPPERCASE=$(echo $KEY_REQUEST_SHOW_KRA | tr [a-z] [A-Z])
	if [ "$KEY_REQUEST_SHOW_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-request-show tests 
		  subsystemType=kra
		  run_pki-key-request-show-kra_tests $subsystemType $MYROLE
	fi
	KEY_MOD_KRA_UPPERCASE=$(echo $KEY_MOD_KRA | tr [a-z] [A-Z])
	if [ "$KEY_MOD_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-mod tests
		  subsystemType=kra
		  run_pki-key-mod-kra_tests $subsystemType $MYROLE
	fi
	KEY_RECOVER_KRA_UPPERCASE=$(echo $KEY_RECOVER_KRA | tr [a-z] [A-Z])
	if [ "$KEY_RECOVER_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-recover tests
		subsystemType=kra
		run_pki-key-recover-kra_tests $subsystemType $MYROLE
	fi
	KEY_ARCHIVE_KRA_UPPERCASE=$(echo $KEY_ARCHIVE_KRA | tr [a-z] [A-Z])
	if [ "$KEY_ARCHIVE_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-archive tests
		subsystemType=kra
		run_pki-key-archive-kra_tests $subsystemType $MYROLE
	fi
	KEY_RETRIEVE_KRA_UPPERCASE=$(echo $KEY_RETRIEVE_KRA | tr [a-z] [A-Z])	
	if [ "$KEY_RETRIEVE_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-retrieve tests
		subsystemType=kra
		run_pki-key-retrieve-kra_tests $subsystemType $MYROLE
	fi
	KEY_REQUEST_REVIEW_KRA_UPPERCASE=$(echo $KEY_REQUEST_REVIEW_KRA | tr [a-z] [A-Z])
	if [ "$KEY_REQUEST_REVIEW_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki key-request-review tests
		subsystemType=kra
		run_pki-key-request-review-kra_tests $subsystemType $MYROLE
	fi
	
	######## PKI KRA KEY TESTS ############
	PKI_KRA_KEY_TESTS_UPPERCASE=$(echo $PKI_KRA_KEY_TESTS | tr [a-z] [A-Z])
        if [ "$PKI_KRA_KEY_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		subsystemType=kra
		run_pki-kra-key-kra_tests
		run_pki-kra-key-generate-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-find-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-template-find-kra_tests
		run_pki-kra-key-template-show-kra_tests
		run_pki-kra-key-request-find-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-show-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-request-show-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-mod-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-recover-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-archive-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-retrieve-kra_tests $subsystemType $MYROLE
		run_pki-kra-key-request-review-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_CONFIG_UPPERCASE=$(echo $KRA_KEY_CONFIG | tr [a-z] [A-Z]) 
	if [ "$KRA_KEY_CONFIG_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key config tests
		run_pki-kra-key-kra_tests 
	fi
	KRA_KEY_GENERATE_UPPERCASE=$(echo $KRA_KEY_GENERATE | tr [a-z] [A-Z])
	if [ "$KRA_KEY_GENERATE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key generate tests
		  subsystemType=kra
		  run_pki-kra-key-generate-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_FIND_UPPERCASE=$(echo $KRA_KEY_FIND | tr [a-z] [A-Z])
	if [ "$KRA_KEY_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key find tests
		  subsystemType=kra
		  run_pki-kra-key-find-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_TEMPLATE_FIND_UPPERCASE=$(echo $KRA_KEY_TEMPLATE_FIND | tr [a-z] [A-Z])
	if [ "$KRA_KEY_TEMPLATE_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key template-find tests
		  run_pki-kra-key-template-find-kra_tests
	fi
	KRA_KEY_TEMPLATE_SHOW_UPPERCASE=$(echo $KRA_KEY_TEMPLATE_SHOW | tr [a-z] [A-Z])
	if [ "$KRA_KEY_TEMPLATE_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key template-show tests
		 run_pki-kra-key-template-show-kra_tests
	fi
	KRA_KEY_REQUEST_FIND_UPPERCASE=$(echo $KRA_KEY_REQUEST_FIND | tr [a-z] [A-Z])
	if [ "$KRA_KEY_REQUEST_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key request-find tests 
		  subsystemType=kra
		  run_pki-kra-key-request-find-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_SHOW_UPPERCASE=$(echo $KRA_KEY_SHOW | tr [a-z] [A-Z])
	if [ "$KRA_KEY_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-show tests 
		  subsystemType=kra
		  run_pki-kra-key-show-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_REQUEST_SHOW_UPPERCASE=$(echo $KRA_KEY_REQUEST_SHOW | tr [a-z] [A-Z])
	if [ "$KRA_KEY_REQUEST_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-request-show tests 
		  subsystemType=kra
		  run_pki-kra-key-request-show-kra_tests $subsystemType $MYROLE
  	fi
	KRA_KEY_MOD_UPPERCASE=$(echo $KRA_KEY_MOD | tr [a-z] [A-Z])
	if [ "$KRA_KEY_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-mod tests
		  subsystemType=kra
		  run_pki-kra-key-mod-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_RECOVER_UPPERCASE=$(echo $KRA_KEY_RECOVER | tr [a-z] [A-Z])
	if [ "$KEY_RECOVER_KRA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-recover tests
		subsystemType=kra
		run_pki-kra-key-recover-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_ARCHIVE_UPPERCASE=$(echo $KRA_KEY_ARCHIVE | tr [a-z] [A-Z])
	if [ "$KRA_KEY_ARCHIVE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-archive tests
		subsystemType=kra
		run_pki-kra-key-archive-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_RETRIEVE_UPPERCASE=$(echo $KRA_KEY_RETRIEVE | tr [a-z] [A-Z])	
	if [ "$KRA_KEY_RETRIEVE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-retrieve tests
		subsystemType=kra
		run_pki-kra-key-retrieve-kra_tests $subsystemType $MYROLE
	fi
	KRA_KEY_REQUEST_REVIEW_UPPERCASE=$(echo $KRA_KEY_REQUEST_REVIEW | tr [a-z] [A-Z])
	if [ "$KRA_KEY_REQUEST_REVIEW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		# Execute pki kra key-request-review tests
		subsystemType=kra
		run_pki-kra-key-request-review-kra_tests $subsystemType $MYROLE	
	fi

	######## PKI KRA_USER TESTS ############
        PKI_KRA_USER_UPPERCASE=$(echo $PKI_KRA_USER | tr [a-z] [A-Z])
        if [ "$PKI_KRA_USER_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-user tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
		  caId=$CA_INST
		  run_pki-kra-user-cli-kra-user-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-kra-user-cli-kra-user-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-kra-user-cli-kra-user-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-kra-user-cli-kra-user-mod_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
		  run_pki-kra-user-cli-kra-user-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-kra-user-cli-kra-user-membership-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-kra-user-cli-kra-user-membership-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-kra-user-cli-kra-user-membership-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-kra-user-cli-user-cert-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-kra-user-cli-kra-user-cert-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-kra-user-cli-kra-user-cert-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-kra-user-cli-kra-user-cert-delete_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	KRA_USER_ADD_UPPERCASE=$(echo $KRA_USER_ADD | tr [a-z] [A-Z])
        if [ "$KRA_USER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-user-add tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-kra-user-cli-kra-user-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_USER_SHOW_UPPERCASE=$(echo $KRA_USER_SHOW | tr [a-z] [A-Z])
        if [ "$KRA_USER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-user-show tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-kra-user-cli-kra-user-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_USER_FIND_UPPERCASE=$(echo $KRA_USER_FIND | tr [a-z] [A-Z])
        if [ "$KRA_USER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-user-find tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-kra-user-cli-kra-user-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	KRA_USER_MOD_UPPERCASE=$(echo $KRA_USER_MOD | tr [a-z] [A-Z])
        if [ "$KRA_USER_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-user-mod tests
                  subsystemId=$KRA_INST
		  subsystemType=kra
		  caId=$CA_INST
                  run_pki-kra-user-cli-kra-user-mod_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	KRA_USER_DEL_UPPERCASE=$(echo $KRA_USER_DEL | tr [a-z] [A-Z])
        if [ "$KRA_USER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-user-del tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-kra-user-cli-kra-user-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_USER_MEMBERSHIP_ADD_UPPERCASE=$(echo $KRA_USER_MEMBERSHIP_ADD | tr [a-z] [A-Z])
        if [ "$KRA_USER_MEMBERSHIP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-user-membership-add tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-kra-user-cli-kra-user-membership-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_USER_MEMBERSHIP_FIND_UPPERCASE=$(echo $KRA_USER_MEMBERSHIP_FIND | tr [a-z] [A-Z])
        if [ "$KRA_USER_MEMBERSHIP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-user-membership-find tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-kra-user-cli-kra-user-membership-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_USER_MEMBERSHIP_DEL_UPPERCASE=$(echo $KRA_USER_MEMBERSHIP_DEL | tr [a-z] [A-Z])
        if [ "$KRA_USER_MEMBERSHIP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-user-membership-del tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  caId=$CA_INST
                  run_pki-kra-user-cli-kra-user-membership-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_USER_CERT_ADD_UPPERCASE=$(echo $KRA_USER_CERT_ADD | tr [a-z] [A-Z])
        if [ "$KRA_USER_CERT_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-cert-add tests
                  subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                  run_pki-kra-user-cli-user-cert-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-kra-user-cert  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_USER_CERT_FIND_UPPERCASE=$(echo $KRA_USER_CERT_FIND | tr [a-z] [A-Z])
        if [ "$KRA_USER_CERT_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-user-cert-find tests
                subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                run_pki-kra-user-cli-kra-user-cert-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_USER_CERT_SHOW_UPPERCASE=$(echo $KRA_USER_CERT_SHOW | tr [a-z] [A-Z])
        if [ "$KRA_USER_CERT_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-user-cert-show tests
                subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                run_pki-kra-user-cli-kra-user-cert-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_USER_CERT_DEL_UPPERCASE=$(echo $KRA_USER_CERT_DEL | tr [a-z] [A-Z])
        if [ "$KRA_USER_CERT_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-user-cert-del tests
                subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                run_pki-kra-user-cli-kra-user-cert-delete_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi

	######## PKI OCSP_USER TESTS ############
        PKI_OCSP_USER_UPPERCASE=$(echo $PKI_OCSP_USER | tr [a-z] [A-Z])
        if [ "$PKI_OCSP_USER_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-user tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-ocsp-user-cli-ocsp-user-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-ocsp-user-cli-ocsp-user-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-ocsp-user-cli-ocsp-user-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-ocsp-user-cli-ocsp-user-mod_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-ocsp-user-cli-ocsp-user-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-ocsp-user-cli-ocsp-user-membership-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-ocsp-user-cli-ocsp-user-membership-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-ocsp-user-cli-ocsp-user-membership-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-ocsp-user-cli-ocsp-user-cert  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-ocsp-user-cli-ocsp-user-cert-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-ocsp-user-cli-ocsp-user-cert-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-ocsp-user-cli-ocsp-user-cert-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-ocsp-user-cli-ocsp-user-cert-delete_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_USER_ADD_UPPERCASE=$(echo $OCSP_USER_ADD | tr [a-z] [A-Z])
        if [ "$OCSP_USER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-user-add tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-ocsp-user-cli-ocsp-user-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_USER_SHOW_UPPERCASE=$(echo $OCSP_USER_SHOW | tr [a-z] [A-Z])
        if [ "$OCSP_USER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-user-show tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-ocsp-user-cli-ocsp-user-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	OCSP_USER_FIND_UPPERCASE=$(echo $OCSP_USER_FIND | tr [a-z] [A-Z])
        if [ "$OCSP_USER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-user-find tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-ocsp-user-cli-ocsp-user-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_USER_MOD_UPPERCASE=$(echo $OCSP_USER_MOD | tr [a-z] [A-Z])
        if [ "$OCSP_USER_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-user-mod tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-ocsp-user-cli-ocsp-user-mod_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_USER_DEL_UPPERCASE=$(echo $OCSP_USER_DEL | tr [a-z] [A-Z])
        if [ "$OCSP_USER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-user-del tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-ocsp-user-cli-ocsp-user-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_USER_MEMBERSHIP_ADD_UPPERCASE=$(echo $OCSP_USER_MEMBERSHIP_ADD | tr [a-z] [A-Z])
        if [ "$OCSP_USER_MEMBERSHIP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-user-membership-add tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-ocsp-user-cli-ocsp-user-membership-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_USER_MEMBERSHIP_FIND_UPPERCASE=$(echo $OCSP_USER_MEMBERSHIP_FIND | tr [a-z] [A-Z])
        if [ "$OCSP_USER_MEMBERSHIP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-user-membership-find tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-ocsp-user-cli-ocsp-user-membership-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	OCSP_USER_MEMBERSHIP_DEL_UPPERCASE=$(echo $OCSP_USER_MEMBERSHIP_DEL | tr [a-z] [A-Z])
        if [ "$OCSP_USER_MEMBERSHIP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-user-membership-del tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  caId=$CA_INST
                  run_pki-ocsp-user-cli-ocsp-user-membership-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_USER_CERT_ADD_UPPERCASE=$(echo $OCSP_USER_CERT_ADD | tr [a-z] [A-Z])
        if [ "$OCSP_USER_CERT_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-cert-add tests
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                  run_pki-ocsp-user-cli-ocsp-user-cert  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-ocsp-user-cli-ocsp-user-cert-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_USER_CERT_FIND_UPPERCASE=$(echo $OCSP_USER_CERT_FIND | tr [a-z] [A-Z])
        if [ "$OCSP_USER_CERT_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-user-cert-find tests
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                run_pki-ocsp-user-cli-ocsp-user-cert-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_USER_CERT_SHOW_UPPERCASE=$(echo $OCSP_USER_CERT_SHOW | tr [a-z] [A-Z])
        if [ "$OCSP_USER_CERT_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-user-cert-show tests
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                run_pki-ocsp-user-cli-ocsp-user-cert-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_USER_CERT_DEL_UPPERCASE=$(echo $OCSP_USER_CERT_DEL | tr [a-z] [A-Z])
        if [ "$OCSP_USER_CERT_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-user-cert-del tests
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                run_pki-ocsp-user-cli-ocsp-user-cert-delete_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	
	######## PKI TKS_USER TESTS ############
        PKI_TKS_USER_UPPERCASE=$(echo $PKI_TKS_USER | tr [a-z] [A-Z])
        if [ "$PKI_TKS_USER_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-user tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-tks-user-cli-tks-user-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tks-user-cli-tks-user-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tks-user-cli-tks-user-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tks-user-cli-tks-user-mod_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tks-user-cli-tks-user-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tks-user-cli-tks-user-membership-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tks-user-cli-tks-user-membership-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tks-user-cli-tks-user-membership-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tks-user-cli-tks-user-cert  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tks-user-cli-tks-user-cert-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tks-user-cli-tks-user-cert-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tks-user-cli-tks-user-cert-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tks-user-cli-tks-user-cert-delete_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_USER_ADD_UPPERCASE=$(echo $TKS_USER_ADD | tr [a-z] [A-Z])
        if [ "$TKS_USER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-user-add tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-tks-user-cli-tks-user-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_USER_SHOW_UPPERCASE=$(echo $TKS_USER_SHOW | tr [a-z] [A-Z])
        if [ "$TKS_USER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-user-show tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-tks-user-cli-tks-user-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	TKS_USER_FIND_UPPERCASE=$(echo $TKS_USER_FIND | tr [a-z] [A-Z])
        if [ "$TKS_USER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-user-find tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-tks-user-cli-tks-user-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_USER_MOD_UPPERCASE=$(echo $TKS_USER_MOD | tr [a-z] [A-Z])
        if [ "$TKS_USER_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-user-mod tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-tks-user-cli-tks-user-mod_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_USER_DEL_UPPERCASE=$(echo $TKS_USER_DEL | tr [a-z] [A-Z])
        if [ "$TKS_USER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-user-del tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-tks-user-cli-tks-user-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_USER_MEMBERSHIP_ADD_UPPERCASE=$(echo $TKS_USER_MEMBERSHIP_ADD | tr [a-z] [A-Z])
        if [ "$TKS_USER_MEMBERSHIP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-user-membership-add tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-tks-user-cli-tks-user-membership-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_USER_MEMBERSHIP_FIND_UPPERCASE=$(echo $TKS_USER_MEMBERSHIP_FIND | tr [a-z] [A-Z])
        if [ "$TKS_USER_MEMBERSHIP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-user-membership-find tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-tks-user-cli-tks-user-membership-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	TKS_USER_MEMBERSHIP_DEL_UPPERCASE=$(echo $TKS_USER_MEMBERSHIP_DEL | tr [a-z] [A-Z])
        if [ "$TKS_USER_MEMBERSHIP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-user-membership-del tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  caId=$CA_INST
                  run_pki-tks-user-cli-tks-user-membership-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_USER_CERT_ADD_UPPERCASE=$(echo $TKS_USER_CERT_ADD | tr [a-z] [A-Z])
        if [ "$TKS_USER_CERT_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-cert-add tests
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                  run_pki-tks-user-cli-tks-user-cert  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tks-user-cli-tks-user-cert-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_USER_CERT_FIND_UPPERCASE=$(echo $TKS_USER_CERT_FIND | tr [a-z] [A-Z])
        if [ "$TKS_USER_CERT_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-user-cert-find tests
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                run_pki-tks-user-cli-tks-user-cert-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_USER_CERT_SHOW_UPPERCASE=$(echo $TKS_USER_CERT_SHOW | tr [a-z] [A-Z])
        if [ "$TKS_USER_CERT_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-user-cert-show tests
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                run_pki-tks-user-cli-tks-user-cert-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_USER_CERT_DEL_UPPERCASE=$(echo $TKS_USER_CERT_DEL | tr [a-z] [A-Z])
        if [ "$TKS_USER_CERT_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-user-cert-del tests
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                run_pki-tks-user-cli-tks-user-cert-delete_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi

	######## PKI TPS_USER TESTS ############
        PKI_TPS_USER_UPPERCASE=$(echo $PKI_TPS_USER | tr [a-z] [A-Z])
        if [ "$PKI_TPS_USER_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-user tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-tps-user-cli-tps-user-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tps-user-cli-tps-user-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tps-user-cli-tps-user-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tps-user-cli-tps-user-mod_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tps-user-cli-tps-user-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tps-user-cli-tps-user-membership-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tps-user-cli-tps-user-membership-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tps-user-cli-tps-user-membership-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tps-user-cli-tps-user-cert  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tps-user-cli-tps-user-cert-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tps-user-cli-tps-user-cert-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tps-user-cli-tps-user-cert-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tps-user-cli-tps-user-cert-delete_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_USER_ADD_UPPERCASE=$(echo $TPS_USER_ADD | tr [a-z] [A-Z])
        if [ "$TPS_USER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-user-add tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-tps-user-cli-tps-user-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_USER_SHOW_UPPERCASE=$(echo $TPS_USER_SHOW | tr [a-z] [A-Z])
        if [ "$TPS_USER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-user-show tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-tps-user-cli-tps-user-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	TPS_USER_FIND_UPPERCASE=$(echo $TPS_USER_FIND | tr [a-z] [A-Z])
        if [ "$TPS_USER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-user-find tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-tps-user-cli-tps-user-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_USER_MOD_UPPERCASE=$(echo $TPS_USER_MOD | tr [a-z] [A-Z])
        if [ "$TPS_USER_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-user-mod tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-tps-user-cli-tps-user-mod_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_USER_DEL_UPPERCASE=$(echo $TPS_USER_DEL | tr [a-z] [A-Z])
        if [ "$TPS_USER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-user-del tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-tps-user-cli-tps-user-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_USER_MEMBERSHIP_ADD_UPPERCASE=$(echo $TPS_USER_MEMBERSHIP_ADD | tr [a-z] [A-Z])
        if [ "$TPS_USER_MEMBERSHIP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-user-membership-add tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-tps-user-cli-tps-user-membership-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_USER_MEMBERSHIP_FIND_UPPERCASE=$(echo $TPS_USER_MEMBERSHIP_FIND | tr [a-z] [A-Z])
        if [ "$TPS_USER_MEMBERSHIP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-user-membership-find tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-tps-user-cli-tps-user-membership-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	TPS_USER_MEMBERSHIP_DEL_UPPERCASE=$(echo $TPS_USER_MEMBERSHIP_DEL | tr [a-z] [A-Z])
        if [ "$TPS_USER_MEMBERSHIP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-user-membership-del tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  caId=$CA_INST
                  run_pki-tps-user-cli-tps-user-membership-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_USER_CERT_ADD_UPPERCASE=$(echo $TPS_USER_CERT_ADD | tr [a-z] [A-Z])
        if [ "$TPS_USER_CERT_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-user-cert-add tests
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                  run_pki-tps-user-cli-tps-user-cert  $subsystemId $subsystemType $MYROLE $caId $MASTER
                  run_pki-tps-user-cli-tps-user-cert-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_USER_CERT_FIND_UPPERCASE=$(echo $TPS_USER_CERT_FIND | tr [a-z] [A-Z])
        if [ "$TPS_USER_CERT_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-user-cert-find tests
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                run_pki-tps-user-cli-tps-user-cert-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_USER_CERT_SHOW_UPPERCASE=$(echo $TPS_USER_CERT_SHOW | tr [a-z] [A-Z])
        if [ "$TPS_USER_CERT_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-user-cert-show tests
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                run_pki-tps-user-cli-tps-user-cert-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_USER_CERT_DEL_UPPERCASE=$(echo $TPS_USER_CERT_DEL | tr [a-z] [A-Z])
        if [ "$TPS_USER_CERT_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-user-cert-del tests
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                run_pki-tps-user-cli-tps-user-cert-delete_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi

	######## PKI KRA GROUP TESTS ############
        PKI_KRA_GROUP_TEST_UPPERCASE=$(echo $PKI_KRA_GROUP_TEST | tr [a-z] [A-Z])
        if [ "$PKI_KRA_GROUP_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki kra-group tests
                subsystemId=$KRA_INST
		caId=$CA_INST
                subsystemType=kra
                run_pki-kra-group-cli-kra-group-add_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-kra-group-cli-kra-group-mod_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-kra-group-cli-kra-group-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-kra-group-cli-kra-group-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-kra-group-cli-kra-group-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-kra-group-cli-kra-group-member-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-kra-group-cli-kra-group-member-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-kra-group-cli-kra-group-member-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-kra-group-cli-kra-group-member-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi

        KRA_GROUP_ADD_UPPERCASE=$(echo $KRA_GROUP_ADD | tr [a-z] [A-Z])
        if [ "$KRA_GROUP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-group-add tests
                subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                run_pki-kra-group-cli-kra-group-add_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        KRA_GROUP_MOD_UPPERCASE=$(echo $KRA_GROUP_MOD | tr [a-z] [A-Z])
        if [ "$KRA_GROUP_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-group-mod tests
                subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                run_pki-kra-group-cli-kra-group-mod_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        KRA_GROUP_FIND_UPPERCASE=$(echo $KRA_GROUP_FIND | tr [a-z] [A-Z])
        if [ "$KRA_GROUP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-group-find tests
                subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                run_pki-kra-group-cli-kra-group-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_GROUP_SHOW_UPPERCASE=$(echo $KRA_GROUP_SHOW | tr [a-z] [A-Z])
        if [ "$KRA_GROUP_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-group-show tests
                subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                run_pki-kra-group-cli-kra-group-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_GROUP_DEL_UPPERCASE=$(echo $KRA_GROUP_DEL | tr [a-z] [A-Z])
        if [ "$KRA_GROUP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-group-del tests
                subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                run_pki-kra-group-cli-kra-group-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_GROUP_MEMBER_ADD_UPPERCASE=$(echo $KRA_GROUP_MEMBER_ADD | tr [a-z] [A-Z])
        if [ "$KRA_GROUP_MEMBER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-group-member-add tests
                subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                run_pki-kra-group-cli-kra-group-member-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_GROUP_MEMBER_SHOW_UPPERCASE=$(echo $KRA_GROUP_MEMBER_SHOW | tr [a-z] [A-Z])
        if [ "$KRA_GROUP_MEMBER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-group-member-show tests
                subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                run_pki-kra-group-cli-kra-group-member-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_GROUP_MEMBER_FIND_UPPERCASE=$(echo $KRA_GROUP_MEMBER_FIND | tr [a-z] [A-Z])
        if [ "$KRA_GROUP_MEMBER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-group-member-find tests
                subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                run_pki-kra-group-cli-kra-group-member-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        KRA_GROUP_MEMBER_DEL_UPPERCASE=$(echo $KRA_GROUP_MEMBER_DEL | tr [a-z] [A-Z])
        if [ "$KRA_GROUP_MEMBER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki kra-group-member-del tests
                subsystemId=$KRA_INST
                subsystemType=kra
		caId=$CA_INST
                run_pki-kra-group-cli-kra-group-member-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	######## PKI GROUP OCSP TESTS ############
        PKI_GROUP_OCSP_TEST_UPPERCASE=$(echo $PKI_GROUP_OCSP_TEST | tr [a-z] [A-Z])
        if [ "$PKI_GROUP_OCSP_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki group tests for ocsp
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                run_pki-group-cli-group-add-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-group-cli-group-show-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-find-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-mod-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-group-cli-group-del-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-add-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-find-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-show-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-del-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_ADD_OCSP_UPPERCASE=$(echo $GROUP_ADD_OCSP | tr [a-z] [A-Z])
        if [ "$GROUP_ADD_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-add-ocsp tests
                  subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                  run_pki-group-cli-group-add-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        GROUP_SHOW_OCSP_UPPERCASE=$(echo $GROUP_SHOW_OCSP | tr [a-z] [A-Z])
        if [ "$GROUP_SHOW_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-show-ocsp tests
                  subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                  run_pki-group-cli-group-show-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_FIND_OCSP_UPPERCASE=$(echo $GROUP_FIND_OCSP | tr [a-z] [A-Z])
        if [ "$GROUP_FIND_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-find-ocsp tests
                  subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                  run_pki-group-cli-group-find-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MOD_OCSP_UPPERCASE=$(echo $GROUP_MOD_OCSP | tr [a-z] [A-Z])
        if [ "$GROUP_MOD_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-mod-ocsp tests
                  subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                  run_pki-group-cli-group-mod-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        GROUP_DEL_OCSP_UPPERCASE=$(echo $GROUP_DEL_OCSP | tr [a-z] [A-Z])
        if [ "$GROUP_DEL_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-del-ocsp tests
                  subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                  run_pki-group-cli-group-del-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_ADD_OCSP_UPPERCASE=$(echo $GROUP_MEMBER_ADD_OCSP | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_ADD_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-add-ocsp tests
                  subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                  run_pki-group-cli-group-member-add-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_FIND_OCSP_UPPERCASE=$(echo $GROUP_MEMBER_FIND_OCSP | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_FIND_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-find-ocsp tests
                  subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                  run_pki-group-cli-group-member-find-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_DEL_OCSP_UPPERCASE=$(echo $GROUP_MEMBER_DEL_OCSP | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_DEL_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-del-ocsp tests
                  subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                  run_pki-group-cli-group-member-del-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_SHOW_OCSP_UPPERCASE=$(echo $GROUP_MEMBER_SHOW_OCSP | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_SHOW_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-show-ocsp tests
                  subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                  run_pki-group-cli-group-member-show-ocsp_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	######## PKI OCSP GROUP TESTS ############
        PKI_OCSP_GROUP_TEST_UPPERCASE=$(echo $PKI_OCSP_GROUP_TEST | tr [a-z] [A-Z])
        if [ "$PKI_OCSP_GROUP_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki ocsp-group tests
                subsystemId=$OCSP_INST
                caId=$CA_INST
                subsystemType=ocsp
                run_pki-ocsp-group-cli-ocsp-group-add_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-ocsp-group-cli-ocsp-group-mod_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-ocsp-group-cli-ocsp-group-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-ocsp-group-cli-ocsp-group-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-ocsp-group-cli-ocsp-group-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-ocsp-group-cli-ocsp-group-member-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-ocsp-group-cli-ocsp-group-member-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-ocsp-group-cli-ocsp-group-member-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-ocsp-group-cli-ocsp-group-member-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_GROUP_ADD_UPPERCASE=$(echo $OCSP_GROUP_ADD | tr [a-z] [A-Z])
        if [ "$OCSP_GROUP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-group-add tests
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                run_pki-ocsp-group-cli-ocsp-group-add_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        OCSP_GROUP_MOD_UPPERCASE=$(echo $OCSP_GROUP_MOD | tr [a-z] [A-Z])
        if [ "$OCSP_GROUP_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-group-mod tests
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                run_pki-ocsp-group-cli-ocsp-group-mod_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        OCSP_GROUP_FIND_UPPERCASE=$(echo $OCSP_GROUP_FIND | tr [a-z] [A-Z])
        if [ "$OCSP_GROUP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-group-find tests
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                run_pki-ocsp-group-cli-ocsp-group-find_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        OCSP_GROUP_SHOW_UPPERCASE=$(echo $OCSP_GROUP_SHOW | tr [a-z] [A-Z])
        if [ "$OCSP_GROUP_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-group-show tests
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                run_pki-ocsp-group-cli-ocsp-group-show_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        OCSP_GROUP_DEL_UPPERCASE=$(echo $OCSP_GROUP_DEL | tr [a-z] [A-Z])
        if [ "$OCSP_GROUP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-group-del tests
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                run_pki-ocsp-group-cli-ocsp-group-del_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        OCSP_GROUP_MEMBER_ADD_UPPERCASE=$(echo $OCSP_GROUP_MEMBER_ADD | tr [a-z] [A-Z])
        if [ "$OCSP_GROUP_MEMBER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-group-member-add tests
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                run_pki-ocsp-group-cli-ocsp-group-member-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_GROUP_MEMBER_SHOW_UPPERCASE=$(echo $OCSP_GROUP_MEMBER_SHOW | tr [a-z] [A-Z])
        if [ "$OCSP_GROUP_MEMBER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-group-member-show tests
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                run_pki-ocsp-group-cli-ocsp-group-member-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_GROUP_MEMBER_FIND_UPPERCASE=$(echo $OCSP_GROUP_MEMBER_FIND | tr [a-z] [A-Z])
        if [ "$OCSP_GROUP_MEMBER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-group-member-find tests
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                run_pki-ocsp-group-cli-ocsp-group-member-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        OCSP_GROUP_MEMBER_DEL_UPPERCASE=$(echo $OCSP_GROUP_MEMBER_DEL | tr [a-z] [A-Z])
        if [ "$OCSP_GROUP_MEMBER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ocsp-group-member-del tests
                subsystemId=$OCSP_INST
                subsystemType=ocsp
                caId=$CA_INST
                run_pki-ocsp-group-cli-ocsp-group-member-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	######## PKI TKS GROUP TESTS ############
        PKI_TKS_GROUP_TEST_UPPERCASE=$(echo $PKI_TKS_GROUP_TEST | tr [a-z] [A-Z])
        if [ "$PKI_TKS_GROUP_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki tks-group tests
                subsystemId=$TKS_INST
                caId=$CA_INST
                subsystemType=tks
                run_pki-tks-group-cli-tks-group-add_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-tks-group-cli-tks-group-mod_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-tks-group-cli-tks-group-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-tks-group-cli-tks-group-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-tks-group-cli-tks-group-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-tks-group-cli-tks-group-member-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-tks-group-cli-tks-group-member-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-tks-group-cli-tks-group-member-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-tks-group-cli-tks-group-member-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_GROUP_ADD_UPPERCASE=$(echo $TKS_GROUP_ADD | tr [a-z] [A-Z])
        if [ "$TKS_GROUP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-group-add tests
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                run_pki-tks-group-cli-tks-group-add_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        TKS_GROUP_MOD_UPPERCASE=$(echo $TKS_GROUP_MOD | tr [a-z] [A-Z])
        if [ "$TKS_GROUP_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-group-mod tests
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                run_pki-tks-group-cli-tks-group-mod_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        TKS_GROUP_FIND_UPPERCASE=$(echo $TKS_GROUP_FIND | tr [a-z] [A-Z])
        if [ "$TKS_GROUP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-group-find tests
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                run_pki-tks-group-cli-tks-group-find_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        TKS_GROUP_SHOW_UPPERCASE=$(echo $TKS_GROUP_SHOW | tr [a-z] [A-Z])
        if [ "$TKS_GROUP_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-group-show tests
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                run_pki-tks-group-cli-tks-group-show_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        TKS_GROUP_DEL_UPPERCASE=$(echo $TKS_GROUP_DEL | tr [a-z] [A-Z])
        if [ "$TKS_GROUP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-group-del tests
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                run_pki-tks-group-cli-tks-group-del_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        TKS_GROUP_MEMBER_ADD_UPPERCASE=$(echo $TKS_GROUP_MEMBER_ADD | tr [a-z] [A-Z])
        if [ "$TKS_GROUP_MEMBER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-group-member-add tests
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                run_pki-tks-group-cli-tks-group-member-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_GROUP_MEMBER_SHOW_UPPERCASE=$(echo $TKS_GROUP_MEMBER_SHOW | tr [a-z] [A-Z])
        if [ "$TKS_GROUP_MEMBER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-group-member-show tests
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                run_pki-tks-group-cli-tks-group-member-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_GROUP_MEMBER_FIND_UPPERCASE=$(echo $TKS_GROUP_MEMBER_FIND | tr [a-z] [A-Z])
        if [ "$TKS_GROUP_MEMBER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-group-member-find tests
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                run_pki-tks-group-cli-tks-group-member-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TKS_GROUP_MEMBER_DEL_UPPERCASE=$(echo $TKS_GROUP_MEMBER_DEL | tr [a-z] [A-Z])
        if [ "$TKS_GROUP_MEMBER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tks-group-member-del tests
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                run_pki-tks-group-cli-tks-group-member-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        ######## PKI GROUP TKS TESTS ############
        PKI_GROUP_TKS_TEST_UPPERCASE=$(echo $PKI_GROUP_TKS_TEST | tr [a-z] [A-Z])
        if [ "$PKI_GROUP_TKS_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki group tests for tks
                subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                run_pki-group-cli-group-add-tks_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-group-cli-group-show-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-find-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-mod-tks_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-group-cli-group-del-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-add-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-find-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-show-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-del-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_ADD_TKS_UPPERCASE=$(echo $GROUP_ADD_TKS | tr [a-z] [A-Z])
        if [ "$GROUP_ADD_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-add-tks tests
                  subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                  run_pki-group-cli-group-add-tks_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        GROUP_SHOW_TKS_UPPERCASE=$(echo $GROUP_SHOW_TKS | tr [a-z] [A-Z])
        if [ "$GROUP_SHOW_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-show-tks tests
                  subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                  run_pki-group-cli-group-show-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_FIND_TKS_UPPERCASE=$(echo $GROUP_FIND_TKS | tr [a-z] [A-Z])
        if [ "$GROUP_FIND_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-find-tks tests
                  subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                  run_pki-group-cli-group-find-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MOD_TKS_UPPERCASE=$(echo $GROUP_MOD_TKS | tr [a-z] [A-Z])
        if [ "$GROUP_MOD_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-mod-tks tests
                  subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                  run_pki-group-cli-group-mod-tks_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        GROUP_DEL_TKS_UPPERCASE=$(echo $GROUP_DEL_TKS | tr [a-z] [A-Z])
        if [ "$GROUP_DEL_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-del-tks tests
                  subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                  run_pki-group-cli-group-del-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_ADD_TKS_UPPERCASE=$(echo $GROUP_MEMBER_ADD_TKS | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_ADD_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-add-tks tests
                  subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                  run_pki-group-cli-group-member-add-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_FIND_TKS_UPPERCASE=$(echo $GROUP_MEMBER_FIND_TKS | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_FIND_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-find-tks tests
                  subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                  run_pki-group-cli-group-member-find-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_DEL_TKS_UPPERCASE=$(echo $GROUP_MEMBER_DEL_TKS | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_DEL_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-del-tks tests
                  subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                  run_pki-group-cli-group-member-del-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_SHOW_TKS_UPPERCASE=$(echo $GROUP_MEMBER_SHOW_TKS | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_SHOW_TKS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-show-tks tests
                  subsystemId=$TKS_INST
                subsystemType=tks
                caId=$CA_INST
                  run_pki-group-cli-group-member-show-tks_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        ######## PKI TPS GROUP TESTS ############
        PKI_TPS_GROUP_TEST_UPPERCASE=$(echo $PKI_TPS_GROUP_TEST | tr [a-z] [A-Z])
        if [ "$PKI_TPS_GROUP_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki tps-group tests
                subsystemId=$TPS_INST
                caId=$CA_INST
                subsystemType=tps
                run_pki-tps-group-cli-tps-group-add_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-tps-group-cli-tps-group-mod_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-tps-group-cli-tps-group-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-tps-group-cli-tps-group-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-tps-group-cli-tps-group-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-tps-group-cli-tps-group-member-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-tps-group-cli-tps-group-member-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-tps-group-cli-tps-group-member-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-tps-group-cli-tps-group-member-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_GROUP_ADD_UPPERCASE=$(echo $TPS_GROUP_ADD | tr [a-z] [A-Z])
        if [ "$TPS_GROUP_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-group-add tests
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                run_pki-tps-group-cli-tps-group-add_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        TPS_GROUP_MOD_UPPERCASE=$(echo $TPS_GROUP_MOD | tr [a-z] [A-Z])
        if [ "$TPS_GROUP_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-group-mod tests
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                run_pki-tps-group-cli-tps-group-mod_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        TPS_GROUP_FIND_UPPERCASE=$(echo $TPS_GROUP_FIND | tr [a-z] [A-Z])
        if [ "$TPS_GROUP_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-group-find tests
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                run_pki-tps-group-cli-tps-group-find_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        TPS_GROUP_SHOW_UPPERCASE=$(echo $TPS_GROUP_SHOW | tr [a-z] [A-Z])
        if [ "$TPS_GROUP_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-group-show tests
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                run_pki-tps-group-cli-tps-group-show_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        TPS_GROUP_DEL_UPPERCASE=$(echo $TPS_GROUP_DEL | tr [a-z] [A-Z])
        if [ "$TPS_GROUP_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-group-del tests
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                run_pki-tps-group-cli-tps-group-del_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        TPS_GROUP_MEMBER_ADD_UPPERCASE=$(echo $TPS_GROUP_MEMBER_ADD | tr [a-z] [A-Z])
        if [ "$TPS_GROUP_MEMBER_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-group-member-add tests
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                run_pki-tps-group-cli-tps-group-member-add_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_GROUP_MEMBER_SHOW_UPPERCASE=$(echo $TPS_GROUP_MEMBER_SHOW | tr [a-z] [A-Z])
        if [ "$TPS_GROUP_MEMBER_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-group-member-show tests
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                run_pki-tps-group-cli-tps-group-member-show_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_GROUP_MEMBER_FIND_UPPERCASE=$(echo $TPS_GROUP_MEMBER_FIND | tr [a-z] [A-Z])
        if [ "$TPS_GROUP_MEMBER_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-group-member-find tests
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                run_pki-tps-group-cli-tps-group-member-find_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        TPS_GROUP_MEMBER_DEL_UPPERCASE=$(echo $TPS_GROUP_MEMBER_DEL | tr [a-z] [A-Z])
        if [ "$TPS_GROUP_MEMBER_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki tps-group-member-del tests
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                run_pki-tps-group-cli-tps-group-member-del_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        ######## PKI GROUP TPS TESTS ############
        PKI_GROUP_TPS_TEST_UPPERCASE=$(echo $PKI_GROUP_TPS_TEST | tr [a-z] [A-Z])
        if [ "$PKI_GROUP_TPS_TEST_UPPERCASE" = "TRUE" ] ; then
                #Execute pki group tests for tps
                subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                run_pki-group-cli-group-add-tps_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-group-cli-group-show-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-find-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-mod-tps_tests  $subsystemId $subsystemType $MYROLE $caId
                run_pki-group-cli-group-del-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-add-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-find-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-show-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
                run_pki-group-cli-group-member-del-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_ADD_TPS_UPPERCASE=$(echo $GROUP_ADD_TPS | tr [a-z] [A-Z])
        if [ "$GROUP_ADD_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-add-tps tests
                  subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                  run_pki-group-cli-group-add-tps_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        GROUP_SHOW_TPS_UPPERCASE=$(echo $GROUP_SHOW_TPS | tr [a-z] [A-Z])
        if [ "$GROUP_SHOW_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-show-tps tests
                  subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                  run_pki-group-cli-group-show-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_FIND_TPS_UPPERCASE=$(echo $GROUP_FIND_TPS | tr [a-z] [A-Z])
        if [ "$GROUP_FIND_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-find-tps tests
                  subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                  run_pki-group-cli-group-find-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MOD_TPS_UPPERCASE=$(echo $GROUP_MOD_TPS | tr [a-z] [A-Z])
        if [ "$GROUP_MOD_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-mod-tps tests
                  subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                  run_pki-group-cli-group-mod-tps_tests  $subsystemId $subsystemType $MYROLE $caId
        fi
        GROUP_DEL_TPS_UPPERCASE=$(echo $GROUP_DEL_TPS | tr [a-z] [A-Z])
        if [ "$GROUP_DEL_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-del-tps tests
                  subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                  run_pki-group-cli-group-del-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_ADD_TPS_UPPERCASE=$(echo $GROUP_MEMBER_ADD_TPS | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_ADD_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-add-tps tests
                  subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                  run_pki-group-cli-group-member-add-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_FIND_TPS_UPPERCASE=$(echo $GROUP_MEMBER_FIND_TPS | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_FIND_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-find-tps tests
                  subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                  run_pki-group-cli-group-member-find-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_DEL_TPS_UPPERCASE=$(echo $GROUP_MEMBER_DEL_TPS | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_DEL_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-del-tps tests
                  subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                  run_pki-group-cli-group-member-del-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
        GROUP_MEMBER_SHOW_TPS_UPPERCASE=$(echo $GROUP_MEMBER_SHOW_TPS | tr [a-z] [A-Z])
        if [ "$GROUP_MEMBER_SHOW_TPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki group-member-show-tps tests
                  subsystemId=$TPS_INST
                subsystemType=tps
                caId=$CA_INST
                  run_pki-group-cli-group-member-show-tps_tests  $subsystemId $subsystemType $MYROLE $caId $MASTER
        fi
	 ##CA Profile Tests
        CA_PROFILE_CONFIG_UPPERCASE=$(echo $CA_PROFILE_CONFIG | tr [a-z] [A-Z])
        if [ "$CA_PROFILE_CONFIG_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ca-profile config tests
                run_pki-ca-profile_tests
        fi
        CA_PROFILE_SHOW_UPPERCASE=$(echo $CA_PROFILE_SHOW | tr [a-z] [A-Z])
        if [ "$CA_PROFILE_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ca-profile-show tests
                subsystemType=ca
                run_pki-ca-profile-show_tests $subsystemType $MYROLE
        fi
        CA_PROFILE_ENABLE_UPPERCASE=$(echo $CA_PROFILE_ENABLE | tr [a-z] [A-Z])
        if [ "$CA_PROFILE_ENABLE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ca-profile-enable tests
                subsystemType=ca
                run_pki-ca-profile-enable_tests $subsystemType $MYROLE
        fi
        CA_PROFILE_DISABLE_UPPERCASE=$(echo $CA_PROFILE_DISABLE | tr [a-z] [A-Z])
        if [ "$CA_PROFILE_DISABLE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ca-profile-disable tests
                subsystemType=ca
                run_pki-ca-profile-disable_tests $subsystemType $MYROLE
        fi
        CA_PROFILE_DEL_UPPERCASE=$(echo $CA_PROFILE_DEL | tr [a-z] [A-Z])
        if [ "$CA_PROFILE_DEL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ca-profile-del tests
                subsystemType=ca
                run_pki-ca-profile-del_tests $subsystemType $MYROLE
        fi
        CA_PROFILE_FIND_UPPERCASE=$(echo $CA_PROFILE_FIND | tr [a-z] [A-Z])
        if [ "$CA_PROFILE_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ca-profile-find tests
                subsystemType=ca
                run_pki-ca-profile-find_tests $subsystemType $MYROLE
        fi
        CA_PROFILE_ADD_UPPERCASE=$(echo $CA_PROFILE_ADD | tr [a-z] [A-Z])
        if [ "$CA_PROFILE_ADD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ca-profile-add tests
                subsystemType=ca
                run_pki-ca-profile-add_tests $subsystemType $MYROLE
        fi
        CA_PROFILE_MOD_UPPERCASE=$(echo $CA_PROFILE_MOD | tr [a-z] [A-Z])
        if [ "$CA_PROFILE_MOD_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ca-profile-mod tests
                subsystemType=ca
                run_pki-ca-profile-mod_tests $subsystemType $MYROLE
        fi
	############## CA PROFILE CLI TESTS #############
	CA_PROFILE_TEST_UPPERCASE=$(echo $CA_PROFILE_TEST | tr [a-z] [A-Z])
	if [ "$CA_PROFILE_TEST_UPPERCASE" = "TRUE" ]; then
		#execute CA PROFILE CLI tests
		subsystemType=ca
		run_pki-ca-profile_tests
		run_pki-ca-profile-show_tests $subsystemType $MYROLE
		run_pki-ca-profile-enable_tests $subsystemType $MYROLE
		run_pki-ca-profile-disable_tests $subsystemType $MYROLE
		run_pki-ca-profile-del_tests $subsystemType $MYROLE
		run_pki-ca-profile-find_tests $subsystemType $MYROLE
		run_pki-ca-profile-add_tests $subsystemType $MYROLE
		run_pki-ca-profile-mod_tests $subsystemType $MYROLE
	fi	
	######## PKI USER TESTS ############
	USER_CLEANUP_CA_UPPERCASE=$(echo $USER_CLEANUP_CA | tr [a-z] [A-Z])
        #Clean up role users (admin agent etc) created in CA
        if [ "$USER_CLEANUP_CA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki user-cleanup-ca tests
		CA_INST=$(cat /tmp/topo_file | grep MY_CA | cut -d= -f2)
                rlLog "Subsystem ID CA=$CA_INST"
                run_pki-user-cli-user-cleanup_tests $CA_INST ca $MY_ROLE
	fi
	######## LEGACY TESTS ############
	PKI_LEGACY_CA_ADMIN_TESTS_UPPERCASE=$(echo $PKI_LEGACY_CA_ADMIN_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_CA_ADMIN_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		#Excute all CA Admin tests
		subsystemType=ca
		run_pki-legacy-ca-usergroup_tests $subsystemType $MYROLE
		run_admin-ca-profile_tests $subsystemType $MYROLE
		run_admin-ca-acl_tests $subsystemType $MYROLE
		run_admin-ca-intdb_tests $subsystemType $MYROLE
		run_admin-ca-authplugin_tests $subsystemType $MYROLE
		run_admin-ca-crlissuingpoints_tests $subsystemType $MYROLE
		run_admin-ca-publishing_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_CA_EE_TESTS_UPPERCASE=$(echo $PKI_LEGACY_CA_EE_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_CA_EE_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		#Execute all CA EE Tests
		subsystemType=ca
		run_ee-ca-enrollment_tests $subsystemType $MYROLE
		run_ee-ca-retrieval_tests $subsystemType $MYROLE
		run_ca-ee-ocsp_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_CA_AG_TESTS_UPPERCASE=$(echo $PKI_LEGACY_CA_AG_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_CA_AG_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
		#Execute all CA Agent tests
		subsystemType=ca
	 	run_ca-ag-requests_tests $subsystemType $MYROLE
		run_agent-ca-crls_tests $subsystemType $MYROLE	
		run_ca-ag-certificates_tests $subsystemType $MYROLE
		run_pki-legacy-ca-scep_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_KRA_ADMIN_TESTS_UPPERCASE=$(echo $PKI_LEGACY_KRA_ADMIN_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_KRA_ADMIN_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" == "TRUE" ]; then
		#Execute all KRA Admin tests
		subsystemType=kra
		run_kra-ad_usergroups $subsystemType $MYROLE
		run_admin-kra-acl_tests $subsystemType $MYROLE
		run_admin-kra-internaldb_tests $subsystemType $MYROLE
		run_admin-kra-log_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_KRA_AGENT_TESTS_UPPERCASE=$(echo $PKI_LEGACY_KRA_AGENT_TESTS | tr [a-z] [A-Z])
	if [ "PKI_LEGACY_KRA_AGENT_TESTS" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		#Execute all KRA Agent tests
		subsystemType=kra
		run_kra-ag_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_OCSP_ADMIN_TESTS_UPPERCASE=$(echo $PKI_LEGACY_OCSP_ADMIN_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_OCSP_ADMIN_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		#Execute all OCSP Admin tests
		subsystemType=ocsp
		run_ocsp-ad_usergroups $subsystemType $MYROLE
		run_admin-ocsp-acl_tests $subsystemType $MYROLE
		run_admin-ocsp-log_tests $subsystemType $MYROLE
		run_admin-ocsp-internaldb_tests $subsystemType $MYROLE	
	fi
	PKI_LEGACY_OCSP_AGENT_TESTS_UPPERCASE=$(echo $PKI_LEGACY_OCSP_AGENT_TESTS_UPPERCASE | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_OCSP_AGENT_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		#Execute all OCSP Agent tests
		subsystemType=ocsp
		run_ocsp-ag_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_TKS_ADMIN_TESTS_UPPERCASE=$(echo $PKI_LEGACY_TKS_ADMIN_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_TKS_ADMIN_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		#Execute all TKS Admin tests
		subsystemType=tks
		run_tks-ad_usergroups $subsystemType $MYROLE
		run_admin-tks-acl_tests $subsystemType $MYROLE
		run_admin-tks-log_tests $subsystemType $MYROLE
		run_admin-tks-internaldb_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_SUBCA_ADMIN_TESTS_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_ADMIN_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_SUBCA_ADMIN_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		# Execute all SUBCA Admin tests
		subsystemType=ca
		run_pki-legacy-subca-usergroup_tests $subsystemType $MYROLE
		run_admin-subca-acl_tests $subsystemType $MYROLE
		run_admin-subca-intdb_tests $subsystemType $MYROLE
		run_admin-subca-authplugin_tests $subsystemType $MYROLE
		run_admin-subca-crlissuingpoints_tests $subsystemType $MYROLE
		run_admin-subca-publishing_tests $subsystemType $MYROLE
		run_admin-subca-profile_tests $subsystemType $MYROLE
		run_admin-subca-log_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_SUBCA_AGENT_TESTS_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_AGENT_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_SUBCA_AGENT_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		#Execute all SUBCA Agent tests
		subsystemType=ca
		run_agent-subca-crls_tests $subsystemType $MYROLE
		run_subca-ag-certificates_tests $subsystemType $MYROLE
		run_subca-ag-requests_tests $subsystemType $MYROLE
		run_agent-subca-profile_tests $subsystemType $MYROLE
		run_pki-legacy-subca-scep_tests $subsystemType $MYROLE		
		
	fi
	PKI_LEGACY_SUBCA_EE_TESTS_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_EE_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_SUBCA_EE_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ca
		run_ee-subca-enrollment_tests $subsystemType $MYROLE
		run_ee-subca-retrieval_tests $subsystemType $MYROLE
	fi
        PKI_LEGACY_CA_USERGROUP_UPPERCASE=$(echo $PKI_LEGACY_CA_USERGROUP | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_CA_USERGROUP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki ca-usergroup-tests  tests
                  subsystemType=ca
                  run_pki-legacy-ca-usergroup_tests $subsystemType $MYROLE
        fi
	PKI_LEGACY_CA_ADMIN_PROFILE_UPPERCASE=$(echo $PKI_LEGACY_CA_ADMIN_PROFILE | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_CA_ADMIN_PROFILE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ca
		run_admin-ca-profile_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_CA_AGENT_PROFILE_UPPERCASE=$(echo $PKI_LEGACY_CA_AGENT_PROFILE | tr [a-z] [A-Z]) 
	if [ "$PKI_LEGACY_CA_AGENT_PROFILE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ca
		run_agent-ca-profile_tests $subsystemType $MYROLE 
	fi
	PKI_LEGACY_CA_ACLS_UPPERCASE=$(echo $PKI_LEGACY_CA_ACLS | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_CA_ACLS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_admin-ca-acl_tests $subsystemType $MYROLE
        fi
	PKI_LEGACY_CA_INTERNALDB_UPPERCASE=$(echo $PKI_LEGACY_CA_INTERNALDB | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_CA_INTERNALDB_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_admin-ca-intdb_tests $subsystemType $MYROLE
        fi
	PKI_LEGACY_CA_AUTHPLUGIN_UPPERCASE=$(echo $PKI_LEGACY_CA_AUTHPLUGIN | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_CA_AUTHPLUGIN_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_admin-ca-authplugin_tests $subsystemType $MYROLE
        fi
	PKI_LEGACY_CA_ADMIN_LOGS_UPPERCASE=$(echo $PKI_LEGACY_CA_ADMIN_LOGS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_CA_ADMIN_LOGS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ca
		run_admin-ca-log_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_CA_EE_ENROLLMENT_UPPERCASE=$(echo $PKI_LEGACY_CA_EE_ENROLLMENT | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_CA_EE_ENROLLMENT_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then 
		subsystemType=ca
		run_ee-ca-enrollment_tests $subsystemType $MYROLE
	fi	
	PKI_LEGACY_CA_AG_REQUESTS_UPPERCASE=$(echo $PKI_LEGACY_CA_AG_REQUESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_CA_AG_REQUESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ca
		run_ca-ag-requests_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_CA_EE_RETRIEVAL_UPPERCASE=$(echo $PKI_LEGACY_CA_EE_RETRIEVAL | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_CA_EE_RETRIEVAL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ca
		run_ee-ca-retrieval_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_CA_CRLISSUINGPOINT_UPPERCASE=$(echo $PKI_LEGACY_CA_CRLISSUINGPOINT | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_CA_CRLISSUINGPOINT_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_admin-ca-crlissuingpoints_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_CA_AGENT_CRL_UPPERCASE=$(echo $PKI_LEGACY_CA_AGENT_CRL | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_CA_AGENT_CRL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_agent-ca-crls_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_CA_ADMIN_PUBLISHING_UPPERCASE=$(echo $PKI_LEGACY_CA_ADMIN_PUBLISHING | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_CA_ADMIN_PUBLISHING_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_admin-ca-publishing_tests $subsystemType $MYROLE
        fi
	PKI_LEGACY_CA_AG_CERTIFICATES_UPPERCASE=$(echo $PKI_LEGACY_CA_AG_CERTIFICATES | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_CA_AG_CERTIFICATES_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ca
		run_ca-ag-certificates_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_CA_ADMIN_EE_OCSP_UPPERCASE=$(echo $PKI_LEGACY_CA_ADMIN_EE_OCSP | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_CA_ADMIN_EE_OCSP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_ca-ee-ocsp_tests $subsystemType $MYROLE
        fi
	PKI_LEGACY_CA_RENEW_MANUAL_UPPERCASE=$(echo $PKI_LEGACY_CA_RENEW_MANUAL | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_CA_RENEW_MANUAL_UPPERCASE" = "TRUE" ] || [ "TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ca-renew-manual tests
                subsystemType=ca
                run_pki-legacy-ca-renew_manual_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_CA_RENEW_DIRECTORY_AUTH_USERCERT_UPPERCASE=$(echo $PKI_LEGACY_CA_RENEW_DIRECTORY_AUTH_USERCERT | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_CA_RENEW_DIRECTORY_AUTH_USERCERT_UPPERCASE" = "TRUE" ] || [ "TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ca-renew-directory-auth-usercert tests
                subsystemType=ca
                run_pki-legacy-ca-renew_dir_auth_user_cert_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_CA_RENEW_SSLCLIENTAUTH_CERT_UPPERCASE=$(echo $PKI_LEGACY_CA_RENEW_SSLCLIENTAUTH_CERT | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_CA_RENEW_SSLCLIENTAUTH_CERT_UPPERCASE" = "TRUE" ] || [ "TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ca-renew-sslclient-cert tests
                subsystemType=ca
                run_pki-legacy-ca-renew_self_ca_user_ssl_client_cert_tests $subsystemType $MYROLE
        fi
	PKI_LEGACY_CA_SCEP_ENROLL_UPPERCASE=$(echo $PKI_LEGACY_CA_SCEP_ENROLL | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_CA_SCEP_ENROLL_UPPERCASE" = "TRUE" ] || [ "TEST_ALL_UPPERCASE" = "TRUE" ]; then
		# Execute ca scep enroll tests
		subsystemType=ca
		run_pki-legacy-ca-scep_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_KRA_AG_UPPERCASE=$(echo $PKI_LEGACY_KRA_AG_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_KRA_AG_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=kra
		run_kra-ag_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_KRA_AD_USERGROUPS_UPPERCASE=$(echo $PKI_LEGACY_KRA_AD_USERGROUPS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_KRA_AD_USERGROUPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=kra
		run_kra-ad_usergroups $subsystemType $MYROLE
	fi
	PKI_LEGACY_KRA_AD_ACLS_UPPERCASE=$(echo $PKI_LEGACY_KRA_AD_ACLS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_KRA_AD_ACLS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=kra
		run_admin-kra-acl_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_KRA_AD_INTERNALDB_UPPERCASE=$(echo $PKI_LEGACY_KRA_AD_INTERNALDB | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_KRA_AD_INTERNALDB_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=kra
		run_admin-kra-internaldb_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_KRA_AD_LOGS_UPPERCASE=$(echo $PKI_LEGACY_KRA_AD_LOGS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_KRA_AD_LOGS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then 
		subsystemType=kra
		run_admin-kra-log_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_SUBCA_USERGROUP_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_USERGROUP | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_SUBCA_USERGROUP_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
                # Execute pki subca-usergroup-tests  tests
                subsystemType=ca
                run_pki-legacy-subca-usergroup_tests $subsystemType $MYROLE
        fi
	PKI_LEGACY_SUBCA_ADMIN_ACLS_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_ADMIN_ACLS | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_SUBCA_ADMIN_ACLS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_admin-subca-acl_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_SUBCA_ADMIN_INTERNALDB_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_ADMIN_INTERNALDB | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_SUBCA_ADMIN_INTERNALDB_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_admin-subca-intdb_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_SUBCA_ADMIN_AUTHPLUGIN_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_ADMIN_AUTHPLUGIN | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_SUBCA_ADMIN_AUTHPLUGIN_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_admin-subca-authplugin_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_SUBCA_ADMIN_CRLISSUINGPOINT_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_ADMIN_CRLISSUINGPOINT | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_SUBCA_ADMIN_CRLISSUINGPOINT_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_admin-subca-crlissuingpoints_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_SUBCA_ADMIN_PUBLISHING_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_ADMIN_PUBLISHING | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_SUBCA_ADMIN_PUBLISHING_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_admin-subca-publishing_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_SUBCA_AGENT_CRL_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_AGENT_CRL | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_SUBCA_AGENT_CRL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_agent-subca-crls_tests $subsystemType $MYROLE
        fi
	PKI_LEGACY_SUBCA_AG_CERTIFICATES_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_AG_CERTIFICATES | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_SUBCA_AG_CERTIFICATES_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_subca-ag-certificates_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_SUBCA_AG_REQUESTS_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_AG_REQUESTS | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_SUBCA_AG_REQUESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_subca-ag-requests_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_SUBCA_EE_ENROLLMENT_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_EE_ENROLLMENT | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_SUBCA_EE_ENROLLMENT_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_ee-subca-enrollment_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_SUBCA_EE_RETRIEVAL_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_EE_RETRIEVAL | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_SUBCA_EE_RETRIEVAL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_ee-subca-retrieval_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_SUBCA_ADMIN_PROFILE_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_ADMIN_PROFILE | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_SUBCA_ADMIN_PROFILE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_admin-subca-profile_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_SUBCA_AGENT_PROFILE_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_AGENT_PROFILE | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_SUBCA_AGENT_PROFILE_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=ca
                run_agent-subca-profile_tests $subsystemType $MYROLE
        fi
	PKI_LEGACY_SUBCA_ADMIN_LOGS_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_ADMIN_LOGS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_SUBCA_ADMIN_LOGS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ca
		run_admin-subca-log_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_SUBCA_SCEP_ENROLL_UPPERCASE=$(echo $PKI_LEGACY_SUBCA_SCEP_ENROLL | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_SUBCA_SCEP_ENROLL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		# Execute subca scep enroll tests
		subsystemType=ca
		run_pki-legacy-subca-scep_tests $subsystemType $MYROLE
	fi	
	PKI_LEGACY_OCSP_AD_USERGROUPS_UPPERCASE=$(echo $PKI_LEGACY_OCSP_AD_USERGROUPS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_OCSP_AD_USERGROUPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ocsp
		run_ocsp-ad_usergroups $subsystemType $MYROLE
	fi
	PKI_LEGACY_OCSP_AD_ACLS_UPPERCASE=$(echo $PKI_LEGACY_OCSP_AD_ACLS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_OCSP_AD_ACLS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ocsp
		run_admin-ocsp-acl_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_OCSP_AD_LOGS_UPPERCASE=$(echo $PKI_LEGACY_OCSP_AD_LOGS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_OCSP_AD_LOGS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ocsp
		run_admin-ocsp-log_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_OCSP_AD_INTERNALDB_UPPERCASE=$(echo $PKI_LEGACY_OCSP_AD_INTERNALDB | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_OCSP_AD_INTERNALDB_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ocsp
		run_admin-ocsp-internaldb_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_OCSP_AG_UPPERCASE=$(echo $PKI_LEGACY_OCSP_AG_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_OCSP_AG_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ocsp
		run_ocsp-ag_tests $subsystemType $MYROLE
	fi
        PKI_LEGACY_TKS_AD_USERGROUPS_UPPERCASE=$(echo $PKI_LEGACY_TKS_AD_USERGROUPS | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_TKS_AD_USERGROUPS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=tks
                run_tks-ad_usergroups $subsystemType $MYROLE
        fi
        PKI_LEGACY_TKS_AD_ACLS_UPPERCASE=$(echo $PKI_LEGACY_TKS_AD_ACLS | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_TKS_AD_ACLS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=tks
                run_admin-tks-acl_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_TKS_AD_LOGS_UPPERCASE=$(echo $PKI_LEGACY_TKS_AD_LOGS | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_TKS_AD_LOGS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=tks
                run_admin-tks-log_tests $subsystemType $MYROLE
        fi
        PKI_LEGACY_TKS_AD_INTERNALDB_UPPERCASE=$(echo $PKI_LEGACY_TKS_AD_INTERNALDB | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_TKS_AD_INTERNALDB_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=tks
                run_admin-tks-internaldb_tests $subsystemType $MYROLE
        fi
	PKI_LEGACY_TPS_ENROLLMENTS_UPPERCASE=$(echo $PKI_LEGACY_TPS_ENROLLMENTS | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_TPS_ENROLLMENTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=tps
                run_tps-enrollment_tests $subsystemType $MYROLE
        fi
	PKI_LEGACY_IPA_UPPERCASE=$(echo $PKI_LEGACY_IPA_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_IPA_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		subsystemType=ca
		run_ipa_backend_plugin $subsystemType $MYROLE
	fi
	PKI_LEGACY_CLONE_CA_TESTS_UPPERCASE=$(echo $PKI_LEGACY_CLONE_CA_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_CLONE_CA_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPERCASE" = "TRUE" ]; then
		subsystemType=ca
		clone_legacy_ca_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_CLONE_KRA_TESTS_UPPERCASE=$(echo $PKI_LEGACY_CLONE_KRA_TESTS | tr [a-z] [A-Z])
	if [ "$PKI_LEGACY_CLONE_KRA_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPERCASE" = "TRUE" ]; then
		subsystemType=kra
		clone_legacy_drm_tests $subsystemType $MYROLE
	fi
	PKI_LEGACY_TPS_ENROLLMENTS_UPPERCASE=$(echo $PKI_LEGACY_TPS_ENROLLMENTS | tr [a-z] [A-Z])
        if [ "$PKI_LEGACY_TPS_ENROLLMENTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                subsystemType=tps
                run_tps-enrollment_tests $subsystemType $MYROLE
        fi
	######## INSTALL TESTS ############
        PKI_INSTALL_TESTS_UPPERCASE=$(echo $PKI_INSTALL_TESTS | tr [a-z] [A-Z])
        if [ "$PKI_INSTALL_TESTS_UPPERCASE" = "TRUE" ] ; then
                # Execute pki install tests
                  subsystemId=$CA_INST
                  subsystemType=ca
                # Execute pki KRA install tests
                  run_rhcs_ca_installer_tests $subsystemId $subsystemType $MYROLE
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  run_rhcs_kra_installer_tests $subsystemId $subsystemType $MYROLE
                # Execute pki OCSP install tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  run_rhcs_ocsp_installer_tests $subsystemId $subsystemType $MYROLE
                # Execute pki TKS install tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  run_rhcs_tks_installer_tests $subsystemId $subsystemType $MYROLE
                # Execute pki TPS install tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  run_rhcs_tps_installer_tests $subsystemId $subsystemType $MYROLE
        fi

        PKI_CA_INSTALL_UPPERCASE=$(echo $PKI_CA_INSTALL | tr [a-z] [A-Z])
        if [ "$PKI_CA_INSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki CA install tests
                  subsystemId=$CA_INST
                  subsystemType=ca
                  run_rhcs_ca_installer_tests $subsystemId $subsystemType $MYROLE
        fi

        PKI_KRA_INSTALL_UPPERCASE=$(echo $PKI_KRA_INSTALL | tr [a-z] [A-Z])
        if [ "$PKI_KRA_INSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki KRA install tests
                  subsystemId=$KRA_INST
                  subsystemType=kra
                  run_rhcs_kra_installer_tests
        fi

        PKI_OCSP_INSTALL_UPPERCASE=$(echo $PKI_OCSP_INSTALL | tr [a-z] [A-Z])
        if [ "$PKI_OCSP_INSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki OCSP install tests
                  subsystemId=$OCSP_INST
                  subsystemType=ocsp
                  run_rhcs_ocsp_installer_tests
        fi

        PKI_TKS_INSTALL_UPPERCASE=$(echo $PKI_TKS_INSTALL | tr [a-z] [A-Z])
        if [ "$PKI_TKS_INSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki TKS install tests
                  subsystemId=$TKS_INST
                  subsystemType=tks
                  run_rhcs_tks_installer_tests $subsystemId $subsystemType $MYROLE
        fi
        PKI_TPS_INSTALL_UPPERCASE=$(echo $PKI_TPS_INSTALL | tr [a-z] [A-Z])
        if [ "$PKI_TPS_INSTALL_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki TPS install tests
                  subsystemId=$TPS_INST
                  subsystemType=tps
                  run_rhcs_tps_installer_tests $subsystemId $subsystemType $MYROLE
        fi
	PKI_CA_SELFTEST_CONFIG_UPPERCASE=$(echo $PKI_CA_SELFTEST_CONFIG | tr [a-z] [A-Z])
	if [ "$PKI_CA_SELFTEST_CONFIG_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		# Execute pki ca-selftest --help
		  run_pki-ca-selftest_tests
	fi		
	PKI_CA_SELFTEST_FIND_UPPERCASE=$(echo $PKI_CA_SELFTEST_FIND | tr [a-z] [A-Z])
	if [ "$PKI_CA_SELFTEST_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		# Execute pki ca-selftest-find 
		 subsystemType=ca
	  	 run_pki-ca-selftest-find_tests $subsystemType $MYROLE
	fi
	PKI_CA_SELFTEST_RUN_UPPERCASE=$(echo $PKI_CA_SELFTEST_RUN | tr [a-z] [A-Z])
	if [ "$PKI_CA_SELFTEST_RUN_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		# Execute pki ca-selftest-run 
		 subsystemType=ca
	  	 run_pki-ca-selftest-run_tests $subsystemType $MYROLE
	fi
	PKI_CA_SELFTEST_SHOW_UPPERCASE=$(echo $PKI_CA_SELFTEST_SHOW | tr [a-z] [A-Z])
	if [ "$PKI_CA_SELFTEST_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		# Execute pki ca-selftest-show
		 subsystemType=ca
	  	 run_pki-ca-selftest-show_tests $subsystemType $MYROLE
	fi
	PKI_CA_SELFTEST_ADMIN_UPPERCASE=$(echo $PKI_CA_SELFTEST_ADMIN | tr [a-z] [A-Z])
        if [ "$PKI_CA_SELFTEST_ADMIN_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ca-selftest admin
                  subsystemType=ca
                  run_pki-ca-selftest-admin_tests $subsystemType $MYROLE
        fi
	PKI_KRA_SELFTEST_FIND_UPPERCASE=$(echo $PKI_KRA_SELFTEST_FIND | tr [a-z] [A-Z])
        if [ "$PKI_KRA_SELFTEST_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki kra-selftest-find
                 subsystemType=kra
                 run_pki-kra-selftest-find_tests $subsystemType $MYROLE
        fi
        PKI_KRA_SELFTEST_RUN_UPPERCASE=$(echo $PKI_KRA_SELFTEST_RUN | tr [a-z] [A-Z])
        if [ "$PKI_KRA_SELFTEST_RUN_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki kra-selftest-run
                 subsystemType=kra
                 run_pki-kra-selftest-run_tests $subsystemType $MYROLE
        fi
	PKI_KRA_SELFTEST_SHOW_UPPERCASE=$(echo $PKI_KRA_SELFTEST_SHOW | tr [a-z] [A-Z])
        if [ "$PKI_KRA_SELFTEST_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki kra-selftest-show
                 subsystemType=kra
                 run_pki-kra-selftest-show_tests $subsystemType $MYROLE
        fi
	PKI_KRA_SELFTEST_CONFIG_UPPERCASE=$(echo $PKI_KRA_SELFTEST_CONFIG | tr [a-z] [A-Z])
        if [ "$PKI_KRA_SELFTEST_CONFIG_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki kra-selftest --help
                  run_pki-kra-selftest_tests
        fi
	PKI_KRA_SELFTEST_ADMIN_UPPERCASE=$(echo $PKI_KRA_SELFTEST_ADMIN | tr [a-z] [A-Z])
        if [ "$PKI_KRA_SELFTEST_ADMIN_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki kra-selftest admin
		  subsystemType=kra
	  	  run_pki-kra-selftest-admin_tests $subsystemType $MYROLE
        fi
	PKI_OCSP_SELFTEST_FIND_UPPERCASE=$(echo $PKI_OCSP_SELFTEST_FIND | tr [a-z] [A-Z])
        if [ "$PKI_OCSP_SELFTEST_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ocsp-selftest-find
                 subsystemType=ocsp
                 run_pki-ocsp-selftest-find_tests $subsystemType $MYROLE
        fi
        PKI_OCSP_SELFTEST_RUN_UPPERCASE=$(echo $PKI_OCSP_SELFTEST_RUN | tr [a-z] [A-Z])
        if [ "$PKI_OCSP_SELFTEST_RUN_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ocsp-selftest-run
                 subsystemType=ocsp
                 run_pki-ocsp-selftest-run_tests $subsystemType $MYROLE
        fi
        PKI_OCSP_SELFTEST_SHOW_UPPERCASE=$(echo $PKI_OCSP_SELFTEST_SHOW | tr [a-z] [A-Z])
        if [ "$PKI_OCSP_SELFTEST_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ocsp-selftest-show
                 subsystemType=ocsp

                 run_pki-ocsp-selftest-show_tests $subsystemType $MYROLE
        fi
        PKI_OCSP_SELFTEST_CONFIG_UPPERCASE=$(echo $PKI_OCSP_SELFTEST_CONFIG | tr [a-z] [A-Z])
        if [ "$PKI_OCSP_SELFTEST_CONFIG_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki ocsp-selftest --help
                  run_pki-ocsp-selftest_tests
        fi
	PKI_TKS_SELFTEST_FIND_UPPERCASE=$(echo $PKI_TKS_SELFTEST_FIND | tr [a-z] [A-Z])
        if [ "$PKI_TKS_SELFTEST_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki tks-selftest-find
                 subsystemType=tks
                 run_pki-tks-selftest-find_tests $subsystemType $MYROLE
        fi
        PKI_TKS_SELFTEST_RUN_UPPERCASE=$(echo $PKI_TKS_SELFTEST_RUN | tr [a-z] [A-Z])
        if [ "$PKI_TKS_SELFTEST_RUN_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki tks-selftest-run
                 subsystemType=tks
                 run_pki-tks-selftest-run_tests $subsystemType $MYROLE
        fi
        PKI_TKS_SELFTEST_SHOW_UPPERCASE=$(echo $PKI_TKS_SELFTEST_SHOW | tr [a-z] [A-Z])
        if [ "$PKI_TKS_SELFTEST_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki tks-selftest-show
                 subsystemType=tks
                 run_pki-tks-selftest-show_tests $subsystemType $MYROLE
        fi
        PKI_TKS_SELFTEST_CONFIG_UPPERCASE=$(echo $PKI_TKS_SELFTEST_CONFIG | tr [a-z] [A-Z])
        if [ "$PKI_TKS_SELFTEST_CONFIG_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki tks-selftest --help
                  run_pki-tks-selftest_tests
        fi
	PKI_TPS_SELFTEST_FIND_UPPERCASE=$(echo $PKI_TPS_SELFTEST_FIND | tr [a-z] [A-Z])
        if [ "$PKI_TPS_SELFTEST_FIND_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki tps-selftest-find
                 subsystemType=tps
                 run_pki-tps-selftest-find_tests $subsystemType $MYROLE
        fi
        PKI_TPS_SELFTEST_RUN_UPPERCASE=$(echo $PKI_TPS_SELFTEST_RUN | tr [a-z] [A-Z])
        if [ "$PKI_TPS_SELFTEST_RUN_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki tps-selftest-run
                 subsystemType=tps
                 run_pki-tps-selftest-run_tests $subsystemType $MYROLE
        fi
        PKI_TPS_SELFTEST_SHOW_UPPERCASE=$(echo $PKI_TPS_SELFTEST_SHOW | tr [a-z] [A-Z])
        if [ "$PKI_TPS_SELFTEST_SHOW_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki tps-selftest-show
                 subsystemType=tps
                 run_pki-tps-selftest-show_tests $subsystemType $MYROLE
        fi
        PKI_TPS_SELFTEST_CONFIG_UPPERCASE=$(echo $PKI_TPS_SELFTEST_CONFIG | tr [a-z] [A-Z])
        if [ "$PKI_TPS_SELFTEST_CONFIG_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute pki tps-selftest --help
                  run_pki-tps-selftest_tests
        fi
	#############CA Selftests###################
	PKI_CA_SELFTESTS_UPPERCASE=$(echo $PKI_CA_SELFTESTS | tr [a-z] [A-Z])
	if [ "$PKI_CA_SELFTESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
		# Execute all ca selftest cli's
		subsystemType=ca
		run_pki-ca-selftest_tests
		run_pki-ca-selftest-find_tests $subsystemType $MYROLE
		run_pki-ca-selftest-run_tests $subsystemType $MYROLE
		run_pki-ca-selftest-show_tests $subsystemType $MYROLE
	fi
	#############KRA Selftests###################
	PKI_KRA_SELFTESTS_UPPERCASE=$(echo $PKI_KRA_SELFTESTS | tr [a-z] [A-Z])
        if [ "$PKI_KRA_SELFTESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute all kra selftest cli's
                subsystemType=kra
                run_pki-kra-selftest_tests
                run_pki-kra-selftest-find_tests $subsystemType $MYROLE
                run_pki-kra-selftest-run_tests $subsystemType $MYROLE
                run_pki-kra-selftest-show_tests $subsystemType $MYROLE
		run_pki-kra-selftest-admin_tests $subsystemType $MYROLE
        fi
	#############OCSP Selftests###################
	PKI_OCSP_SELFTESTS_UPPERCASE=$(echo $PKI_OCSP_SELFTESTS | tr [a-z] [A-Z])
        if [ "$PKI_OCSP_SELFTESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute all ocsp selftest cli's
                subsystemType=ocsp
                run_pki-ocsp-selftest_tests
                run_pki-ocsp-selftest-find_tests $subsystemType $MYROLE
                run_pki-ocsp-selftest-run_tests $subsystemType $MYROLE
                run_pki-ocsp-selftest-show_tests $subsystemType $MYROLE
        fi
	#############TKS Selftests###################
	PKI_TKS_SELFTESTS_UPPERCASE=$(echo $PKI_TKS_SELFTESTS | tr [a-z] [A-Z])
        if [ "$PKI_TKS_SELFTESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute all tks selftest cli's
                subsystemType=tks
                run_pki-tks-selftest_tests
                run_pki-tks-selftest-find_tests $subsystemType $MYROLE
                run_pki-tks-selftest-run_tests $subsystemType $MYROLE
                run_pki-tks-selftest-show_tests $subsystemType $MYROLE
        fi
	#############TPS Selftests###################
	PKI_TPS_SELFTESTS_UPPERCASE=$(echo $PKI_TPS_SELFTESTS | tr [a-z] [A-Z])
        if [ "$PKI_TPS_SELFTESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ]; then
                # Execute all tps selftest cli's
                subsystemType=tps
                run_pki-tps-selftest_tests
                run_pki-tps-selftest-find_tests $subsystemType $MYROLE
                run_pki-tps-selftest-run_tests $subsystemType $MYROLE
                run_pki-tps-selftest-show_tests $subsystemType $MYROLE
        fi
	rlPhaseEnd
	######## DEV UNIT TESTS ############
	DEV_JAVA_TESTS_UPPERCASE=$(echo $DEV_JAVA_TESTS | tr [a-z] [A-Z])
        if [ "$DEV_JAVA_TESTS_UPPERCASE" = "TRUE" ] || [ "$TEST_ALL_UPPERCASE" = "TRUE" ] ; then
        rlPhaseStartSetup "Dev Tests"
             run_dev_junit_tests
        rlPhaseEnd
        fi

	######## CODE COVERAGE TESTS ############
	CODE_COVERAGE_UPPERCASE=$(echo $CODE_COVERAGE | tr [a-z] [A-Z])
	if [ "$CODE_COVERAGE_UPPERCASE" = "TRUE" ] ; then
	        rlPhaseStartSetup "JACOCO Code coverage report"
        	        rlRun "cp /tmp/jacoco.exec /opt/rhqa_pki/."
                	rlLog "ant task to create a report"
	                rlRun "cd $dir2 && $cmd2"
                	rlLog "Jacoco coverage report stored locally on $HOSTNAME can be viewed at http://$HOSTNAME:8000/"
	                rlRun "screen -d -m sh -c 'cd $dir1 ; $cmd1'"
			#Archive the codecoverage results 
			if [ "$ARCHIVELOCATIONSERVER" != "" ] ; then
				rlLog "Archiving results to $ARCHIVELOCATIONSERVER"
				rlRun "backupCodeCoverageResults $dir1"
			fi
        	rlPhaseEnd
	fi
    rlJournalPrintText
    report=/tmp/rhts.report.$RANDOM.txt
    makereport $report
    rhts-submit-log -l $report
rlJournalEnd
