#!/bin/bash
# vim: dict=/usr/share/beakerlib/dictionary.vim cpt=.,w,b,u,t,i,k
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   runtest.sh of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli/ca
#   Description: PKI USER CLI tests
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
# The following rhcs will be tested:
#
# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Author: Laxmi Sunkara <lsunkara@redhat.com>
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

# Include data-driven test data file:

# Include rhts environment
. /usr/bin/rhts-environment.sh
. /usr/share/beakerlib/beakerlib.sh
. /opt/rhqa_pki/rhcs-shared.sh
. /opt/rhqa_pki/env.sh

# Include test case file
. ./pki-user-cli-user-ca.sh
. ./pki-user-cli-user-add-ca.sh
. ./pki-user-cli-user-show-ca.sh
. ./pki-user-cli-user-find-ca.sh
. ./pki-user-cli-user-del-ca.sh


##############################################################################
PACKAGE="pki-tools"


rlJournalStart
	rlPhaseStartSetup "pki-user-cli-startup: Check for pki-tools package"
		rpm -qa | grep $PACKAGE
		if [ $? -eq 0 ] ; then
			rlPass "$PACKAGE package is installed"
		else
			rlFail "$PACKAGE package NOT found!"
		fi
	 rlPhaseEnd

	# Execute pki user ca config tests
	  run_pki-user-cli-user-ca_tests
	# Execute pki user-add-ca tests
	  run_pki-user-cli-user-add-ca_tests
	# Execute pki user-show-ca tests
          run_pki-user-cli-user-show-ca_tests
	# Execute pki user-find-ca tests
	  run_pki-user-cli-user-find-ca_tests
	# Execute pki user-del-ca tests
	  run_pki-user-cli-user-del-ca_tests
   rlJournalPrintText
   report=/tmp/rhts.report.$RANDOM.txt
   makereport $report
   rhts-submit-log -l $report
rlJournalEnd
