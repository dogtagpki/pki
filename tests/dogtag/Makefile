# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Makefile of /CoreOS/rhcs/PKI_TEST_USER_ID
#   Description: Basic install test for rhcs
#   Author: Laxmi Sunkara <lsunkara@redhat.com>
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


export TEST=/CoreOS/dogtag/PKI_TEST_USER_ID
export TESTVERSION=1.0.8_RPM_IDENTIFIER

BUILT_FILE=

FILES=$(METADATA) runtest.sh Makefile PURPOSE shared acceptance dev_java_tests

.PHONY: all install download clean

run: $(FILES) build
	rm -rf /opt/rhqa_pki
	mkdir /opt/rhqa_pki
	rm -f /opt/rhqa_pki/env.sh
	cp ./shared/env.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/rhcs-shared.sh
	cp ./shared/rhcs-shared.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/rhcs-install-shared.sh
	cp ./shared/rhcs-install-shared.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/pki-user-cli-lib.sh
	cp ./shared/pki-user-cli-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/set-root-pw.exp
	cp ./shared/set-root-pw.exp /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/pki-cert-cli-lib.sh
	cp ./shared/pki-cert-cli-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/dummycert1.pem
	cp ./shared/dummycert1.pem /opt/rhqa_pki/.
	chmod 755 /opt/rhqa_pki/*.sh
	./runtest.sh

build: $(BUILT_FILES)
	#shared
	chmod 755 ./shared/rhcs-shared.sh
	chmod 755 ./shared/rhcs-install-shared.sh
	chmod 755 ./shared/set-root-pw.exp
	chmod 755 ./shared/pki-user-cli-lib.sh
	chmod 755 ./shared/dummycert1.pem
	chmod 755 ./shared/pki-cert-cli-lib.sh
	chmod a+x runtest.sh
	#quickinstall
	chmod a+x ./acceptance/quickinstall/rhcs-install.sh
	chmod a+x ./acceptance/quickinstall/rhcs-install-lib.sh
	chmod a+x ./acceptance/quickinstall/rhds-install.sh
	#CA
	chmod 777 ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-ca.sh
	chmod 777 ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-add-ca.sh
	chmod 777 ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-show-ca.sh
	chmod 777 ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-find-ca.sh
	chmod 777 ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-del-ca.sh


clean:
	rm -f *~ $(BUILT_FILES)


include /usr/share/rhts/lib/rhts-make.include

$(METADATA): Makefile
	@echo "Owner:           Asha Akkiangady  <aakkiang@redhat.com>" > $(METADATA)
	@echo "Name:            $(TEST)" >> $(METADATA)
	@echo "TestVersion:     $(TESTVERSION)" >> $(METADATA)
	@echo "Path:            $(TEST_DIR)" >> $(METADATA)
	@echo "Description:     Package containing libraries for rhcs beaker tests" >> $(METADATA)
	@echo "Type:            Acceptance" >> $(METADATA)
	@echo "TestTime:        180m" >> $(METADATA)
	@echo "RunFor:          rhcs" >> $(METADATA)
	@echo "Requires:        expect" >> $(METADATA)
	@echo "Priority:        Normal" >> $(METADATA)
	@echo "License:         GPLv2" >> $(METADATA)
	@echo "Confidential:    no" >> $(METADATA)
	@echo "Destructive:     no" >> $(METADATA)

	rhts-lint $(METADATA)
