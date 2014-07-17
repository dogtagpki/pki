# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Makefile of /CoreOS/rhcs/PKI_TEST_USER_ID
#   Description: PKI Automation Tests
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

FILES=$(METADATA) runtest.sh Makefile PURPOSE shared acceptance dev_java_tests codecoverage

.PHONY: all install download clean

run: $(FILES) build
	rm -rf /opt/rhqa_pki
	mkdir /opt/rhqa_pki
	mkdir /opt/rhqa_pki/java
	rm -f /opt/rhqa_pki/env.sh
	cp ./shared/env.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/rhcs-shared.sh
	cp ./shared/rhcs-shared.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/rhcs-install-shared.sh
	cp ./shared/rhcs-install-shared.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/pki-user-cli-lib.sh
	cp ./shared/pki-user-cli-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/pki-cert-cli-lib.sh
	cp ./shared/pki-cert-cli-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/dummycert1.pem
	cp ./shared/dummycert1.pem /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/build.xml
	cp ./shared/build.xml /opt/rhqa_pki/.
	chmod a+x /opt/rhqa_pki/*.sh
	rm -f /opt/rhqa_pki/java/generateCRMFRequest.jar
	cp  ./shared/generateCRMFRequest.jar /opt/rhqa_pki/java/
	rm -f /opt/rhqa_pki/pki-auth-plugin-lib.sh
	cp ./shared/pki-auth-plugin-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/pki-config-lib.sh
	cp ./shared/pki-config-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/id_rsa-host-beaker_archive.pub
	cp  ./codecoverage/id_rsa-host-beaker_archive.pub /opt/rhqa_pki/id_rsa-host-beaker_archive.pub
	rm -f /opt/rhqa_pki/id_rsa-host-beaker_archive
	cp  ./codecoverage/id_rsa-host-beaker_archive /opt/rhqa_pki/id_rsa-host-beaker_archive
	rm -f /opt/rhqa_pki/known_hosts_archivehost
	cp  ./codecoverage/known_hosts_archivehost /opt/rhqa_pki/known_hosts_archivehost
	rm -f /opt/rhqa_pki/saving_codecoverage_results.sh
	cp  ./codecoverage/saving_codecoverage_results.sh /opt/rhqa_pki/saving_codecoverage_results.sh
	./runtest.sh

build: $(BUILT_FILES)
	#shared
	chmod a+x ./shared/rhcs-shared.sh
	chmod a+x ./shared/rhcs-install-shared.sh
	chmod a+x ./shared/pki-user-cli-lib.sh
	chmod a+x ./shared/dummycert1.pem
	chmod a+x ./shared/pki-cert-cli-lib.sh
	chmod a+x runtest.sh
	#quickinstall
	chmod a+x ./acceptance/quickinstall/rhcs-install.sh
	chmod a+x ./acceptance/quickinstall/rhcs-install-lib.sh
	chmod a+x ./acceptance/quickinstall/rhds-install.sh
	#user CA
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-add-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-show-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-mod-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-find-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-del-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-membership-add-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-membership-find-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-membership-del-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-find-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-add-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-show-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cert-delete-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/ca/pki-user-cli-user-cleanup-ca.sh
	#CA user
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-add.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-show.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-find.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-del.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-membership-add.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-membership-find.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-membership-del.sh
	#CA cert
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-cert.sh
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-cert-show.sh
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-cert-request-show.sh
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-bigInt.sh
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-cert-revoke.sh
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-cert-release-hold.sh
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-cert-hold.sh
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-submit-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-profile-find-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-profile-show-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-find-ca.sh
	#group CA
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-add-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-show-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-find-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-mod-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-del-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-member-add-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-member-find-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-member-del-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-member-show-ca.sh

clean:
	rm -f *~ $(BUILT_FILES)


include /usr/share/rhts/lib/rhts-make.include

$(METADATA): Makefile
	@echo "Owner:           Asha Akkiangady  <aakkiang@redhat.com>" > $(METADATA)
	@echo "Name:            $(TEST)" >> $(METADATA)
	@echo "TestVersion:     $(TESTVERSION)" >> $(METADATA)
	@echo "Path:            $(TEST_DIR)" >> $(METADATA)
	@echo "Description:     Package containing tests and libraries for rhcs beaker tests" >> $(METADATA)
	@echo "Type:            FUNCTIONAL" >> $(METADATA)
	@echo "TestTime:        360m" >> $(METADATA)
	@echo "RunFor:          rhcs" >> $(METADATA)
	@echo "Requires:        expect" >> $(METADATA)
	@echo "Priority:        Normal" >> $(METADATA)
	@echo "License:         GPLv2" >> $(METADATA)
	@echo "Confidential:    no" >> $(METADATA)
	@echo "Destructive:     no" >> $(METADATA)

	rhts-lint $(METADATA)
