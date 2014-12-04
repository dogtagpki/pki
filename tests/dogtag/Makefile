# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Makefile of /CoreOS/rhcs/saili
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

FILES=$(METADATA) runtest.sh topologies.sh Makefile PURPOSE shared acceptance dev_java_tests codecoverage

.PHONY: all install download clean

run: $(FILES) build
	mkdir -p /opt/rhqa_pki
	mkdir -p /opt/rhqa_pki/jars
	mkdir -p /opt/rhqa_pki/PkiLib
	cp -n ./shared/env.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/rhcs-shared.sh
	cp ./shared/rhcs-shared.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/rhcs-install-shared.sh
	cp ./shared/rhcs-install-shared.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/pki-user-cli-lib.sh
	cp ./shared/pki-user-cli-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/pki-cert-cli-lib.sh
	cp ./shared/pki-cert-cli-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/pki-key-cli-lib.sh
	cp ./shared/pki-key-cli-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/dummycert1.pem
	cp ./shared/dummycert1.pem /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/build.xml
	cp ./shared/build.xml /opt/rhqa_pki/.
	chmod a+x /opt/rhqa_pki/*.sh
	rm -f /opt/rhqa_pki/jars/pki-qe-tools.jar
	cp  ./shared/jars/pki-qe-tools.jar /opt/rhqa_pki/jars/
	rm -f /opt/rhqa_pki/pki-auth-plugin-lib.sh
	cp ./shared/pki-auth-plugin-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/pki-config-lib.sh
	cp ./shared/pki-config-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/pki-profile-lib.sh
	cp ./shared/pki-profile-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/id_rsa-host-beaker_archive.pub
	cp  ./codecoverage/id_rsa-host-beaker_archive.pub /opt/rhqa_pki/id_rsa-host-beaker_archive.pub
	rm -f /opt/rhqa_pki/id_rsa-host-beaker_archive
	cp  ./codecoverage/id_rsa-host-beaker_archive /opt/rhqa_pki/id_rsa-host-beaker_archive
	rm -f /opt/rhqa_pki/known_hosts_archivehost
	cp  ./codecoverage/known_hosts_archivehost /opt/rhqa_pki/known_hosts_archivehost
	rm -f /opt/rhqa_pki/saving_codecoverage_results.sh
	cp  ./codecoverage/saving_codecoverage_results.sh /opt/rhqa_pki/saving_codecoverage_results.sh
	#Python
	rm -f /opt/rhqa_pki/PkiLib/pkicommonlib.py
	cp ./shared/PkiLib/pkicommonlib.py /opt/rhqa_pki/PkiLib/pkicommonlib.py
	rm -f /opt/rhqa_pki/PkiLib/pkiprofilelib.py
	cp ./shared/PkiLib/pkiprofilelib.py /opt/rhqa_pki/PkiLib/pkiprofilelib.py
	rm -f /opt/rhqa_pki/PkiLib/pkiprofilecli.py
	cp ./shared/PkiLib/pkiprofilecli.py /opt/rhqa_pki/PkiLib/pkiprofilecli.py
	rm -f /opt/rhqa_pki/PkiLib/pkiconstraintslib.py
	cp ./shared/PkiLib/pkiconstraintslib.py /opt/rhqa_pki/PkiLib/pkiconstraintslib.py
	rm -f /opt/rhqa_pki/PkiLib/__init__.py
	cp ./shared/PkiLib/__init__.py /opt/rhqa_pki/PkiLib/__init__.py
	#Runtest
	./runtest.sh

build: $(BUILT_FILES)
	#shared
	chmod a+x ./shared/rhcs-shared.sh
	chmod a+x ./shared/rhcs-install-shared.sh
	chmod a+x ./shared/pki-user-cli-lib.sh
	chmod a+x ./shared/dummycert1.pem
	chmod a+x ./shared/pki-cert-cli-lib.sh
	chmod a+x runtest.sh
	chmod a+x topologies.sh
	#quickinstall
	chmod a+x ./acceptance/quickinstall/rhcs-install.sh
	chmod a+x ./acceptance/quickinstall/rhcs-install-lib.sh
	chmod a+x ./acceptance/quickinstall/rhds-install.sh
	#user CA
	chmod a+x ./acceptance/cli-tests/pki-tests-setup/create-role-users.sh
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
	chmod a+x ./acceptance/cli-tests/pki-tests-setup/cleanup-role-users.sh
	#user KRA
	chmod a+x ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-mod-kra.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-cert-find-kra.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-cert-add-kra.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-cert-show-kra.sh
	chmod a+x ./acceptance/cli-tests/pki-user-cli/kra/pki-user-cli-user-cert-delete-kra.sh
	#CA user
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-add.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-show.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-find.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-del.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-membership-add.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-membership-find.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-membership-del.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-mod.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert-add.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert-find.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert-show.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-user-cli/pki-ca-user-cli-ca-user-cert-delete.sh
	#KRA user
	chmod a+x ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-mod.sh
	chmod a+x ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-cert-add.sh
	chmod a+x ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-cert.sh
	chmod a+x ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-cert-find.sh
	chmod a+x ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-cert-show.sh
	chmod a+x ./acceptance/cli-tests/pki-kra-user-cli/pki-kra-user-cli-kra-user-cert-delete.sh
	#cert CA
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
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-review-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-request-find-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-cert-cli/pki-cert-cli-find-ca.sh
	#CA cert
	chmod a+x ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-cert-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-show-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-show-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-revoke-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-release-hold-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-cert-hold-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-submit-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-profile-find-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-profile-show-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-review-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-request-find-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-cert-cli/pki-ca-cert-cli-find-ca.sh
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
	#CA group
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-add.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-find.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-mod.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-show.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-del.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-add.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-show.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-find.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-del.sh
	#group KRA
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-add-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-show-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-find-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-mod-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-del-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-member-add-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-member-find-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-member-del-ca.sh
	chmod a+x ./acceptance/cli-tests/pki-group-cli/pki-group-cli-group-member-show-ca.sh
	#KRA group
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-add.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-find.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-mod.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-show.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-del.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-add.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-show.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-find.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-group-cli/pki-ca-group-cli-ca-group-member-del.sh
	#key KRA
	chmod a+x ./acceptance/cli-tests/pki-key-cli/pki-key-cli-kra.sh
	chmod a+x ./acceptance/cli-tests/pki-key-cli/pki-key-cli-generate-kra.sh
	chmod a+x ./acceptance/cli-tests/pki-key-cli/pki-key-cli-find-kra.sh
	chmod a+x ./acceptance/cli-tests/pki-key-cli/pki-key-cli-template-find-kra.sh
	chmod a+x ./acceptance/cli-tests/pki-key-cli/pki-key-cli-template-show-kra.sh
	chmod a+x ./acceptance/cli-tests/pki-key-cli/pki-key-cli-request-find-kra.sh
	chmod a+x ./acceptance/cli-tests/pki-key-cli/pki-key-cli-request-show-kra.sh
	chmod a+x ./acceptance/cli-tests/pki-key-cli/pki-key-cli-show-kra.sh
	chmod a+x ./acceptance/cli-tests/pki-key-cli/pki-key-cli-mod-kra.sh 
	chmod a+X ./acceptance/cli-tests/pki-key-cli/pki-key-cli-archive-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-key-cli/pki-key-cli-recover-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-key-cli/pki-key-cli-retrieve-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-key-cli/pki-key-cli-request-review-kra.sh
	#kra key
	chmod a+X ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-generate-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-find-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-template-find-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-template-show-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-request-find-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-request-show-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-show-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-mod-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-archive-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-recover-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-retrieve-kra.sh
	chmod a+X ./acceptance/cli-tests/pki-kra-key-cli/pki-kra-key-cli-request-review-kra.sh
	#ca-profile
	chmod a+x ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-show.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-enable.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-disable.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-del.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-find.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-add.sh
	chmod a+x ./acceptance/cli-tests/pki-ca-profile-cli/pki-ca-profile-cli-mod.sh
	# bug verifications
	chmod a+x ./acceptance/bugzilla/tomcatjss-bugs/bug-1058366.sh
	chmod a+x ./acceptance/bugzilla/tomcatjss-bugs/bug-1084224.sh
	chmod a+x ./acceptance/bugzilla/pki-core-bugs/giant-debug-log.sh
	chmod a+x ./acceptance/bugzilla/pki-core-bugs/CSbackup-bug.sh
	chmod a+x ./acceptance/bugzilla/bug_setup.sh
	chmod a+x ./acceptance/bugzilla/bug_uninstall.sh
	chmod a+x ./acceptance/bugzilla/jss-bugs/bug-1133718.sh
	chmod a+x ./acceptance/bugzilla/jss-bugs/bug-1040640.sh
	chmod a+x ./acceptance/bugzilla/pki-core-bugs/bug-790924.sh
	# legacy
	chmod a+x ./acceptance/legacy/ca_tests/acls/ca-admin-acl.sh

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
	@echo "TestTime:        1500m" >> $(METADATA)
	@echo "RunFor:          rhcs" >> $(METADATA)
	@echo "Requires:        expect" >> $(METADATA)
	@echo "Priority:        Normal" >> $(METADATA)
	@echo "License:         GPLv2" >> $(METADATA)
	@echo "Confidential:    no" >> $(METADATA)
	@echo "Destructive:     no" >> $(METADATA)

	rhts-lint $(METADATA)
