# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Makefile of /CoreOS/rhcs/acceptance/install
#   Description: Basic install test for rhcs
#   Author: Asha Akkiangady <aakkiang@redhat.com>
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
export TEST=/CoreOS/rhcs/shared
export TESTVERSION=1.0.0

BUILT_FILES=

FILES=$(METADATA) rhcs-shared.sh rhcs-install-shared.sh pki-user-cli-lib.sh set-root-pw.exp runtest.sh Makefile PURPOSE env.sh pki-cert-cli-lib.sh dummycert1.pem

.PHONY: all install download clean

run: $(FILES) build
	rm -rf /opt/rhqa_pki
	mkdir /opt/rhqa_pki
	rm -f /opt/rhqa_pki/env.sh
	cp ./env.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/rhcs-shared.sh
	cp ./rhcs-shared.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/rhcs-install-shared.sh
	cp ./rhcs-install-shared.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/pki-user-cli-lib.sh
	cp ./pki-user-cli-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/set-root-pw.exp
	cp ./set-root-pw.exp /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/pki-cert-cli-lib.sh
	cp ./pki-cert-cli-lib.sh /opt/rhqa_pki/.
	rm -f /opt/rhqa_pki/dummycert1.pem
	cp ./dummycert1.pem /opt/rhqa_pki/.
	chmod 755 /opt/rhqa_pki/*.sh
	./runtest.sh

build: $(BUILT_FILES)
	chmod 755 rhcs-shared.sh
	chmod 755 rhcs-install-shared.sh
	chmod 755 set-root-pw.exp
	chmod 755 pki-user-cli-lib.sh
	chmod 755 dummycert1.pem
	chmod 755 pki-cert-cli-lib.sh
	chmod a+x runtest.sh

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
	@echo "TestTime:        2m" >> $(METADATA)
	@echo "RunFor:          rhcs" >> $(METADATA)
	@echo "Requires:        expect" >> $(METADATA)
	@echo "Priority:        Normal" >> $(METADATA)
	@echo "License:         GPLv2" >> $(METADATA)
	@echo "Confidential:    no" >> $(METADATA)
	@echo "Destructive:     no" >> $(METADATA)

	rhts-lint $(METADATA)
