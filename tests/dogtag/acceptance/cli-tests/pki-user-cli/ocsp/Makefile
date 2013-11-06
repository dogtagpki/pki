# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   Makefile of /CoreOS/rhcs/acceptance/cli-tests/pki-user-cli/ocsp
#   Description: RHCS pki-user-add CLI tests
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

export TEST=/CoreOS/rhcs/acceptance/cli-tests/pki-user-cli/ocsp
export TESTVERSION=1.0

BUILT_FILES=

FILES=$(METADATA) pki-user-cli-user-ocsp.sh pki-user-cli-user-add-ocsp.sh pki-user-cli-user-show-ocsp.sh pki-user-cli-user-find-ocsp.sh pki-user-cli-user-del-ocsp.sh runtest.sh Makefile PURPOSE

.PHONY: all install download clean

run: $(FILES) build
	./runtest.sh

build: $(BUILT_FILES)
	chmod a+x runtest.sh
	chmod 777 pki-user-cli-user-ocsp.sh
	chmod 777 pki-user-cli-user-add-ocsp.sh
	chmod 777 pki-user-cli-user-show-ocsp.sh
	chmod 777 pki-user-cli-user-find-ocsp.sh
	chmod 777 pki-user-cli-user-del-ocsp.sh

clean:
	rm -f *~ $(BUILT_FILES)
	chmod a+x runtest.sh
	chmod 777 pki-user-cli-user-ocsp.sh
	chmod 777 pki-user-cli-user-add-ocsp.sh
	chmod 777 pki-user-cli-user-show-ocsp.sh
	chmod 777 pki-user-cli-user-find-ocsp.sh
	chmod 777 pki-user-cli-user-del-ocsp.sh



include /usr/share/rhts/lib/rhts-make.include

$(METADATA): Makefile
	@echo "Owner:           Asha Akkiangady <aakkiang@redhat.com>" > $(METADATA)
	@echo "Name:            $(TEST)" >> $(METADATA)
	@echo "TestVersion:     $(TESTVERSION)" >> $(METADATA)
	@echo "Path:            $(TEST_DIR)" >> $(METADATA)
	@echo "Description:     RHCS quickinstall" >> $(METADATA)
	@echo "Type:            Functional" >> $(METADATA)
	@echo "TestTime:        60m" >> $(METADATA)
	@echo "RunFor:          rhcs" >> $(METADATA)
	@echo "Requires:        expect" >> $(METADATA)
	@echo "Priority:        Normal" >> $(METADATA)
	@echo "License:         GPLv2" >> $(METADATA)
	@echo "Confidential:    no" >> $(METADATA)
	@echo "Destructive:     no" >> $(METADATA)

	rhts-lint $(METADATA)
