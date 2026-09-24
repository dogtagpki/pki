Name:           pki-kratool
Version:        10.13.14
Release:        1%{?dist}
Summary:        KRATool - PKI KRA LDIF Migration Tool

License:        GPLv2
URL:            https://www.dogtagpki.org
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  maven
BuildRequires:  java-1.8.0-openjdk-devel
BuildRequires:  jss >= 4.9.0
BuildRequires:  pki-base >= 10.13.0
BuildRequires:  slf4j
BuildRequires:  apache-commons-cli
BuildRequires:  apache-commons-lang3
BuildRequires:  ldapjdk

Requires:       java-1.8.0-openjdk
Requires:       pki-base-java >= 10.13.0

%description
KRATool is a utility for migrating archived private keys between
PKI Key Recovery Authority (KRA) instances, including support for
cross-scheme cryptographic migration.

Key features:
- Separate control of source and target wrapping algorithms
- Order-independent LDIF field parsing
- Algorithm auto-detection and session key regeneration
- Optional software token fallback for unsupported algorithms
- Backward compatible with legacy KRATool usage

%prep
%setup -q

%build
mvn clean package

%install
install -d -m 755 %{buildroot}%{_javadir}
install -m 644 target/%{name}-%{version}.jar %{buildroot}%{_javadir}/

install -d -m 755 %{buildroot}%{_bindir}
cat > %{buildroot}%{_bindir}/KRATool << 'WRAPPER'
#!/bin/sh
#
# --- BEGIN COPYRIGHT BLOCK ---
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
# Copyright (C) 2007 Red Hat, Inc.
# All rights reserved.
# --- END COPYRIGHT BLOCK ---
#

# load default, system-wide, and user-specific PKI configuration and
# set NSS_DEFAULT_DB_TYPE.
. /usr/share/pki/scripts/config

###############################################################################
##  (1) Specify variables used by this script.                               ##
###############################################################################

COMMAND=KRATool

###############################################################################
##  (2) Check for valid usage of this command wrapper.                       ##
###############################################################################

###############################################################################
##  (3) Define helper functions.                                             ##
###############################################################################

###############################################################################
##  (4) Set the LD_LIBRARY_PATH environment variable to determine the        ##
##      search order this command wrapper uses to find shared libraries.     ##
###############################################################################

if [ -e "${PKI_JAVA_PATH}" ]; then
    JAVA="${PKI_JAVA_PATH}"
elif [ -e "${JAVA_HOME}/jre/bin/java" ]; then
    JAVA="${JAVA_HOME}/jre/bin/java"
elif [ -e "${JAVA_HOME}/bin/java" ]; then
    JAVA="${JAVA_HOME}/bin/java"
else
    JAVA="/usr/bin/env java"
fi
JAVA_OPTIONS=""

###############################################################################
##  (5) Execute the java command specified by this java command wrapper      ##
##      based upon the LD_LIBRARY_PATH and PKI_LIB environment variables.   ##
##      Our jar is prepended so its KRATool class takes precedence over the  ##
##      one bundled in pki-tools.jar.                                        ##
###############################################################################

${JAVA} ${JAVA_OPTIONS} \
  -cp "@KRATOOL_JAR@:${PKI_LIB}/*" \
  -Dcom.redhat.fips=false \
  -Djava.util.logging.config.file=${PKI_LOGGING_CONFIG} \
  com.netscape.cmstools.${COMMAND} "$@"

exit $?
WRAPPER
sed -i 's|@KRATOOL_JAR@|%{_javadir}/%{name}-%{version}.jar|' %{buildroot}%{_bindir}/KRATool
chmod 755 %{buildroot}%{_bindir}/KRATool

install -d -m 755 %{buildroot}%{_defaultlicensedir}/%{name}
install -m 644 LICENSE %{buildroot}%{_defaultlicensedir}/%{name}/

%files
%license LICENSE
%{_javadir}/%{name}-%{version}.jar
%{_bindir}/KRATool

%changelog
* Wed Sep 23 2026 Christina Fu <cfu@redhat.com> - 10.13.14-1
- Fix KRATool launcher script to work in FIPS mode; fixed token comparison
* Tue Mar 31 2026 Christina Fu <cfu@redhat.com> - 10.13.13-1
- Enhanced KRATool with cross-scheme migration support
- Make KRATool an independent RPM package
