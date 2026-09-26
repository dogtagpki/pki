Name:           pki-kratool
Version:        11.9.2
Release:        1%{?dist}
Summary:        KRATool - PKI KRA LDIF Migration Tool

License:        GPLv2
URL:            https://www.dogtagpki.org
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  maven
BuildRequires:  java-17-openjdk-devel
BuildRequires:  jss >= 5.9.0
BuildRequires:  pki-base >= 11.9.0
BuildRequires:  slf4j
BuildRequires:  apache-commons-cli
BuildRequires:  apache-commons-lang3
BuildRequires:  ldapjdk

Requires:       java-17-openjdk-headless
Requires:       pki-base-java >= 11.9.0

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
#!/usr/bin/sh
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

JAVA="${JAVA_HOME}/bin/java"
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
  -Dredhat.crypto-policies=false \
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
* Thu Sep 24 2026 Christina Fu <cfu@redhat.com> - 11.9.2-1
- Fix KRATool launcher script to work in FIPS mode; fixed token comparison
* Fri Mar 20 2026 Christina Fu <cfu@redhat.com> - 11.10.0-1
- Make KRATool an independent RPM package
