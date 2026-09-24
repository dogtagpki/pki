%global product_name PKI HSM Compatibility Verification

Name:           pki-hsm-compat-verify
Version:        1.0.0
Release:        1%{?dist}
Summary:        PKI HSM/PKCS#11 Compatibility Verification Tool
License:        GPL-2.0-only
URL:            https://www.dogtagpki.org

Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  java-1.8.0-openjdk-devel
BuildRequires:  maven
BuildRequires:  jss >= 4.9.0
BuildRequires:  apache-commons-cli
BuildRequires:  dogtag-pki-base-java >= 10.13.0

# Runtime dependencies - use file paths instead of package names to avoid forcing upgrades
Requires:       java-1.8.0-openjdk-headless
#Requires:       jss >= 4.9.0
#Requires:       apache-commons-cli
#Requires:       dogtag-pki-base-java >= 10.13.0
Requires:       /usr/lib/java/jss.jar
Requires:       /usr/share/java/apache-commons-cli.jar
Requires:       /usr/share/java/pki/pki-cmsutil.jar
Requires:       /usr/share/java/pki/pki-certsrv.jar

%description
A standalone tool to test HSM/PKCS#11 compatibility for Dogtag PKI KRA
key archival and recovery operations. This tool can be used to verify
that an HSM supports the minimum cryptographic capabilities required
for KRA without requiring a full PKI installation.

The tool performs two-phase testing:
- Setup phase: Creates PKI infrastructure (CA, transport, storage certs) on HSM
- Test phase: Tests complete archival/recovery workflow

%prep
%setup -q

%build
mvn clean package -DskipTests -Djss.jar.path=/usr/lib/java/jss.jar

%install
# Install JAR
install -d -m 755 %{buildroot}%{_javadir}/pki
install -m 644 target/pki-hsm-compat-verify.jar %{buildroot}%{_javadir}/pki/

# Install wrapper scripts
install -d -m 755 %{buildroot}%{_bindir}

# hsmCompatVerifyServ wrapper
cat > %{buildroot}%{_bindir}/hsmCompatVerifyServ <<'EOF'
#!/bin/sh
# KRA HSM Compatibility Verification Tool - Server Side

# load default, system-wide, and user-specific PKI configuration
[ -f /usr/share/pki/scripts/config ] && . /usr/share/pki/scripts/config || exit 1

JAVA="${JAVA_HOME:+${JAVA_HOME}/bin/}java"
PKI_LIB_DIR="${PKI_LIB:-%{_javadir}}"
JAVA_OPTIONS=""

${JAVA} ${JAVA_OPTIONS} \
  -cp "%{_javadir}/pki/pki-hsm-compat-verify.jar:${PKI_LIB_DIR}/*" \
  -Dcom.redhat.fips=false \
  ${PKI_LOGGING_CONFIG:+-Djava.util.logging.config.file=${PKI_LOGGING_CONFIG}} \
  com.netscape.cmstools.hsmCompatVerifyServ "$@"

exit $?
EOF
chmod 755 %{buildroot}%{_bindir}/hsmCompatVerifyServ

# hsmCompatVerifyClnt wrapper
cat > %{buildroot}%{_bindir}/hsmCompatVerifyClnt <<'EOF'
#!/bin/sh
# KRA HSM Compatibility Verification Tool - Client Side

# load default, system-wide, and user-specific PKI configuration
[ -f /usr/share/pki/scripts/config ] && . /usr/share/pki/scripts/config || exit 1

JAVA="${JAVA_HOME:+${JAVA_HOME}/bin/}java"
PKI_LIB_DIR="${PKI_LIB:-%{_javadir}}"
JAVA_OPTIONS=""

${JAVA} ${JAVA_OPTIONS} \
  -cp "%{_javadir}/pki/pki-hsm-compat-verify.jar:${PKI_LIB_DIR}/*" \
  -Dcom.redhat.fips=false \
  ${PKI_LOGGING_CONFIG:+-Djava.util.logging.config.file=${PKI_LOGGING_CONFIG}} \
  com.netscape.cmstools.hsmCompatVerifyClnt "$@"

exit $?
EOF
chmod 755 %{buildroot}%{_bindir}/hsmCompatVerifyClnt

%files
%{_bindir}/hsmCompatVerifyServ
%{_bindir}/hsmCompatVerifyClnt
%{_javadir}/pki/pki-hsm-compat-verify.jar

%changelog
* Mon Apr 06 2026 Christina Fu <cfu@redhat.com> - 1.0.0-1
- Initial standalone package for PKI HSM compatibility verification tool
