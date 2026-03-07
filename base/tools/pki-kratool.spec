Name:           pki-kratool
Version:        11.6.0
Release:        1%{?dist}
Summary:        Dogtag PKI KRA LDIF Migration Tool

License:        GPLv2
URL:            https://www.dogtagpki.org
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  maven
BuildRequires:  java-17-openjdk-devel
BuildRequires:  jss >= 5.5.0
BuildRequires:  pki-base >= 11.6.0

# Runtime dependencies - use file paths instead of package names to avoid forcing upgrades
Requires:       java-17-openjdk-headless
#Requires:       jss >= 5.5.0
#Requires:       pki-base >= 11.6.0
#Requires:       slf4j
#Requires:       apache-commons-cli
#Requires:       apache-commons-lang3
#Requires:       ldapjdk
Requires:       /usr/lib/java/jss/jss-base.jar
Requires:       /usr/share/java/pki/pki-common.jar
Requires:       /usr/share/java/ldapjdk.jar
Requires:       /usr/share/java/slf4j/slf4j-api.jar
Requires:       /usr/share/java/slf4j/slf4j-jdk14.jar
Requires:       /usr/share/java/apache-commons-cli.jar
Requires:       /usr/share/java/apache-commons-lang3.jar

%description
KRATool is a command-line utility for migrating KRA (Key Recovery Authority)
LDIF data between different storage certificates and HSMs. This enhanced version
supports cross-scheme migration, enabling migration between KRAs using different
cryptographic algorithms (e.g., RSA to RSA-OAEP, AES/CBC to AES-KWP).

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
cat > %{buildroot}%{_bindir}/KRATool << 'EOF'
#!/bin/bash
exec java -cp %{_javadir}/pki-kratool-%{version}.jar:/usr/share/java/pki/pki-common.jar:/usr/lib/java/jss/jss-base.jar:/usr/share/java/slf4j/slf4j-api.jar:/usr/share/java/slf4j/slf4j-jdk14.jar:/usr/share/java/ldapjdk.jar:/usr/share/java/apache-commons-cli.jar:/usr/share/java/apache-commons-lang3.jar com.netscape.cmstools.KRATool "$@"
EOF
chmod 755 %{buildroot}%{_bindir}/KRATool

%files
%{_javadir}/%{name}-%{version}.jar
%{_bindir}/KRATool

%changelog
* Tue Feb 11 2025 Christina Fu <cfu@redhat.com> - 11.6.0-1
- Enhanced KRATool with cross-scheme migration support

