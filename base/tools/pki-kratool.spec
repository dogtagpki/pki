Name:           pki-kratool
Version:        11.10.0
Release:        1%{?dist}
Summary:        KRATool - PKI KRA LDIF Migration Tool

License:        GPLv2
URL:            https://www.dogtagpki.org
Source0:        %{name}-%{version}.tar.gz

BuildArch:      noarch

BuildRequires:  maven
BuildRequires:  java-17-openjdk-devel
BuildRequires:  jss >= 5.5.0
BuildRequires:  pki-base >= 11.6.0
BuildRequires:  slf4j
BuildRequires:  apache-commons-cli
BuildRequires:  apache-commons-lang3
BuildRequires:  ldapjdk

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
cat > %{buildroot}%{_bindir}/KRATool << EOF
#!/bin/bash
exec java -cp %{_javadir}/%{name}-%{version}.jar:/usr/share/java/pki/pki-common.jar:/usr/lib/java/jss/jss-base.jar:/usr/share/java/slf4j/slf4j-api.jar:/usr/share/java/slf4j/slf4j-jdk14.jar:/usr/share/java/ldapjdk.jar:/usr/share/java/apache-commons-cli.jar:/usr/share/java/apache-commons-lang3.jar com.netscape.cmstools.KRATool "\$@"
EOF
chmod 755 %{buildroot}%{_bindir}/KRATool

install -d -m 755 %{buildroot}%{_defaultlicensedir}/%{name}
install -m 644 LICENSE %{buildroot}%{_defaultlicensedir}/%{name}/

%files
%license LICENSE
%{_javadir}/%{name}-%{version}.jar
%{_bindir}/KRATool

%changelog
* Fri Mar 20 2026 Christina Fu <cfu@redhat.com> - 11.10.0-1
- Make KRATool an independent RPM package
