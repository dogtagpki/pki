Name:           pki-kratool
Version:        10.13.13
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

# Runtime dependencies - use file paths instead of package names to avoid forcing upgrades
Requires:       java-1.8.0-openjdk
#Requires:       jss >= 4.9.0
#Requires:       pki-base >= 10.13.0
#Requires:       slf4j
#Requires:       apache-commons-cli
#Requires:       apache-commons-lang3
#Requires:       ldapjdk
Requires:       /usr/lib64/jss/jss.jar
Requires:       /usr/share/java/pki/pki-certsrv.jar
Requires:       /usr/share/java/pki/pki-cmsutil.jar
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
exec java -cp %{_javadir}/%{name}-%{version}.jar:/usr/share/java/pki/pki-certsrv.jar:/usr/share/java/pki/pki-cmsutil.jar:/usr/lib64/jss/jss.jar:/usr/share/java/slf4j/slf4j-api.jar:/usr/share/java/slf4j/slf4j-jdk14.jar:/usr/share/java/ldapjdk.jar:/usr/share/java/apache-commons-cli.jar:/usr/share/java/apache-commons-lang3.jar com.netscape.cmstools.KRATool "\$@"
EOF
chmod 755 %{buildroot}%{_bindir}/KRATool

install -d -m 755 %{buildroot}%{_defaultlicensedir}/%{name}
install -m 644 LICENSE %{buildroot}%{_defaultlicensedir}/%{name}/

%files
%license LICENSE
%{_javadir}/%{name}-%{version}.jar
%{_bindir}/KRATool

%changelog
* Tue Mar 31 2026 Christina Fu <cfu@redhat.com> - 10.13.13-1
- Enhanced KRATool with cross-scheme migration support
- Make KRATool an independent RPM package
