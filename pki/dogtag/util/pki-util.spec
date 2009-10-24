Name:           pki-util
Version:        1.3.0
Release:        1%{?dist}
Summary:        Dogtag Certificate System - PKI Utility Framework
URL:            http://pki.fedoraproject.org/
License:        GPLv2 with exceptions
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  jss >= 4.2.6
BuildRequires:  ldapjdk
BuildRequires:  osutil
BuildRequires:  xerces-j2

Requires:       java >= 1:1.6.0
Requires:       jpackage-utils
Requires:       jss >= 4.2.6
Requires:       ldapjdk

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag PKI Utility Framework is required by the following four
Dogtag PKI subsystems:

    the Dogtag Certificate Authority,
    the Dogtag Data Recovery Manager,
    the Dogtag Online Certificate Status Protocol Manager, and
    the Dogtag Token Key Service.

%package javadoc
Summary:    Dogtag Certificate System - PKI Utility Framework Javadocs
Group:      Documentation

Requires:   %{name} = %{version}-%{release}

%description javadoc
Dogtag Certificate System - PKI Utility Framework Javadocs

This documentation pertains exclusively to version %{version} of
the Dogtag PKI Utility Framework.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="util" \
    -Dversion="%{version}"

%install
rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}
cd %{buildroot}%{_datadir}/java/pki
mv cmsutil.jar cmsutil-%{version}.jar
ln -s cmsutil-%{version}.jar cmsutil.jar
mv nsutil.jar nsutil-%{version}.jar
ln -s nsutil-%{version}.jar nsutil.jar

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_datadir}/java/pki

%files javadoc
%defattr(0644,root,root,0755)
%dir %{_javadocdir}/%{name}-%{version}
%{_javadocdir}/%{name}-%{version}/*

%changelog
* Tue Oct 13 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #521989 - packaging for Fedora Dogtag
