Name:           pki-common
Version:        9.0.0
Release:        1%{?dist}
Summary:        Dogtag Certificate System - PKI Common Framework
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  jss >= 4.2.6
BuildRequires:  ldapjdk
BuildRequires:  osutil
BuildRequires:  pki-symkey
BuildRequires:  pki-util
BuildRequires:  velocity
BuildRequires:  xalan-j2
Buildrequires:  xerces-j2

Requires:       java >= 1:1.6.0
Requires:       jss >= 4.2.6
Requires:       osutil
Requires:       pki-common-ui
Requires:       pki-java-tools
Requires:       pki-setup
Requires:       pki-symkey
Requires:       tomcatjss
Requires:       %{_javadir}/ldapjdk.jar
Requires:       %{_javadir}/velocity.jar
Requires:       %{_javadir}/xalan-j2.jar
Requires:       %{_javadir}/xalan-j2-serializer.jar
Requires:       %{_javadir}/xerces-j2.jar
Requires:       velocity

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%if 0%{?rhel}
# For EPEL, override the '_sharedstatedir' macro on RHEL
%define         _sharedstatedir    /var/lib
%endif

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag PKI Common Framework is required by the following four
Dogtag PKI subsystems:

    the Dogtag Certificate Authority,
    the Dogtag Data Recovery Manager,
    the Dogtag Online Certificate Status Protocol Manager, and
    the Dogtag Token Key Service.

%package javadoc
Summary:    Dogtag Certificate System - PKI Common Framework Javadocs
Group:      Documentation

Requires:   pki-common = %{version}-%{release}

%description javadoc
Dogtag Certificate System - PKI Common Framework Javadocs

This documentation pertains exclusively to version %{version} of
the Dogtag PKI Common Framework.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="common" \
    -Dversion="%{version}"

%install
rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}
cd %{buildroot}%{_javadir}/pki
mv certsrv.jar certsrv-%{version}.jar
ln -s certsrv-%{version}.jar certsrv.jar
mv cms.jar cms-%{version}.jar
ln -s cms-%{version}.jar cms.jar
mv cmsbundle.jar cmsbundle-%{version}.jar
ln -s cmsbundle-%{version}.jar cmsbundle.jar
mv cmscore.jar cmscore-%{version}.jar
ln -s cmscore-%{version}.jar cmscore.jar

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_javadir}/pki/
%{_datadir}/pki/

%files javadoc
%defattr(-,root,root,-)
%{_javadocdir}/%{name}-%{version}/

%changelog
* Fri Nov 19 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0 --> Dogtag 9.0.0.
