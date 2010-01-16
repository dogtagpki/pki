Name:           pki-common
Version:        1.3.0
Release:        8%{?dist}
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
BuildRequires:  pki-util
BuildRequires:  symkey
BuildRequires:  velocity
BuildRequires:  xalan-j2
Buildrequires:  xerces-j2

Requires:       java >= 1:1.6.0
Requires:       jss >= 4.2.6
Requires:       osutil
Requires:       pki-common-ui
Requires:       pki-java-tools
Requires:       pki-setup
Requires:       symkey
Requires:       tomcatjss
Requires:       %{_javadir}/ldapjdk.jar
Requires:       %{_javadir}/velocity.jar
Requires:       %{_javadir}/xalan-j2.jar
Requires:       %{_javadir}/xerces-j2.jar
Requires:       velocity

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

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
mkdir -p %{buildroot}%{_sharedstatedir}/tomcat5/common/lib
cd %{buildroot}%{_sharedstatedir}/tomcat5/common/lib
ln -s %{_javadir}/ldapjdk.jar ldapjdk.jar
ln -s %{_javadir}/pki/cmsutil.jar cmsutil.jar
ln -s %{_javadir}/pki/nsutil.jar nsutil.jar
ln -s %{_javadir}/velocity.jar velocity.jar
ln -s %{_javadir}/xalan-j2.jar xalan-j2.jar
ln -s %{_javadir}/xerces-j2.jar xerces-j2.jar

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_javadir}/pki/
%{_datadir}/pki/
%{_sharedstatedir}/tomcat5/common/lib/*

%files javadoc
%defattr(-,root,root,-)
%{_javadocdir}/%{name}-%{version}/

%changelog
* Fri Jan 15 2010 Kevin Wright <kwright@redhat.com> 1.3.0-8
- Removed Requires:       rhgb

* Thu Jan 14 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-7
- Bugzilla Bug #441974 -  CA Setup Wizard cannot create new Security Domain.
- Moved 'Conflicts: tomcat-native' to lower-level 'tomcatjss' package

* Thu Dec 24 2009 Kevin Wright <kwright@redhat.com> 1.3.0-6
- Bugzilla Bug #522207 - packaging for Fedora Dogtag
- Removed Requires:       rhgb

* Wed Dec 23 2009 Kevin Wright <kwright@redhat.com> 1.3.0-5
- Bugzilla Bug #522207 - packaging for Fedora Dogtag
- Removed Requires:       %{_javadir}/pki/cmsutil.jar
- Removed Requires:       %{_javadir}/pki/nsutil.jar
- Removed BuildRequires:  dogtag-pki-common-ui
- added   Requires:       pki-util
- changed -javadoc to: %defattr(-,root,root,-)

* Mon Dec 7 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-4
- Bugzilla Bug #522207 - packaging for Fedora Dogtag
- Removed 'postinstall' tasks
- Removed 'with exceptions' from License

* Tue Nov 24 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #522207 - packaging for Fedora Dogtag
- Use "_javadir" macro when appropriate

* Mon Nov 2 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-2
- Bugzilla Bug #522207 - packaging for Fedora Dogtag
- Take ownership of directories

* Tue Oct 13 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #522207 - packaging for Fedora Dogtag
