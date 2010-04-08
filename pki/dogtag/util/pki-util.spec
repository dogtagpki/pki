Name:           pki-util
Version:        1.3.1
Release:        1%{?dist}
Summary:        Dogtag Certificate System - PKI Utility Framework
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
BuildRequires:  xerces-j2

Requires:       java >= 1:1.6.0
Requires:       jpackage-utils
Requires:       jss >= 4.2.6
Requires:       ldapjdk

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%if 0%{?rhel}
# For EPEL, override the '_sharedstatedir' macro on RHEL
%define         _sharedstatedir    /var/lib
%endif

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
cd %{buildroot}%{_javadir}/pki
mv cmsutil.jar cmsutil-%{version}.jar
ln -s cmsutil-%{version}.jar cmsutil.jar
mv nsutil.jar nsutil-%{version}.jar
ln -s nsutil-%{version}.jar nsutil.jar
mkdir -p %{buildroot}%{_sharedstatedir}/tomcat5/common/lib
cd %{buildroot}%{_sharedstatedir}/tomcat5/common/lib
ln -s %{_javadir}/pki/cmsutil.jar cmsutil.jar
ln -s %{_javadir}/pki/nsutil.jar nsutil.jar

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_javadir}/pki/
%{_sharedstatedir}/tomcat5/common/lib/*

%files javadoc
%defattr(0644,root,root,0755)
%{_javadocdir}/%{name}-%{version}/

%changelog
* Thu Apr 8 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.1-1
- Update source tarball

* Tue Apr 6 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-6
- Bugzilla Bug #568787 - pki-ca fails to create SSL connectors
- Bugzilla Bug #573038 - Unable to login on Dogtag EPEL installation

* Mon Jan 25 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-5
- Created "_sharedstatedir/tomcat5/common/lib/cmsutil.jar" link
- Created "_sharedstatedir/tomcat5/common/lib/nsutil.jar" link

* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-4
- Removed 'with exceptions' from License

* Tue Nov 24 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #521989 - packaging for Fedora Dogtag
- Use "_javadir" macro when appropriate

* Mon Nov 2 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-2
- Bugzilla Bug #521989 - packaging for Fedora Dogtag
- Take ownership of directories

* Tue Oct 13 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #521989 - packaging for Fedora Dogtag
