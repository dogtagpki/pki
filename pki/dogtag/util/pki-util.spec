Name:           pki-util
Version:        1.3.2
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
* Wed Aug 4 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.2-1
- Bugzilla Bug #527593 - More robust signature digest alg, like SHA256
  instead of SHA1 for ECC
- Bugzilla Bug #528236 - rhcs80 web conf wizard - cannot specify CA signing
  algorithm
- Bugzilla Bug #533510 - tps exception, cannot start when signed audit true
- Bugzilla Bug #529280 - TPS returns HTTP data without ending in 0rn per
  RFC 2616
- Bugzilla Bug #498299 - Should not be able to change the status manually
  on a token marked as permanently lost or destroyed
- Bugzilla Bug #554892 - configurable frequency signed audit
- Bugzilla Bug #500700 - tps log rotation
- Bugzilla Bug #562893 - tps shutdown if audit logs full
- Bugzilla Bug #557346 - Name Constraints Extension cant be marked critical
- Bugzilla Bug #556152 - ACL changes to CA and OCSP
- Bugzilla Bug #556167 - ACL changes to CA and OCSP
- Bugzilla Bug #581004 - add more audit logging to the TPS
- Bugzilla Bug #566517 - CC: Add client auth to OCSP publishing, and move
  to a client-auth port
- Bugzilla Bug #565842 - Clone config throws errors - fix key_algorithm
- Bugzilla Bug #581017 - enabling log signing from tps ui pages causes tps
  crash
- Bugzilla Bug #581004 - add more audit logs
- Bugzilla Bug #595871 - CC: TKS needed audit message changes
- Bugzilla Bug #598752 - Common Criteria: TKS ACL analysis result.
- Bugzilla Bug #598666 - Common Criteria: incorrect ACLs for signedAudit
- Bugzilla Bug #504905 - Smart card renewal should load old encryption cert
  on the token.
- Bugzilla Bug #499292 - TPS - Enrollments where keys are recovered need
  to do both GenerateNewKey and RecoverLast operation for encryption key.
- Bugzilla Bug #498299 - fix case where no transitions available

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
