Name:           pki-ca
Version:        1.3.3
Release:        1%{?dist}
Summary:        Dogtag Certificate System - Certificate Authority
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Daemons

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  jss >= 4.2.6
BuildRequires:  pki-common
BuildRequires:  pki-util
BuildRequires:  tomcatjss

Requires:       java >= 1:1.6.0
Requires:       pki-ca-ui
Requires:       pki-common
Requires:       pki-console
Requires:       pki-selinux
Requires:       pki-silent
Requires(post):    chkconfig
Requires(preun):   chkconfig
Requires(preun):   initscripts
Requires(postun):  initscripts

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Certificate Authority is a required PKI subsystem which issues,
renews, revokes, and publishes certificates as well as compiling and
publishing Certificate Revocation Lists (CRLs).
The Dogtag Certificate Authority can be configured as a self-signing
Certificate Authority (CA), where it is the root CA, or it can act as a
subordinate CA, where it obtains its own signing certificate from a public CA.

%prep

%setup -q

%build
ant \
    -Dinit.d="rc.d/init.d" \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="ca" \
    -Dversion="%{version}"

%install
%define major_version %(echo `echo %{version} | awk -F. '{ print $1 }'`)
%define minor_version %(echo `echo %{version} | awk -F. '{ print $2 }'`)
%define patch_version %(echo `echo %{version} | awk -F. '{ print $3 }'`)

rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}
sed -i 's/^preop.product.version=.*$/preop.product.version=%{version}/' %{buildroot}%{_datadir}/pki/ca/conf/CS.cfg
sed -i 's/^cms.version=.*$/cms.version=%{major_version}.%{minor_version}/' %{buildroot}%{_datadir}/pki/ca/conf/CS.cfg
mkdir -p %{buildroot}%{_localstatedir}/lock/pki/ca
mkdir -p %{buildroot}%{_localstatedir}/run/pki/ca
cd %{buildroot}%{_javadir}
mv ca.jar ca-%{version}.jar
ln -s ca-%{version}.jar ca.jar

# supply convenience symlink(s) for backwards compatibility
mkdir -p %{buildroot}%{_javadir}/pki/ca
cd %{buildroot}%{_javadir}/pki/ca
ln -s ../../ca.jar ca.jar

%clean
rm -rf %{buildroot}

%post
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add pki-cad || :

%preun
if [ $1 = 0 ] ; then
    /sbin/service pki-cad stop >/dev/null 2>&1
    /sbin/chkconfig --del pki-cad || :
fi

%postun
if [ "$1" -ge "1" ] ; then
    /sbin/service pki-cad condrestart >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_initrddir}/*
%{_javadir}/*
%{_datadir}/pki/
%{_localstatedir}/lock/*
%{_localstatedir}/run/*

%changelog
* Tue Mar 9 2010 Ade Lee <alee@redhat.com> 1.3.3-1
- Bugzilla Bug #545935 -  Add new client-auth ee port to address CVE-2009-3555 
  TLS: MITM attacks via session renegotiation

* Tue Feb 16 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.2-2
- Bugzilla Bug #566059 -  Add 'pki-console' as a runtime dependency
  for CA, KRA, OCSP, and TKS . . .

* Wed Feb 10 2010 Andrew Wnuk <awnuk@redhat.com> 1.3.2-1
- Bugzilla Bug #516632 -  CS Incorrectly Issuing Multiple Certificates
  from the Same Request
- Bugzilla Bug #563742 -  IPA certificate profile needs CRL distribution
  extension.

* Mon Feb 8 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.1-1
- Bugzilla Bug #562986 -  Supply convenience symlink(s) for backwards
  compatibility (rename jar files as appropriate)

* Fri Jan 15 2010 Kevin Wright <kwright@redhat.com> 1.3.0-8
- removed BuildRequires dogtag-pki-ca-ui

* Tue Jan 12 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-7
- Corrected "|| :" scriptlet logic (see Bugzilla Bug #475895)

* Mon Dec 7 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-6
- Bugzilla Bug #522210 - Packaging for Fedora Dogtag
- Bugzilla Bug #529070 -  rpm packaging problems (cannot reinstall correctly) 
- Removed 'with exceptions' from License

* Tue Nov 24 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-5
- Bugzilla Bug #522210 - Packaging for Fedora Dogtag
- Use "_javadir" macro when appropriate

* Mon Nov 2 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-4
- Bugzilla Bug #522210 - Packaging for Fedora Dogtag
- Take ownership of directories

* Tue Oct 13 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #522210 - Packaging for Fedora Dogtag

* Fri Sep 18 2009 Ade Lee <alee@redhat.com> 1.3.0-2
- Bugzilla Bug 522210 - addtional changes for packaging for Fedora Dogtag
  remove unused defines, unneeded attr defs, unneeded comments, autoreqprov

* Wed Sep 9 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug 522210 - Packaging for Fedora Dogtag
