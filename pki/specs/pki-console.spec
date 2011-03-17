Name:             pki-console
Version:          9.0.1
Release:          1%{?dist}
Summary:          Certificate System - PKI Console
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Base

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake
BuildRequires:    idm-console-framework
BuildRequires:    java-devel >= 1:1.6.0
BuildRequires:    jpackage-utils
BuildRequires:    jss >= 4.2.6-12
BuildRequires:    ldapjdk
BuildRequires:    nspr-devel
BuildRequires:    nss-devel
BuildRequires:    pki-util

Requires:         idm-console-framework
Requires:         java >= 1:1.6.0
Requires:         jss >= 4.2.6-12
Requires:         ldapjdk
Requires:         pki-console-theme

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Certificate System (CS) is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The PKI Console is a java application used to administer CS.

For deployment purposes, a PKI Console requires ONE AND ONLY ONE of the
following "Mutually-Exclusive" PKI Theme packages:

  * dogtag-pki-theme (Dogtag Certificate System deployments)
  * redhat-pki-theme (Red Hat Certificate System deployments)


%prep


%setup -q


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVAR_INSTALL_DIR:PATH=/var -DBUILD_PKI_CONSOLE:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"


%files
%defattr(-,root,root,-)
%doc base/console/LICENSE
%{_bindir}/pkiconsole
%{_javadir}/pki/


%changelog
* Thu Mar 17 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.1-1
- Bugzilla Bug #688763 - Rebase updated Dogtag Packages for Fedora 15 (alpha)
- Bugzilla Bug #676682 - REGRESSION: Restore missing 'gif' files
  to console . . .

* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0 --> Dogtag 9.0.0
- Bugzilla Bug #607380 - CC: Make sure Java Console can configure
  all security relevant config items
- Bugzilla Bug #539781 - rhcs 71 - CRLs Partitioned
  by Reason Code - onlySomeReasons ?
- Bugzilla Bug #518241 - pkiconsole does not launch when CA is configured
  with ECC
- Bugzilla Bug #516632 - RHCS 7.1 - CS Incorrectly Issuing Multiple
  Certificates from the Same Request
- Bugzilla Bug #451874 - RFE - Java console - Certificate Wizard missing
  e.c. support
- Bugzilla Bug #638377 - Generate PKI UI components which exclude
  a GUI interface
- Bugzilla Bug #651977 - turn off ssl2 for java servers (server.xml)
- Bugzilla Bug #512496 - RFE rhcs80 - crl updates and scheduling feature 
- Bugzilla Bug #662201 - Console: View button for log messages
  is not functional.
- Bugzilla Bug #649343 - Publishing queue should recover from CA crash.
- Bugzilla Bug #663546 - Disable the functionalities that are not exposed
  in the console
- Bugzilla Bug #656733 - Standardize jar install location and jar names
- Bugzilla Bug #642741 - CS build uses deprecated functions

* Wed Apr 21 2010 Andrew Wnuk <awnuk@redhat.com> 1.3.2-1
- Bugzilla Bug #493765 - console renewal fix for ca, ocsp, and ssl certificates 

* Mon Feb 08 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.1-1
- Bugzilla Bug #562986 - Supply convenience symlink(s) for backwards
  compatibility (rename jar files as appropriate)

* Fri Jan 15 2010 Kevin Wright <kwright@redhat.com> 1.3.0-4
- removed BuildRequires dogtag-pki-console-ui

* Wed Jan 06 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #553487 - Review Request: pki-console
- The Dogtag PKI Console
- Take ownership of directories

* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-2
- Removed 'with exceptions' from License

* Thu Oct 15 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Packaging for Fedora Dogtag

