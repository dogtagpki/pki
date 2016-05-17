Name:             pki-console
Version:          10.3.1
Release:          1%{?dist}
Summary:          Certificate System - PKI Console
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Base

%bcond_without    javadoc

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake >= 2.8.9-1
BuildRequires:    idm-console-framework
BuildRequires:    java-devel >= 1:1.7.0
BuildRequires:    ldapjdk
BuildRequires:    nspr-devel
BuildRequires:    nss-devel
BuildRequires:    junit
BuildRequires:    jpackage-utils >= 1.7.5-10
BuildRequires:    jss >= 4.2.6-35
BuildRequires:    pki-base-java >= %{version}

Requires:         idm-console-framework
Requires:         java >= 1:1.7.0
Requires:         ldapjdk
Requires:         pki-base-java >= %{version}
Requires:         pki-console-theme >= %{version}
Requires:         jpackage-utils >= 1.7.5-10
Requires:         jss >= 4.2.6-35

%if 0%{?rhel}
# NOTE:  In the future, as a part of its path, this URL will contain a release
#        directory which consists of the fixed number of the upstream release
#        upon which this tarball was originally based.
Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{version}/%{release}/rhel/%{name}-%{version}%{?prerel}.tar.gz
%else
Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{version}/%{release}/%{name}-%{version}%{?prerel}.tar.gz
%endif

%description
Certificate System (CS) is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The PKI Console is a java application used to administer CS.

For deployment purposes, a PKI Console requires ONE AND ONLY ONE of the
following "Mutually-Exclusive" PKI Theme packages:

  * dogtag-pki-console-theme (Dogtag Certificate System deployments)
  * redhat-pki-console-theme (Red Hat Certificate System deployments)


%prep


%setup -q -n %{name}-%{version}%{?prerel}


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVERSION=%{version}-%{release} \
	-DVAR_INSTALL_DIR:PATH=/var \
    -DBUILD_PKI_CONSOLE:BOOL=ON \
    -DJAVA_LIB_INSTALL_DIR=%{_jnidir} \
%if ! %{with javadoc}
    -DWITH_JAVADOC:BOOL=OFF \
%endif
    ..
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
* Tue May 17 2016 Dogtag Team <pki-devel@redhat.com> 10.3.1-1
- Updated version number to 10.3.1-1 (to allow upgrade from 10.3.0.b1)

* Mon May 16 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0-1
- Updated version number to 10.3.0-1

* Mon Apr 18 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0.b1-1
- Build for F24 beta

* Thu Apr  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0.a2-1
- Updated build for F24 alpha

* Fri Mar  4 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0.a1-1
- Build for F24 alpha

* Sat Aug  8 2015 Dogtag Team <pki-devel@redhat.com> 10.3.0-0.1
- Updated version number to 10.3.0-0.1

* Sat Jul 18 2015 Dogtag Team <pki-devel@redhat.com> 10.2.7-0.1
- Updated version number to 10.2.7-0.1

* Sat Jul 18 2015 Dogtag Team <pki-devel@redhat.com> 10.2.6-1
- Update release number for release build

* Sat Jun 20 2015 Dogtag Team <pki-devel@redhat.com> 10.2.6-0.2
- Remove ExcludeArch directive

* Fri Jun 19 2015 Dogtag Team <pki-devel@redhat.com> 10.2.6-0.1
- Updated version number to 10.2.6-0.1

* Fri Jun 19 2015 Dogtag Team <pki-devel@redhat.com> 10.2.5-1
- Update release number for release build

* Tue May 26 2015 Dogtag Team <pki-devel@redhat.com> 10.2.5-0.1
- Updated version number to 10.2.5-0.1

* Tue May 26 2015 Dogtag Team <pki-devel@redhat.com> 10.2.4-1
- Update release number for release build

* Thu Apr 23 2015 Dogtag Team <pki-devel@redhat.com> 10.2.4-0.1
- Updated version number to 10.2.4-0.1

* Thu Apr 23 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-1
- Update release number for release build

* Thu Apr  9 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-0.1
- Reverted version number back to 10.2.3-0.1

* Mon Apr  6 2015 Dogtag Team <pki-devel@redhat.com> 10.3.0-0.1
- Updated version number to 10.3.0-0.1

* Wed Mar 18 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-0.1
- Updated version number to 10.2.3-0.1

* Tue Mar 17 2015 Dogtag Team <pki-devel@redhat.com> 10.2.2-1
- Update release number for release build

* Thu Jan  8 2015 Dogtag Team <pki-devel@redhat.com> 10.2.2-0.1
- Updated version number to 10.2.2-0.1

* Thu Jan  8 2015 Dogtag Team <pki-devel@redhat.com> 10.2.1-1
- Update release number for release build

* Mon Nov 24 2014 Christina Fu <cfu@redhat.com> 10.2.1-0.2
- Ticket 1198 Bugzilla 1158410 add TLS range support to server.xml by default and upgrade (cfu)
- PKI Trac Ticket #1211 - New release overwrites old source tarball (mharmsen)
- up the release number to 0.2

* Fri Oct 24 2014 Dogtag Team <pki-devel@redhat.com> 10.2.1-0.1
- Updated version number to 10.2.1-0.1.

* Wed Sep  3 2014 Dogtag Team <pki-devel@redhat.com> 10.2.0-1
- Update release number for release build

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 10.1.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Fri Nov 22 2013 Dogtag Team <pki-devel@redhat.com> 10.2.0-0.1
- Updated version number to 10.2.0-0.1.

* Fri Nov 15 2013 Ade Lee <alee@redhat.com> 10.1.0-1
- Trac Ticket 788 - Clean up spec files
- Update release number for release build

* Sun Nov 10 2013 Ade Lee <alee@redhat.com> 10.1.0-0.3
- Change release number for beta build

* Fri Jun 14 2013 Endi S. Dewata <edewata@redhat.com> 10.1.0-0.2
- Updated dependencies to Java 1.7.

* Tue May 7 2013 Ade Lee <alee@redhat.com> 10.1.0-0.1
- Change release number for 10.1 development

* Mon May 6 2013 Ade Lee <alee@redhat.com> 10.0.2-3
- New srpm generated due to changes in java test framework

* Thu May 2 2013 Matthew Harmsen <mharmsen@redhat.com> 10.0.2-2
- Fix console wrapper script to work in Fedora 19

* Fri Apr 26 2013 Ade Lee <alee@redhat.com> 10.0.2-1
- Change release number for official release.

* Wed Mar 27 2013 Endi S. Dewata <edewata@redhat.com> 10.0.2-0.1
- Updated version number to 10.0.2-0.1.

* Fri Dec 7 2012 Ade Lee <alee@redhat.com> 10.0.0-1
- Update to official release for rc1

* Tue Nov 20 2012 Ade Lee <alee@redhat.com> 10.0.0-0.12.b3
- Removed conditionals for fedora < 17
- Update cmake version

* Mon Nov 12 2012 Ade Lee <alee@redhat.com> 10.0.0-0.11.b3
- Update release to b3

* Mon Oct 29 2012 Ade Lee <alee@redhat.com> 10.0.0-0.10.b2
- Update release to b2

* Wed Oct 24 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.9.b1
- TRAC Ticket #350 - Dogtag 10: Remove version numbers from PKI jar files . . .

* Mon Oct 8 2012 Ade Lee <alee@redhat.com> 10.0.0-0.8.b1
- Update release to b1

* Mon Oct 1 2012 Ade Lee <alee@redhat.com> 10.0.0-0.8.a2
- Update release to a2

* Sun Sep 30 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.8.a1
- Modified CMake to use RPM version number

* Thu Aug 30 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.7.a1
- Added runtime dependency on pki-base

* Wed Aug 22 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.6.a1
- Replaced pki-util with pki-base

* Thu Jul 12 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.5.a1
- Added option to build without Javadoc

* Thu Apr  5 2012 Christina Fu <cfu@redhat.com> 10.0.0-0.4.a1
- Bug 745278 - [RFE] ECC encryption keys cannot be archived

* Wed Mar 14 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.3.a1
- Corrected 'junit' dependency check

* Wed Feb 22 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.2.a1
- Bugzilla Bug #788787 - added 'junit'/'junit4' build-time requirements

* Wed Feb  1 2012 Nathan Kinder <nkinder@redhat.com> 10.0.0-0.1.a1
- Updated package version number

* Thu Sep 22 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.5-1
- Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . . (mharmsen)
- Bugzilla Bug #699809 - Convert CS to use systemd (alee)

* Wed Aug 31 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.4-1
- Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . .

* Thu Jul 14 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.3-1
- Bugzilla Bug #700462 - No action on clicking "Help" button of
  pkiconsole's right pane (alee)
- Bugzilla Bug #697939 - DRM signed audit log message - operation should
  be read instead of modify (jmagne)
- Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- Updated release of 'jss'

* Fri Mar 25 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.2-1
- Bugzilla Bug #690950 - Update Dogtag Packages for Fedora 15 (beta)
- Require "jss >= 4.2.6-15" as a build and runtime requirement

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

