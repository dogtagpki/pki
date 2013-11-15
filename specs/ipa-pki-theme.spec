Name:             ipa-pki-theme
Version:          10.1.0
Release:          1%{?dist}
Summary:          Certificate System - IPA PKI Theme Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Base

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}%{?prerel}.tar.gz

%if 0%{?rhel}
ExcludeArch:      ppc ppc64 s390 s390x
%endif

%global overview                                                       \
Several PKI packages require a "virtual" theme component.  These       \
"virtual" theme components are "Provided" by various theme "flavors"   \
including "dogtag", "redhat", and "ipa".  Consequently,                \
all "dogtag", "redhat", and "ipa" theme components MUST be             \
mutually exclusive!                                                    \
                                                                       \
On Fedora systems, the "dogtag" theme packages are the ONLY available  \
theme components.                                                      \
                                                                       \
Similarly, the "ipa" theme packages are ONLY available on RHEL         \
systems, and represent the default theme components.                   \
                                                                       \
Alternatively, on RHEL systems, if the "dogtag" theme packages are     \
available as EPEL packages, while they may be used as a transparent    \
replacement for their corresponding "ipa" theme package, they are not  \
intended to be used as a replacement for their corresponding "redhat"  \
theme components.                                                      \
                                                                       \
Finally, if available for a RHEL system (e. g. - RHCS subscription),   \
each "redhat" theme package MUST be used as a transparent replacement  \
for its corresponding "ipa" theme package or "dogtag" theme package.   \
%{nil}

%description %{overview}


%package -n       ipa-pki-server-theme
Summary:          Certificate System - PKI Server Framework User Interface
Group:            System Environment/Base

Conflicts:        dogtag-pki-server-theme
Conflicts:        dogtag-pki-common-theme
Conflicts:        dogtag-pki-common-ui
Conflicts:        dogtag-pki-ca-theme
Conflicts:        dogtag-pki-ca-ui

Conflicts:        redhat-pki-server-theme
Conflicts:        redhat-pki-common-theme
Conflicts:        redhat-pki-common-ui
Conflicts:        redhat-pki-ca-theme
Conflicts:        redhat-pki-ca-ui

Obsoletes:        ipa-pki-common-theme
Obsoletes:        ipa-pki-common-ui
Obsoletes:        ipa-pki-ca-theme

Provides:         pki-server-theme = %{version}-%{release}
Provides:         pki-common-theme = %{version}-%{release}
Provides:         pki-common-ui = %{version}-%{release}

Provides:         ipa-pki-ca-theme = %{version}-%{release}
Provides:         pki-ca-theme = %{version}-%{release}
Provides:         pki-ca-ui = %{version}-%{release}

%description -n   ipa-pki-server-theme
This PKI Server Framework User Interface contains
NO textual or graphical user interface for the PKI Server Framework.

This package is used by the Certificate System utilized by IPA.

%{overview}


%prep


%setup -q -n %{name}-%{version}%{?prerel}


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVERSION=%{version}-%{release} \
	-DBUILD_IPA_PKI_THEME:BOOL=ON \
	..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"


%files -n ipa-pki-server-theme
%defattr(-,root,root,-)
%doc dogtag/common-ui/LICENSE
%dir %{_datadir}/pki
%{_datadir}/pki/common-ui/


%changelog
* Fri Nov 15 2013 Ade Lee <alee@redhat.com> 10.1.0-1
- Trac Ticket 788 - Clean up spec files
- Update release number for release build

* Tue May 7 2013 Ade Lee <alee@redhat.com> 10.1.0-0.1
- Change release number for 10.1 development

* Fri Apr 26 2013 Ade Lee <alee@redhat.com> 10.0.2-1
- Change release number for official release.

* Wed Mar 27 2013 Endi S. Dewata <edewata@redhat.com> 10.0.2-0.1
- Updated version number to 10.0.2-0.1.

* Fri Dec 7 2012 Ade Lee <alee@redhat.com> 10.0.0-1
- Update to official release for rc1

* Mon Nov 12 2012 Ade Lee <alee@redhat.com> 10.0.0-0.6.b3
- Update release to b3

* Fri Nov 9 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.5.b2
- Removed IPA CA theme package.

* Thu Nov 8 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.4.b2
- Renamed ipa-pki-common-theme to ipa-pki-server-theme.

* Mon Oct 29 2012 Ade Lee <alee@redhat.com> 10.0.0-0.3.b2
- Update release to b2

* Mon Oct 8 2012 Ade Lee <alee@redhat.com> 10.0.0-0.2.b1
- Update release to b1

* Mon Oct 1 2012 Ade Lee <alee@redhat.com> 10.0.0-0.2.a2
- Update release to a2

* Sun Sep 30 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.2.a1
- Modified CMake to use RPM version number

* Wed Feb  1 2012 Nathan Kinder <nkinder@redhat.com> 10.0.0-0.1.a1
- Updated package version number

* Tue Aug 23 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.5-1
- 'ipa-pki-ca-theme'
-      Bugzilla Bug #695015 - Serial No. of a revoked certificate is not
       populated in the CA signedAudit messages (alee)
-      Bugzilla Bug #694143 - CA Agent not returning specified request (awnuk)
-      Bugzilla Bug #704351 - remove help buttons in agent and ee UI in all
       subsystems (alee)
-      Bugzilla Bug #712931 - CS requires too many ports
       to be open in the FW (alee)
- 'ipa-pki-common-theme'

* Thu Jul 14 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.4-1
- 'ipa-pki-ca-theme'
-      Bugzilla Bug #669226 - Remove Legacy Build System
- 'ipa-pki-common-theme'
-      Bugzilla Bug #669226 - Remove Legacy Build System

* Thu Jan 20 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.3-1
- Augmented overview description.
- 'ipa-pki-ca-theme'
-     Bugzilla Bug #564207 - Searches for completed requests in the agent
      interface returns zero entries

* Thu Jan 20 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.2-1
- 'ipa-pki-common-theme'
-     Bugzilla Bug #671058 - ipa2 - ipa-server-install fails on pkisilent -
      xml parsing string -- ?

* Tue Jan 18 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.1-1
- Made 'ipa-pki-common-theme' a runtime dependency of 'ipa-pki-ca-theme'
- https://pkgdb.lab.eng.bos.redhat.com/pkg/packages/srpm/5936/
-   Package Wrangler:  applied GPLv2 license header to 'xml.vm'

* Thu Jan 13 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-2
- Bugzilla Bug #668836 - Review Request: ipa-pki-theme
-   Modified overview to pertain more to these packages
-   Removed "Obsoletes:" lines (only pertinent to internal deployments)
-   Modified installation section to preserve timestamps
-   Removed sectional comments

* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision. (kwright@redhat.com & mharmsen@redhat.com)

