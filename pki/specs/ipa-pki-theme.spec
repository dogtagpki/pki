Name:             ipa-pki-theme
Version:          9.0.3
Release:          7%{?dist}
Summary:          Certificate System - IPA PKI Theme Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Base

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

Patch0:           %{name}-%{version}-r1886.patch
Patch1:           %{name}-%{version}-r2161.patch

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


%package -n       ipa-pki-common-theme
Summary:          Certificate System - PKI Common Framework User Interface
Group:            System Environment/Base

Conflicts:        dogtag-pki-common-theme
Conflicts:        dogtag-pki-common-ui
Conflicts:        redhat-pki-common-theme
Conflicts:        redhat-pki-common-ui

Provides:         pki-common-theme = %{version}-%{release}
Provides:         pki-common-ui = %{version}-%{release}

%description -n   ipa-pki-common-theme
This PKI Common Framework User Interface contains
NO textual or graphical user interface for the PKI Common Framework.

This package is used by the Certificate System utilized by IPA.

%{overview}


%package -n       ipa-pki-ca-theme
Summary:          Certificate System - Certificate Authority User Interface
Group:            System Environment/Base

Requires:         ipa-pki-common-theme = %{version}-%{release}

Conflicts:        dogtag-pki-ca-theme
Conflicts:        dogtag-pki-ca-ui
Conflicts:        redhat-pki-ca-theme
Conflicts:        redhat-pki-ca-ui

Provides:         pki-ca-theme = %{version}-%{release}
Provides:         pki-ca-ui = %{version}-%{release}

%description -n   ipa-pki-ca-theme
This Certificate Authority (CA) User Interface contains
NO textual or graphical user interface for the CA.

This package is used by the Certificate System utilized by IPA.

%{overview}


%prep


%setup -q


%patch0 -b .p0
%patch1 -b .p1


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DBUILD_IPA_PKI_THEME:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"


%files -n ipa-pki-common-theme
%defattr(-,root,root,-)
%doc dogtag/common-ui/LICENSE
%dir %{_datadir}/pki
%{_datadir}/pki/common-ui/


%files -n ipa-pki-ca-theme
%defattr(-,root,root,-)
%doc dogtag/ca-ui/LICENSE
%{_datadir}/pki/ca-ui/


%changelog
* Tue Aug 23 2011 Ade Lee <alee@redhat.com> 9.0.3-7
- Resolves #712931 - CS requires too many ports to be open in the FW, r2161

* Wed Mar 9 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.3-6
- Resolves: #643543
- update to the ipa-pki-theme-9.0.3-r1886.patch file

* Wed Mar 9 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.3-5
- Resolves: #643543

* Wed Mar 9 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.3-4
- Resolves #643543

* Wed Mar 9 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.3-3
- Resolves 643543

* Wed Mar 9 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.3-2
- Resolves 643543
- Resolves #683172 - pkisilent needs to provide option to set
  nsDS5ReplicaTransportInfo to TLS in replication agreements
  when creating a clone, r1886

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

