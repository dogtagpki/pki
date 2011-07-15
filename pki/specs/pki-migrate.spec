Name:             pki-migrate
Version:          9.0.1
Release:          1%{?dist}
Summary:          Red Hat Certificate System - PKI Migration Scripts
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Base

# Suppress automatic 'requires' and 'provisions' of multi-platform 'binaries'
AutoReqProv:      no

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake
BuildRequires:    java-devel >= 1:1.6.0
BuildRequires:    jpackage-utils

Requires:         java >= 1:1.6.0

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%global _binaries_in_noarch_packages_terminate_build   0

%description
Red Hat Certificate System (CS) is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

PKI Migration Scripts are used to export data from previous versions of
Netscape Certificate Management Systems, iPlanet Certificate Management
Systems, and Red Hat Certificate Systems into a flat-file which may then
be imported into this release of Red Hat Certificate System.

Note that since this utility is platform-independent, it is generally possible
to migrate data from previous PKI deployments originally stored on other
hardware platforms as well as earlier versions of this operating system.


%prep


%setup -q


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVAR_INSTALL_DIR:PATH=/var -DBUILD_PKI_MIGRATE:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"


%files
%defattr(-,root,root,-)
%doc base/migrate/LICENSE
%dir %{_datadir}/pki
%{_datadir}/pki/migrate/


%changelog
* Thu Jul 14 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.1-1
- Bugzilla Bug #669226 - Remove Legacy Build System

* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0 (internal) --> Dogtag 9.0.0

* Mon Jul 13 2009 Matthew Harmsen <mharmsen@redhat.com> 8.0.0-17
- Bugzilla Bug #511136 - Integrate EULA file into RHCS
- Release Candidate 4 build

* Wed Jul 08 2009 Kevin Wright <kwright@redhat.com> 8.0.0-16
- Bugzilla Bug #510352 - Release Candidate 3 build

* Thu Jul 02 2009 Kevin Wright <kwright@redhat.com> 8.0.0-15
- Bugzilla Bug #509447 - Release Candidate 2 build

* Thu Jun 25 2009 Kevin Wright <kwright@redhat.com> 8.0.0-14
- Bugzilla Bug #508179 - Remove base_phase ".beta" tag

* Fri Jun 05 2009 Matthew Harmsen <mharmsen@redhat.com> 8.0.0-13
- Bugzilla Bug #499496 - pki-migrate package should include only the tools
  we support

* Mon May 18 2009 Ade Lee <alee@redhat.com> 8.0.0-12
- Bugzilla Bug #493717 - migration scripts required for TPS groups

* Mon May 04 2009 Kevin Wright <kwright@redhat.com> 8.0.0-11
- Bugzilla Bug #499030 - Beta 2 Release

* Fri Mar 27 2009 Matthew Harmsen <mharmsen@redhat.com> 8.0.0-10
- Bugzilla Bug #492502 - Redefine "base_phase" from ".alpha" to ".beta"

* Sat Feb 28 2009 Matthew Harmsen <mharmsen@redhat.com> 8.0.0-9
- Bugzilla Bug #487896 - Introduce optional 'base_phase' release tag to
  denote ".alpha", ".beta", etc.

* Tue Feb 17 2009 Matthew Harmsen <mharmsen@redhat.com> 8.0.0-8
- Bugzilla Bug #485790 - Need changes made to spec files in various packages
  to be able to build in koji/brew

* Fri Jan 30 2009 Matthew Harmsen <mharmsen@redhat.com> 8.0.0-7
- Bugzilla Bug #253615 - RFE: migration tool needs to be written for the
  serialization changes - Allowed 63ToTxt binaries to be published

* Sat Nov 29 2008 Matthew Harmsen <mharmsen@redhat.com> 8.0.0-6
- Aligned RHEL 5, RHEL 4, and Solaris 9 "base_release" numbers
- Bugzilla Bug #445402 - Changed "base_url" from
  "http://www.redhat.com/software/rha/certificate" to
  "http://www.redhat.com/certificate_system"

* Sat Nov 22 2008 Matthew Harmsen <mharmsen@redhat.com> 8.0.0-5
- Bugzilla Bug #472305 - "equality" tests in all spec files need to be fixed
- Bumped "java" and "java-devel" 1.4.2 and 1.5.0 dependencies to 1.6.0
- Changed "java-sdk" to "java-devel" for consistency

* Tue Oct 14 2008 Ade Lee <alee@redhat.com> 8.0.0-4
- bugzilla bug #223361 - added 80 migration scripts

* Fri Jun 08 2007 Matthew Harmsen <mharmsen@redhat.com> 8.0.0-3
- bugzilla bug #243480 - added legacy upgrade path

* Tue Jun 05 2007 Matthew Harmsen <mharmsen@redhat.com> 8.0.0-2
- bugzilla bug #242575 - Made numerous changes to spec file.

* Mon May 21 2007 Kevin McCarthy <kmccarth@redhat.com> 8.0.0-1
- Bump to version 8.0.

* Thu Apr 05 2007 Thomas Kwan <nkwan@redhat.com> 1.0.0-1
- Fixed change log to use the correct version

