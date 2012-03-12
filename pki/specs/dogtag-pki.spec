Summary:          Dogtag Public Key Infrastructure (PKI) Suite
Name:             dogtag-pki
Version:          9.0.0
Release:          10%{?dist}
# The entire source code is GPLv2 except for 'pki-tps' which is LGPLv2
License:          GPLv2 and LGPLv2
URL:              http://pki.fedoraproject.org/
Group:            System Environment/Daemons
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:        noarch

# Establish MINIMUM package versions based upon platform
%if 0%{?fedora} >= 17
%define dogtag_pki_theme_version   9.0.11
%define esc_version                1.1.0
%define jss_version                4.2.6-21
%define osutil_version             2.0.2
%define pki_core_version           9.0.18
%define pki_kra_version            9.0.10
%define pki_ocsp_version           9.0.9
%define pki_ra_version             9.0.4
%define pki_tks_version            9.0.9
%define pki_tps_version            9.0.7
%define pki_console_version        9.0.5
%define tomcatjss_version          6.0.2
%else
%if 0%{?fedora} >= 16
%define dogtag_pki_theme_version   9.0.11
%define esc_version                1.1.0
%define jss_version                4.2.6-19.1
%define osutil_version             2.0.2
%define pki_core_version           9.0.18
%define pki_kra_version            9.0.10
%define pki_ocsp_version           9.0.9
%define pki_ra_version             9.0.4
%define pki_tks_version            9.0.9
%define pki_tps_version            9.0.7
%define pki_console_version        9.0.5
%define tomcatjss_version          6.0.2
%else
%if 0%{?fedora} >= 15
%define dogtag_pki_theme_version   9.0.11
%define esc_version                1.1.0
%define jss_version                4.2.6-17
%define osutil_version             2.0.1
%define pki_core_version           9.0.18
%define pki_kra_version            9.0.10
%define pki_ocsp_version           9.0.9
%define pki_ra_version             9.0.0
%define pki_tks_version            9.0.9
%define pki_tps_version            9.0.0
%define pki_console_version        9.0.0
%define tomcatjss_version          6.0.0
%else
%define dogtag_pki_theme_version   9.0.0
%define esc_version                1.1.0
%define jss_version                4.2.6-17
%define osutil_version             2.0.0
%define pki_core_version           9.0.0
%define pki_kra_version            9.0.0
%define pki_ocsp_version           9.0.0
%define pki_ra_version             9.0.0
%define pki_tks_version            9.0.0
%define pki_tps_version            9.0.0
%define pki_console_version        9.0.0
%define tomcatjss_version          2.0.0
%endif
%endif
%endif

# Make certain that this 'meta' package requires the latest version(s)
# of ALL top-level Dogtag PKI support packages
Requires:         jss >= %{jss_version}
Requires:         osutil >= %{osutil_version}
Requires:         tomcatjss >= %{tomcatjss_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL top-level Dogtag PKI support javadocs
Requires:         jss-javadoc >= %{jss_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI theme packages
Requires:         dogtag-pki-ca-theme >= %{dogtag_pki_theme_version}
Requires:         dogtag-pki-common-theme >= %{dogtag_pki_theme_version}
Requires:         dogtag-pki-console-theme >= %{dogtag_pki_theme_version}
Requires:         dogtag-pki-kra-theme >= %{dogtag_pki_theme_version}
Requires:         dogtag-pki-ocsp-theme >= %{dogtag_pki_theme_version}
Requires:         dogtag-pki-ra-theme >= %{dogtag_pki_theme_version}
Requires:         dogtag-pki-tks-theme >= %{dogtag_pki_theme_version}
Requires:         dogtag-pki-tps-theme >= %{dogtag_pki_theme_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI core packages
Requires:         pki-ca >= %{pki_core_version}
Requires:         pki-common >= %{pki_core_version}
Requires:         pki-java-tools >= %{pki_core_version}
Requires:         pki-native-tools >= %{pki_core_version}
Requires:         pki-selinux >= %{pki_core_version}
Requires:         pki-setup >= %{pki_core_version}
Requires:         pki-silent >= %{pki_core_version}
Requires:         pki-symkey >= %{pki_core_version}
Requires:         pki-util >= %{pki_core_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI core javadocs
Requires:         pki-common-javadoc >= %{pki_core_version}
Requires:         pki-java-tools-javadoc >= %{pki_core_version}
Requires:         pki-util-javadoc >= %{pki_core_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL other Dogtag PKI subsystems
Requires:         pki-kra >= %{pki_kra_version}
Requires:         pki-ocsp >= %{pki_ocsp_version}
Requires:         pki-ra >= %{pki_ra_version}
Requires:         pki-tks >= %{pki_tks_version}
Requires:         pki-tps >= %{pki_tps_version}

# Make certain that this 'meta' package requires the latest version(s)
# of Dogtag PKI console
Requires:         pki-console >= %{pki_console_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI clients
Requires:         esc >= %{esc_version}

# NOTE:  Several PKI packages require a "virtual" theme component.  These
#        "virtual" theme components are "Provided" by various theme "flavors"
#        including "dogtag", "redhat", and "ipa".  Consequently,
#        all "dogtag", "redhat", and "ipa" theme components MUST be
#        mutually exclusive!
#
#        On Fedora systems, the "dogtag" theme packages are the ONLY available
#        theme components.
#
#        Similarly, the "ipa" theme packages are ONLY available on RHEL
#        systems, and represent the default theme components.
#
#        Alternatively, on RHEL systems, if the "dogtag" theme packages are
#        available as EPEL packages, while they may be used as a transparent
#        replacement for their corresponding "ipa" theme package, they are not
#        intended to be used as a replacement for their corresponding "redhat"
#        theme components.
#
#        Finally, if available for a RHEL system (e. g. - RHCS subscription),
#        each "redhat" theme package MUST be used as a transparent replacement
#        for its corresponding "ipa" theme package or "dogtag" theme package.
Obsoletes:        ipa-pki
Conflicts:        redhat-pki

%description
The Dogtag Public Key Infrastructure (PKI) Suite is comprised of the following
six subsystems and a client (for use by a Token Management System):

  * Certificate Authority (CA)
  * Data Recovery Manager (DRM)
  * Online Certificate Status Protocol (OCSP) Manager
  * Registration Authority (RA)
  * Token Key Service (TKS)
  * Token Processing System (TPS)
  * Enterprise Security Client (ESC)

Additionally, it provides a console GUI application used for server and
user/group administration of CA, DRM, OCSP, and TKS, javadocs on portions
of the Dogtag API, as well as various command-line tools used to assist with
a PKI deployment.

To successfully deploy instances of a CA, DRM, OCSP, or TKS,
a Tomcat Web Server must be up and running locally on this machine.

To successfully deploy instances of an RA, or TPS,
an Apache Web Server must be up and running locally on this machine.

To meet the database storage requirements of each CA, DRM, OCSP, TKS, or TPS
instance, a 389 Directory Server must be up and running either locally on
this machine, or remotely over the attached network connection.

To meet the database storage requirements of an RA, an SQLite database will
be created locally on this machine each time a new RA instance is created.

After installation of this package, use the 'pkicreate' and 'pkiremove'
utilities to respectively create and remove PKI instances.

%prep
cat > README <<EOF
This package is just a "meta-package" whose dependencies pull in all of the
packages comprising the Dogtag Public Key Infrastructure (PKI) Suite.
EOF

%install
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc README

%changelog
* Fri Mar  9 2012 Matthew Harmsen <mharmsen@redhat.com> 9.0.10-1
- Bugzilla Bug #796006 - Get DOGTAG_9_BRANCH GIT repository in-sync
  with DOGTAG_9_BRANCH SVN repository . . .

* Thu Jan  5 2012 Matthew Harmsen <mharmsen@redhat.com> 9.0.9-1
- Bugzilla Bug #737761 - Update Dogtag Packages for Fedora 16
  (Update minimum packages to account for NSS bug change in
   Bugzilla Bug #771357 - sslget does not work after FEDORA-2011-17400
   update, breaking FreeIPA install)

* Fri Oct 28 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.8-1
- Bugzilla Bug #749927 - Java class conflicts using Java 7 in Fedora 17
  (rawhide) . . .
- Bugzilla Bug #749945 - Installation error reported during CA, DRM,
  OCSP, and TKS package installation . . .

* Thu Sep 22 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.7-1
- Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . . (mharmsen)
- Bugzilla Bug #699809 - Convert CS to use systemd (alee)

* Mon Sep 12 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-6
- Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . .
- Established MINIMUM package versions based upon platform

* Thu Jul 14 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-5
- Bugzilla Bug #669226 - Remove Legacy Build System
- Updated release of 'tomcatjss' for Fedora 15

* Wed Jul 13 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-4
- Updated release of 'osutil' for Fedora 15
- Updated release of 'jss' and 'jss-javadoc'

* Tue Apr 5 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-3
- Bugzilla Bug #690950 - Update Dogtag Packages for Fedora 15 (beta)
- Bugzilla Bug #693327 - Missing requires: tomcatjss

* Fri Mar 25 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-2
- Bugzilla Bug #690950 - Update Dogtag Packages for Fedora 15 (beta)
- Require "tomcatjss >= 2.1.1" as a build and runtime requirement
  for Fedora 15 and later platforms

* Wed Mar 23 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0 --> Dogtag 9.0.0.
