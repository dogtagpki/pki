%if 0%{?rhel} || 0%{?fedora} < 24
%global with_python3 0
%else
%global with_python3 1
%endif

Summary:          Dogtag Public Key Infrastructure (PKI) Suite
Name:             dogtag-pki
Version:          10.3.5
Release:          0.1%{?dist}
# The entire source code is GPLv2 except for 'pki-tps' which is LGPLv2
License:          GPLv2 and LGPLv2
URL:              http://pki.fedoraproject.org/
Group:            System Environment/Daemons
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:        noarch

%define dogtag_pki_theme_version   %{version}
%define esc_version                1.1.0
# NOTE:  The following package versions are TLS compliant:
%if 0%{?rhel}
%define pki_core_rhel_version      10.3.3
%define pki_core_rhcs_version      %{version}
%else
%define pki_core_version           %{version}
%endif
%define pki_console_version        %{version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI theme packages
Requires:         dogtag-pki-server-theme >= %{dogtag_pki_theme_version}
Requires:         dogtag-pki-console-theme >= %{dogtag_pki_theme_version}

%if 0%{?rhel}
# Make certain that this 'meta' package requires the latest version(s)
# of ALL Red Hat PKI core (RHEL) packages
Requires:         pki-base >= %{pki_core_rhel_version}
Requires:         pki-base-java >= %{pki_core_rhel_version}
%if 0%{?with_python3}
Requires:         pki-base-python3 >= %{pki_core_rhel_version}
%endif
Requires:         pki-ca >= %{pki_core_rhel_version}
Requires:         pki-kra >= %{pki_core_rhel_version}
Requires:         pki-server >= %{pki_core_rhel_version}
Requires:         pki-symkey >= %{pki_core_rhel_version}
Requires:         pki-tools >= %{pki_core_rhel_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Red Hat PKI core (RHCS) packages
Requires:         pki-ocsp >= %{pki_core_rhcs_version}
Requires:         pki-tks >= %{pki_core_rhcs_version}
Requires:         pki-tps >= %{pki_core_rhcs_version}
%else
# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI core packages
Requires:         pki-base >= %{pki_core_version}
Requires:         pki-base-java >= %{pki_core_version}
%if 0%{?with_python3}
Requires:         pki-base-python3 >= %{pki_core_version}
%endif
Requires:         pki-ca >= %{pki_core_version}
Requires:         pki-kra >= %{pki_core_version}
Requires:         pki-ocsp >= %{pki_core_version}
Requires:         pki-server >= %{pki_core_version}
Requires:         pki-symkey >= %{pki_core_version}
Requires:         pki-tks >= %{pki_core_version}
Requires:         pki-tools >= %{pki_core_version}
Requires:         pki-tps >= %{pki_core_version}
%endif

# Make certain that this 'meta' package requires the latest version(s)
# of Dogtag PKI console
Requires:         pki-console >= %{pki_console_version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI clients
Requires:         esc >= %{esc_version}

%description
The Dogtag Public Key Infrastructure (PKI) Suite is comprised of the following
five subsystems and a client (for use by a Token Management System):

  * Certificate Authority (CA)
  * Key Recovery Authority (KRA)
  * Online Certificate Status Protocol (OCSP) Manager
  * Token Key Service (TKS)
  * Token Processing System (TPS)
  * Enterprise Security Client (ESC)

Additionally, it provides a console GUI application used for server and
user/group administration of CA, KRA, OCSP, and TKS, as well as various
command-line tools used to assist with a PKI deployment.

To successfully deploy instances of a CA, KRA, OCSP, TKS, or TPS,
a Tomcat Web Server must be up and running locally on this machine.

To meet the database storage requirements of each CA, KRA, OCSP, TKS, or TPS
instance, a 389 Directory Server must be up and running either locally on
this machine, or remotely over the attached network connection.

Finally, although they are no longer supplied by this 'meta' package,
javadocs are available for both JSS (jss-javadoc) and portions of
the Dogtag PKI API (pki-javadoc).

NOTE:  As a convenience for standalone deployments, this 'dogtag-pki'
       top-level meta package supplies Dogtag themes for use by the
       certificate server packages:

         * dogtag-pki-theme (Dogtag Certificate System deployments)
           * dogtag-pki-server-theme
           * dogtag-pki-console-theme

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
* Tue Jul  5 2016 Dogtag Team <pki-devel@redhat.com> 10.3.5-0.1
- Updated version number to 10.3.5-0.1

* Tue Jun 21 2016 Dogtag Team <pki-devel@redhat.com> 10.3.4-0.1
- Updated version number to 10.3.4-0.1

* Mon Jun 20 2016 Dogtag Team <pki-devel@redhat.com> 10.3.3-1
- Updated release number to 10.3.3-1

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.3-0.1
- Updated version number to 10.3.3-0.1

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-2
- Provided cleaner runtime dependency separation

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-1
- Updated version number to 10.3.2-1

* Wed May 18 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-0.1
- Updated version number to 10.3.2-0.1

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

* Fri Apr 24 2015 Dogtag Team <pki-devel@redhat.com> 10.2.4-0.2
- Restored requirement for 'jss-javadocs'

* Thu Apr 23 2015 Dogtag Team <pki-devel@redhat.com> 10.2.4-0.1
- Updated version number to 10.2.4-0.1

* Thu Apr 23 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-1
- Update release number for release build
- Remove tomcatjss, jss and selinux requirements as these should
  be handled by pki packages

* Thu Apr  9 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-0.1
- Reverted version number back to 10.2.3-0.1
- Added support for Tomcat 8.

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

* Tue Dec 16 2014 Matthew Harmsen <mharmsen@redhat.com> - 10.2.1-0.4
- PKI TRAC Ticket #1205 - Outdated selinux-policy dependency.

* Mon Nov 24 2014 Christina Fu <cfu@redhat.com> 10.2.1-0.2
- Ticket 1198 Bugzilla 1158410 add TLS range support to server.xml by default and upgrade (cfu)
- Make dependencies comply with TLS changes (mharmsen)
- up the release number to 0.2

* Fri Oct 24 2014 Dogtag Team <pki-devel@redhat.com> 10.2.1-0.1
- Updated version number to 10.2.1-0.1.

* Tue Sep  9 2014 Matthew Harmsen <mharmsen@redhat.com> 10.2.0-3
- PKI TRAC Ticket #1136 - Remove ipa-pki-theme component
- Remove 'ca-ui', 'kra-ui', 'ocsp-ui', 'ra-ui', 'tks-ui', and 'tps-ui'
  directories
- Consolidate 'pki-core' packages

* Sun Sep  7 2014 Dogtag Team <pki-devel@redhat.com> 10.2.0-2
- Updated release number for release build
- Revised dependencies
- Removed RA references
- Changed Apache TPS references to Tomcat TPS references

* Wed Sep  3 2014 Dogtag Team <pki-devel@redhat.com> 10.2.0-1
- Update release number for release build

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 10.1.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Fri Nov 22 2013 Dogtag Team <pki-devel@redhat.com> 10.2.0-0.1
- Updated version number to 10.2.0-0.1.

* Fri Nov 15 2013 Ade Lee <alee@redhat.com> 10.1.0-1
- Trac Ticket 788 - Clean up spec files
- Update release number for release build

* Sun Nov 10 2013 Ade Lee <alee@redhat.com> 10.1.0-0.2
- Change release number for beta build

* Tue May 7 2013 Ade Lee <alee@redhat.com> 10.1.0-0.1
- Change release number for 10.1 development

* Fri Apr 26 2013 Ade Lee <alee@redhat.com> 10.0.2-1
- Change release number for official release.

* Wed Mar 27 2013 Endi S. Dewata <edewata@redhat.com> 10.0.2-0.1
- Updated version number to 10.0.2-0.1.

* Mon Mar  4 2013 Matthew Harmsen <mharmsen@redhat.com> 10.0.1-2
- TRAC Ticket #517 - Clean up theme dependencies
- TRAC Ticket #518 - Remove UI dependencies from pkispawn . . .

* Tue Jan 15 2013 Ade Lee <alee@rdhat.com> 10.0.1-1
- Update for release of 10.0.1 for pki-core

* Fri Jan  4 2013 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-2
- TRAC Ticket #469 - Dogtag 10: Fix tomcatjss issue in pki-core.spec and
  dogtag-pki.spec . . .
- TRAC Ticket #468 - pkispawn throws exception

* Fri Dec 7 2012 Ade Lee <alee@redhat.com> 10.0.0-1
- Update to official release for rc1

* Mon Nov 12 2012 Ade Lee <alee@redhat.com> 10.0.0-0.16.b3
- Update release to b3

* Fri Nov 9 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.15.b2
- Removed Dogtag CA, KRA, OCSP, TKS theme packages.

* Thu Nov 8 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.14.b2
- Renamed dogtag-pki-common-theme to dogtag-pki-server-theme.

* Mon Oct 29 2012 Ade Lee <alee@redhat.com> 10.0.0-0.13.b2
- Update release to b2

* Tue Oct 23 2012 Ade Lee <alee@redhat.com> 10.0.0-0.12.b1
- Remove pki-selinux from f18 build

* Fri Oct 12 2012 Ade Lee <alee@redhat.com> 10.0.0-0.11.b1
- Update tomcatjss version

* Mon Oct 8 2012 Ade Lee <alee@redhat.com> 10.0.0-0.10.b1
- Update release to b1

* Fri Oct 5 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.10.a2
- Merged pki-silent into pki-server.

* Mon Oct 1 2012 Ade Lee <alee@redhat.com> 10.0.0-0.9.a2
- Update release to a2

* Mon Sep 24 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.9.a1
- Merged pki-setup into pki-server
- Fixed pki-javadoc dependency

* Wed Aug 22 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.8.a1
- Replaced pki-native-tools and pki-java-tools with pki-tools

* Wed Aug 22 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.7.a1
- Replaced pki-util, pki-deploy, pki-common with pki-base and pki-server

* Tue Aug 14 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.6.a1
- Updated release of 'tomcatjss' to rely on Tomcat 7 for Fedora 17
- Added 'pki-deploy' runtime dependency

* Thu Jun 14 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.5.a1
- Updated release of 'tomcatjss' to rely on Tomcat 7 for Fedora 18

* Thu Apr  5 2012 Christina Fu <cfu@redhat.com> 10.0.0-0.4.a1
- Bug 745278 - [RFE] ECC encryption keys cannot be archived

* Wed Feb 22 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.3.a1
- Removed dependency on OSUtil.

* Wed Feb 22 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.2.a1
- Added dependency on Apache Commons Codec.

* Wed Feb  1 2012 Nathan Kinder <nkinder@redhat.com> 10.0.0-0.1.a1
- Updated package version number

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
