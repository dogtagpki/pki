Summary:          Dogtag Public Key Infrastructure (PKI) Suite
Name:             dogtag-pki
Version:          9.0.0
Release:          2%{?dist}
# The entire source code is GPLv2 except for 'pki-tps' which is LGPLv2
License:          GPLv2 and LGPLv2
URL:              http://pki.fedoraproject.org/
Group:            System Environment/Daemons
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:        noarch

# Make certain that this 'meta' package requires the latest version(s)
# of ALL top-level Dogtag PKI support packages
Requires:         jss >= 4.2.6-15
Requires:         osutil >= 2.0.0
%if 0%{?fedora} >= 15
BuildRequires:    tomcatjss >= 2.1.1
%else
BuildRequires:    tomcatjss >= 2.0.0
%endif

# Make certain that this 'meta' package requires the latest version(s)
# of ALL top-level Dogtag PKI support javadocs
Requires:         jss-javadoc >= 4.2.6-15

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI theme packages
Requires:         dogtag-pki-ca-theme >= 9.0.0
Requires:         dogtag-pki-common-theme >= 9.0.0
Requires:         dogtag-pki-console-theme >= 9.0.0
Requires:         dogtag-pki-kra-theme >= 9.0.0
Requires:         dogtag-pki-ocsp-theme >= 9.0.0
Requires:         dogtag-pki-ra-theme >= 9.0.0
Requires:         dogtag-pki-tks-theme >= 9.0.0
Requires:         dogtag-pki-tps-theme >= 9.0.0

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI core packages
Requires:         pki-ca >= 9.0.0
Requires:         pki-common >= 9.0.0
Requires:         pki-java-tools >= 9.0.0
Requires:         pki-native-tools >= 9.0.0
Requires:         pki-selinux >= 9.0.0
Requires:         pki-setup >= 9.0.0
Requires:         pki-silent >= 9.0.0
Requires:         pki-symkey >= 9.0.0
Requires:         pki-util >= 9.0.0

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI core javadocs
Requires:         pki-common-javadoc >= 9.0.0
Requires:         pki-java-tools-javadoc >= 9.0.0
Requires:         pki-util-javadoc >= 9.0.0

# Make certain that this 'meta' package requires the latest version(s)
# of ALL other Dogtag PKI subsystems
Requires:         pki-kra >= 9.0.0
Requires:         pki-ocsp >= 9.0.0
Requires:         pki-ra >= 9.0.0
Requires:         pki-tks >= 9.0.0
Requires:         pki-tps >= 9.0.0

# Make certain that this 'meta' package requires the latest version(s)
# of Dogtag PKI console
Requires:         pki-console >= 9.0.0

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI clients
Requires:         esc >= 1.1.0

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
* Fri Mar 25 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-2
- Bugzilla Bug #690950 - Update Dogtag Packages for Fedora 15 (beta)
- Require "tomcatjss >= 2.1.1" as a build and runtime requirement
  for Fedora 15 and later platforms

* Wed Mar 23 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0 --> Dogtag 9.0.0.
