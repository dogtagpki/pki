Summary:          Dogtag Public Key Infrastructure (PKI) Suite
Name:             dogtag-pki
Version:          9.0.0
Release:          1%{?dist}
# The entire source code is GPLv2 except for 'pki-tps' which is LGPLv2
License:          GPLv2 and LGPLv2
URL:              http://pki.fedoraproject.org/
Group:            System Environment/Daemons
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:        noarch

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI UI packages
Requires:         dogtag-pki-common-ui >= 9.0.0
Requires:         dogtag-pki-console-ui >= 9.0.0
Requires:         dogtag-pki-ca-ui >= 9.0.0
Requires:         dogtag-pki-kra-ui >= 9.0.0
Requires:         dogtag-pki-ocsp-ui >= 9.0.0
Requires:         dogtag-pki-ra-ui >= 9.0.0
Requires:         dogtag-pki-tks-ui >= 9.0.0
Requires:         dogtag-pki-tps-ui >= 9.0.0

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI subsystems
Requires:         pki-ca >= 9.0.0
Requires:         pki-kra >= 9.0.0
Requires:         pki-ocsp >= 9.0.0
Requires:         pki-ra >= 9.0.0
Requires:         pki-tks >= 9.0.0
Requires:         pki-tps >= 9.0.0

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI tools
Requires:         pki-java-tools >= 9.0.0
Requires:         pki-native-tools >= 9.0.0

# Make certain that this 'meta' package requires the latest version(s)
# of Dogtag PKI console
Requires:         pki-console >= 9.0.0

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI clients
Requires:         esc >= 9.0.0

# Make certain that this 'meta' package requires the latest version(s)
# of ALL Dogtag PKI javadocs
Requires:         pki-common-javadoc >= 9.0.0
Requires:         pki-java-tools-javadoc >= 9.0.0
Requires:         pki-util-javadoc >= 9.0.0

# Make certain that this 'meta' package requires the latest version(s)
# of ALL top-level Dogtag PKI supporting packages
Requires:         osutil >= 9.0.0
Requires:         pki-common >= 9.0.0
Requires:         pki-selinux >= 9.0.0
Requires:         pki-setup >= 9.0.0
Requires:         pki-silent >= 9.0.0
Requires:         pki-symkey >= 9.0.0
Requires:         pki-util >= 9.0.0
Requires:         tomcatjss >= 1.2.1

# NOTE:  Several PKI packages require a "virtual" UI component.  These
#        "virtual" UI components are "Provided" by various UI "flavors"
#        including "dogtag", "redhat", and "null".  Consequently,
#        all "dogtag", "redhat", and "null" UI components MUST be
#        mutually exclusive!
Conflicts:        ipa-pki
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
# empty

%build
# empty

%install
rm -rf %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)

%changelog
* Fri Nov 19 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0 --> Dogtag 9.0.0.
