Summary:          Dogtag Public Key Infrastructure (PKI) Suite
Name:             dogtag-pki
Version:          1.3.0
Release:          1%{?dist}
# The entire source code is GPLv2 except for 'pki-tps' which is LGPLv2
License:          GPLv2 and LGPLv2
URL:              http://pki.fedoraproject.org/
Group:            System Environment/Daemons
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:        noarch

# Make certain that this 'meta' package requires all Dogtag PKI UI packages
Requires:         dogtag-pki-common-ui
Requires:         dogtag-pki-console-ui
Requires:         dogtag-pki-ca-ui
Requires:         dogtag-pki-kra-ui
Requires:         dogtag-pki-ocsp-ui
Requires:         dogtag-pki-ra-ui
Requires:         dogtag-pki-tks-ui
Requires:         dogtag-pki-tps-ui
# Make certain that this 'meta' package requires all Dogtag PKI subsystems
Requires:         pki-ca
Requires:         pki-kra
Requires:         pki-ocsp
Requires:         pki-ra
Requires:         pki-tks
Requires:         pki-tps
# Make certain that this 'meta' package requires all Dogtag PKI clients
Requires:         esc
# Make certain that this 'meta' package requires all Dogtag PKI javadocs
Requires:         pki-common-javadoc
Requires:         pki-java-tools-javadoc
Requires:         pki-util-javadoc

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
* Thu Feb 11 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-1
- Initial build.

