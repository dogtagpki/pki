Summary:          Public Key Infrastructure (PKI) Packages for IPA
Name:             ipa-pki
Version:          2.0.0
Release:          1%{?dist}
# The entire source code is GPLv2
License:          GPLv2
URL:              http://pki.fedoraproject.org/
Group:            System Environment/Daemons
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)
BuildArch:        noarch

# Make certain that this 'meta' package requires the latest version(s)
# of relevant PKI UI packages
Requires:         null-pki-common-ui
Requires:         null-pki-ca-ui

# Make certain that this 'meta' package requires the latest version(s)
# of relevant PKI subsystem packages
Requires:         pki-ca

# Make certain that this 'meta' package requires the latest version(s)
# of relevant PKI tools
Requires:         pki-java-tools >= 9.0.0
Requires:         pki-native-tools >= 9.0.0

# Make certain that this 'meta' package requires the latest version(s)
# of relevant top-level PKI javadocs
Requires:         pki-common-javadoc
Requires:         pki-java-tools-javadoc
Requires:         pki-util-javadoc

# Make certain that this 'meta' package requires the latest version(s)
# of relevant top-level PKI supporting packages
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
Conflicts:        dogtag-pki
Conflicts:        redhat-pki

%description
This Public Key Infrastructure (PKI) Suite is comprised of the following
subsystems:

  * Certificate Authority (CA)

Additionally, it provides javadocs on portions of the API, as well as various
command-line tools used to assist with an IPA deployment.

To successfully deploy instances of a CA,
a Tomcat Web Server must be up and running locally on this machine.

To meet the database storage requirements of each CA
instance, a 389 Directory Server must be up and running either locally on
this machine, or remotely over the attached network connection.

After installation of this package, IPA utilizes the 'pkicreate' and
'pkiremove' utilities to respectively create and remove PKI instances.

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
* Fri Sep 17 2010 Matthew Harmsen <mharmsen@redhat.com> 2.0.0-1
- Initial revision.
