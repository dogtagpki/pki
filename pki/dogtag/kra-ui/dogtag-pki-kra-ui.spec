Name:           dogtag-pki-kra-ui
Version:        2.0.0
Release:        1%{?dist}
Summary:        Dogtag Certificate System - Data Recovery Authority User Interface
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant

Provides:       pki-kra-ui = %{version}-%{release}

Obsoletes:      pki-kra-ui < %{version}-%{release}

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

# NOTE:  The 'Dogtag Certificate System' and 'Red Hat Certificate System'
#        may NOT co-exist on the same system!
#
#        For example, with the advent of EPEL packages, a user may attempt to
#        install a Dogtag Certificate System on a system which already contains
#        a Red Hat Certificate System.  Since the 'dogtag-pki-kra-ui' UI
#        package conflicts with the 'redhat-pki-kra-ui' UI package,
#        disallow this action by notifying the user that these two packages
#        conflict.  (see Bugzilla Bug #580282 for details)
#
Conflicts:        redhat-pki-kra-ui

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Data Recovery Authority User Interface contains the graphical
user interface for the Dogtag Data Recovery Manager.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="dogtag" \
    -Dproduct.prefix="pki" \
    -Dproduct="kra-ui" \
    -Dversion="%{version}"

%install
rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_datadir}/pki/

%changelog
* Tue Aug 10 2010 Matthew Harmsen <mharmsen@redhat.com> 2.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0.
