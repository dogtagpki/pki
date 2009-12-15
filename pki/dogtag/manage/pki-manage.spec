Name:           pki-manage
Version:        1.3.0
Release:        2%{?dist}
Summary:        Dogtag Certificate System - PKI Uninstall Scripts
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Shells

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant

Requires:       perl >= 5.8.0

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

Dogtag PKI Uninstall Scripts are required to remove
Dogtag PKI subsystems including:

    the Dogtag Certificate Authority,
    the Dogtag Data Recovery Manager,
    the Dogtag Online Certificate Status Protocol Manager,
    the Dogtag Registration Authority,
    the Dogtag Token Key Service, and/or
    the Dogtag Token Processing System.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="manage" \
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
%{_bindir}/*

%changelog
* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-2
- Removed 'with exceptions' from License

* Fri Oct 16 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Packaging for Fedora Dogtag PKI
