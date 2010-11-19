Name:           pki-setup
Version:        2.0.0
Release:        1%{?dist}
Summary:        Dogtag Certificate system - PKI Instance Creation and Removal Scripts
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant

Requires:       perl-Crypt-SSLeay
Requires:       policycoreutils
%{?fc11:Requires: policycoreutils-python}
%{?fc12:Requires: policycoreutils-python}

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

# This package provides and uses a PRIVATE Perl module (pkicommon.pm).
# RPM erroneously believes there should be a requires perl(pkicommon)
# from the public perl library path. Use the documented macros to
# correct RPM's incorrect automatic dependency generation.
%filter_from_requires /perl(pkicommon)/d
%filter_setup

%description
Public Key Infrastructure (PKI) setup scripts used to create and remove
instances from Dogtag PKI deployments.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="setup" \
    -Dversion="%{version}"

%install
rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}

## remove unwanted files
rm -rf %{buildroot}%{_bindir}/pkihost

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_bindir}/*
%{_datadir}/pki/

%changelog
* Tue Aug 10 2010 Matthew Harmsen <mharmsen@redhat.com> 2.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0.
