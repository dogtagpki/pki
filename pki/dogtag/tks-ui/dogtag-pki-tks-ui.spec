Name:           dogtag-pki-tks-ui
Version:        1.3.0
Release:        1%{?dist}
Summary:        Dogtag Certificate System - Token Key Service User Interface
URL:            http://pki.fedoraproject.org/
License:        GPLv2 with exceptions
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant

Requires:       bash

Provides:       pki-tks-ui = %{version}-%{release}

Obsoletes:      pki-tks-ui < %{version}-%{release}

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Token Key Service User Interface contains the graphical
user interface for the Dogtag Token Key Service.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="dogtag" \
    -Dproduct.prefix="pki" \
    -Dproduct="tks-ui" \
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
%{_datadir}/pki/*

%changelog
* Fri Oct 16 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #X  - Packaging for Fedora Dogtag
