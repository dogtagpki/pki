Name:           dogtag-pki-common-ui
Version:        1.3.0
Release:        1%{?dist}
Summary:        Dogtag Certificate System - PKI Common Framework User Interface
URL:            http://pki.fedoraproject.org/
License:        GPLv2 with exceptions
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant

Requires:       bash >= 3.0

Provides:       pki-common-ui = %{version}.%{release}

Obsoletes:      pki-common-ui < %{version}.%{release}

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag PKI Common Framework User Interface contains the graphical
user interface for the Dogtag PKI Common Framework.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="dogtag" \
    -Dproduct.prefix="pki" \
    -Dproduct="common-ui" \
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
* Tue Oct 13 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #522204 - Packaging for Fedora Dogtag PKI
