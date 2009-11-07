Name:           dogtag-pki-ca-ui
Version:        1.3.0
Release:        2%{?dist}
Summary:        Dogtag Certificate System - Certificate Authority User Interface
URL:            http://pki.fedoraproject.org/
License:        GPLv2 with exceptions
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant

Requires:       bash

Provides:       pki-ca-ui = %{version}-%{release}

Obsoletes:      pki-ca-ui < %{version}-%{release}

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Certificate Authority User Interface contains the graphical
user interface for the Dogtag Certificate Authority.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="dogtag" \
    -Dproduct.prefix="pki" \
    -Dproduct="ca-ui" \
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
* Mon Nov 2 2009 Ade Lee <alee@redhat.com> 1.3.0-2
- Bugzilla Bug #522208 - Packaging for Fedora Dogtag
- Take ownership of directories
* Tue Oct 13 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #522208 - Packaging for Fedora Dogtag
