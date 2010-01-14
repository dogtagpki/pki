Name:           dogtag-pki-ra-ui
Version:        1.3.0
Release:        4%{?dist}
Summary:        Dogtag Certificate System - Registration Authority User Interface
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant

Provides:       pki-ra-ui = %{version}-%{release}

Obsoletes:      pki-ra-ui < %{version}-%{release}

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Registration Authority User Interface contains the graphical
user interface for the Dogtag Registration Authority.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="dogtag" \
    -Dproduct.prefix="pki" \
    -Dproduct="ra-ui" \
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
* Thu Jan 14 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-4
- Bugzilla Bug #553848 - New Package for Dogtag PKI: dogtag-pki-ra-ui
- Removed "Requires:  bash"

* Wed Jan 6 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #553848 - New Package for Dogtag PKI: dogtag-pki-ra-ui
- Take ownership of directories

* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-2
- Removed 'with exceptions' from License

* Fri Oct 16 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Fedora Packaging Changes
