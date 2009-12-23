Name:           pki-setup
Version:        1.3.0
Release:        6%{?dist}
Summary:        Dogtag Certificate system - PKI Instance Creation and Removal Scripts
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant

Requires:       policycoreutils
%{?fc11:Requires: policycoreutils-python}
%{?fc12:Requires: policycoreutils-python}

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

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
* Wed Dec 23 2009 Kevin Wright <kwright@redhat.com> 1.3.0-6
- Bugzilla Bug #521993 - packaging for Fedora Dogtag
- Removed Requires for all perl packages
- Removed Requires for pki-native-tools
 
* Mon Dec 14 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-5
- Bugzilla Bug #521993 - packaging for Fedora Dogtag
- Bugzilla Bug #529070 -  rpm packaging problems (cannot reinstall correctly) 
- Removed 'with exceptions' from License
- Removed 'Requires: perl >= 5.8.0'

* Mon Dec 7 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-4
- Bugzilla Bug #528556 -  policycoreutils-python (semanage) prerequisite
  missing from rpm
- Added "conditional" support for Fedora 11
- Added "conditional" support for Fedora 12

* Mon Nov 16 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #533518 -  Remove "pkihost" script from pki-setup . . .

* Mon Nov 2 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-2
- Bugzilla Bug #521993 - packaging for Fedora Dogtag
- Take ownership of directories

* Tue Oct 13 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #521993 - packaging for Fedora Dogtag
