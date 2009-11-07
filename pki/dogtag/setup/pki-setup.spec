Name:           pki-setup
Version:        1.3.0
Release:        2%{?dist}
Summary:        Dogtag Certificate system - PKI Instance Creation and Removal Scripts
URL:            http://pki.fedoraproject.org/
License:        GPLv2 with exceptions
Group:          System Environment/Shells

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant

Requires:       perl >= 5.8.0
Requires:       perl-Crypt-SSLeay
Requires:       perl-XML-LibXML
Requires:       perl-XML-SAX
Requires:       perl-libwww-perl
Requires:       pki-native-tools
Requires:       policycoreutils

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

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_bindir}/*
%{_datadir}/pki/scripts/

%changelog
* Mon Nov 2 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-2
- Bugzilla Bug #521993 - packaging for Fedora Dogtag
- Take ownership of directories
* Tue Oct 13 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #521993 - packaging for Fedora Dogtag
