Name:           pki-native-tools
Version:        1.3.0
Release:        2%{?dist}
Summary:        Dogtag Certificate System - Native Tools
URL:            http://pki.fedoraproject.org/
License:        GPLv2 with exceptions
Group:          System Environment/Shells

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  bash
BuildRequires:  cyrus-sasl-devel
BuildRequires:  mozldap-devel
BuildRequires:  nspr-devel >= 4.6.99
BuildRequires:  nss-devel >= 3.12.3.99
BuildRequires:  svrcore-devel

Requires:       mozldap-tools
Requires:       nss >= 3.12.3.99
Requires:       nss-tools >= 3.12.3.99
Requires:       perl >= 5.8.0

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

These platform-dependent PKI executables are used to help make
Dogtag Certificate System into a more complete and robust PKI solution.

%prep

%setup -q -n %{name}-%{version}

%build
%configure \
%ifarch ppc64 s390x sparc64 x86_64
    --enable-64bit \
%endif
    --libdir=%{_libdir}
make

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

## rearrange files to be in the desired native packaging layout
./setup_package %{buildroot} pki native-tools %{version} %{release} %{buildroot}/opt

## remove unwanted files
rm -rf %{buildroot}/opt
rm -rf %{buildroot}/usr/libexec
rm -rf %{buildroot}%{_datadir}/pki/templates

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE doc/README
%{_bindir}/*
%{_libdir}/pki
%{_datadir}/pki

%changelog
* Mon Nov 2 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-2
- Bugzilla Bug #522895 -  New Package for Dogtag PKI: native-tools
- Prepended directory path in front of setup_package
* Mon Oct 12 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-1
- Bugzilla Bug #522895 -  New Package for Dogtag PKI: native-tools
