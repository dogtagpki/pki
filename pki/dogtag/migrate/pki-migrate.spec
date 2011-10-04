Name:           pki-migrate
Version:        9.0.0
Release:        1%{?dist}
Summary:        Dogtag Certificate System - PKI Migration Scripts
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Base

# Suppress automatic 'requires' and 'provisions' of multi-platform 'binaries'
AutoReqProv:    no

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils

Requires:       java >= 1:1.6.0

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

Dogtag PKI Migration Scripts are used to export data from previous
versions of Netscape Certificate Management Systems, iPlanet Certificate
Management Systems, and Dogtag Certificate Systems into a flat-file
which may then be imported into this release of Dogtag Certificate System.

Note that since this utility is platform-independent, it is generally possible
to migrate data from previous PKI deployments originally stored on other
hardware platforms as well as earlier versions of this operating system.

%global _binaries_in_noarch_packages_terminate_build   0

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="migrate" \
    -Dversion="%{version}"

%install
rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}

# remove unwanted files
rm -rf %{buildroot}%{_datadir}/pki/migrate/*/src
rm -rf %{buildroot}%{_datadir}/pki/migrate/80/*.java
rm -rf %{buildroot}%{_datadir}/pki/migrate/TpsTo80/*.java
rm -rf %{buildroot}%{_datadir}/pki/migrate/TpsTo80/Makefile
rm -rf %{buildroot}%{_datadir}/pki/migrate/TpsTo80/*.c

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_datadir}/pki/migrate/*

%changelog
* Fri Nov 19 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0 --> Dogtag 9.0.0.
