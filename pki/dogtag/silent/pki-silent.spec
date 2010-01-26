Name:           pki-silent
Version:        1.3.1
Release:        1%{?dist}
Summary:        Dogtag Certificate System - Silent Installer
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  jss >= 4.2.6
BuildRequires:  pki-common
BuildRequires:  pki-util

Requires:       java >= 1:1.6.0
Requires:       pki-common

%if 0%{?rhel}
#rhel has no java on ppc
ExcludeArch:    ppc
%endif

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Silent Installer may be used to "automatically" configure
the following Dogtag PKI subsystems in a non-graphical (batch) fashion
including:

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
    -Dproduct="silent" \
    -Dversion="%{version}"

%install
rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}
cd %{buildroot}%{_javadir}
mv silent.jar silent-%{version}.jar
ln -s silent-%{version}.jar silent.jar

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_bindir}/*
%{_javadir}/*
%{_datadir}/pki/

%changelog
* Mon Jan 25 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.1-1
- Bugzilla Bug #558670 -  Update pki-silent templates to work with
  pki component registries

* Wed Jan 6 2010 Kevin Wright <kwright@redhat.com> 1.3.0-5
- no java on rhel ppc

* Mon Dec 14 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-4
- Bugzilla Bug #521996 - Packaging for Fedora Dogtag PKI
- Removed 'with exceptions' from License

* Tue Nov 24 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #521996 - Packaging for Fedora Dogtag PKI
- Use "_javadir" macro when appropriate

* Mon Nov 2 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-2
- Bugzilla Bug #521996 - Packaging for Fedora Dogtag PKI
- Take ownership of directories

* Tue Oct 13 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #521996 - Packaging for Fedora Dogtag PKI
