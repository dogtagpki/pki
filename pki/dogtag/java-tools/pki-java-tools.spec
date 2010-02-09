Name:           pki-java-tools
Version:        1.3.1
Release:        1%{?dist}
Summary:        Dogtag Certificate System - PKI Java-Based Tools
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  jss >= 4.2.6
BuildRequires:  osutil
BuildRequires:  pki-util

Requires:       java >= 1:1.6.0
Requires:       pki-native-tools
Requires:       pki-util

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

These platform-independent PKI executables are used to help make
Dogtag Certificate System into a more complete and robust PKI solution.

%package javadoc
Summary:    Dogtag Certificate System - PKI Java-Based Tools Javadocs
Group:      Documentation

Requires:   %{name} = %{version}-%{release}

%description javadoc
Dogtag Certificate System - PKI Java-Based Tools Javadocs

This documentation pertains exclusively to version %{version} of
the Dogtag PKI Java-Based Tools.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="java-tools" \
    -Dversion="%{version}"

%install
rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}
cd %{buildroot}%{_javadir}
mv pkitools.jar pkitools-%{version}.jar
ln -s pkitools-%{version}.jar pkitools.jar
rm -rf %{buildroot}%{_datadir}/pki

# supply convenience symlink(s) for backwards compatibility
mkdir -p %{buildroot}%{_javadir}/pki
cd %{buildroot}%{_javadir}/pki
ln -s ../pkitools.jar cstools.jar
cd %{buildroot}%{_javadir}
ln -s pkitools.jar cstools.jar

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_bindir}/*
%{_javadir}/*

%files javadoc
%defattr(0644,root,root,0755)
%{_javadocdir}/%{name}-%{version}/

%changelog
* Mon Feb 8 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.1-1
- Bugzilla Bug #562986 -  Supply convenience symlink(s) for backwards
  compatibility (rename jar files as appropriate)

* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-4
- Removed 'with exceptions' from License

* Tue Nov 24 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #521995 - Packaging for Fedora Dogtag PKI
- Use "_javadir" macro when appropriate
- Move jar file to top-level

* Mon Nov 2 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-2
- Bugzilla Bug #521995 - Packaging for Fedora Dogtag PKI
- Take ownership of directories

* Tue Oct 13 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #521995 - Packaging for Fedora Dogtag PKI
