Name:           pki-console
Version:        1.3.0
Release:        4%{?dist}
Summary:        Dogtag Certificate System - PKI Console
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  idm-console-framework
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  jss >= 4.2.6
BuildRequires:  ldapjdk
BuildRequires:  pki-util

Requires:       idm-console-framework
Requires:       java >= 1:1.6.0
Requires:       jss >= 4.2.6
Requires:       ldapjdk
Requires:       pki-console-ui

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The PKI Console is a java application used to administer
Dogtag Certificate System.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="console" \
    -Dversion="%{version}"

%install
rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}
cd %{buildroot}%{_javadir}/pki
ln -s console-cms-%{version}.jar console-cms.jar
ln -s console-cms-%{version}_en.jar console-cms_en.jar

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_bindir}/pkiconsole
%{_javadir}/pki/

%changelog
* Fri Jan 15 2010 Kevin Wright <kwright@redhat.com> 1.3.0-4
- removed BuildRequires dogtag-pki-console-ui

* Wed Jan 6 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #553487 - Review Request: pki-console - The Dogtag PKI Console
- Take ownership of directories

* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-2
- Removed 'with exceptions' from License

* Thu Oct 15 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Packaging for Fedora Dogtag
