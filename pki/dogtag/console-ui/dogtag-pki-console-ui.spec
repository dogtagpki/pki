Name:           dogtag-pki-console-ui
Version:        2.0.0
Release:        1%{?dist}
Summary:        Dogtag Certificate System - PKI Console User Interface
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  jss >= 4.2.6
BuildRequires:  ldapjdk

Requires:       java >= 1:1.6.0
Requires:       jss >= 4.2.6
Requires:       ldapjdk

Provides:       pki-console-ui = %{version}-%{release}

Obsoletes:      pki-console-ui < %{version}-%{release}

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

# NOTE:  The 'Dogtag Certificate System' and 'Red Hat Certificate System'
#        may NOT co-exist on the same system!
#
#        For example, with the advent of EPEL packages, a user may attempt to
#        install a Dogtag Certificate System on a system which already contains
#        a Red Hat Certificate System.  Since the 'dogtag-pki-console-ui' UI
#        package conflicts with the 'redhat-pki-console-ui' UI package,
#        disallow this action by notifying the user that these two packages
#        conflict.  (see Bugzilla Bug #580282 for details)
#
Conflicts:        redhat-pki-console-ui

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag PKI Console User Interface contains the graphical
user interface for the Dogtag PKI Console.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="dogtag" \
    -Dproduct.prefix="pki" \
    -Dproduct="console-ui" \
    -Dversion="%{version}"

%install
rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}
cd %{buildroot}%{_javadir}
ln -s pki-console-theme-%{version}_en.jar pki-console-theme_en.jar

# supply convenience symlink(s) for backwards compatibility
mkdir -p %{buildroot}%{_javadir}/pki
cd %{buildroot}%{_javadir}/pki
ln -s ../pki-console-theme_en.jar cms-theme_en.jar

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_javadir}/*

%changelog
* Tue Aug 10 2010 Matthew Harmsen <mharmsen@redhat.com> 2.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0.
