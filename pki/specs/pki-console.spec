###############################################################################
###                       P A C K A G E   H E A D E R                       ###
###############################################################################

Name:             pki-console
Version:          9.0.0
Release:          1%{?dist}
Summary:          Certificate System - PKI Console
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Base

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake
BuildRequires:    idm-console-framework
BuildRequires:    java-devel >= 1:1.6.0
BuildRequires:    jpackage-utils
BuildRequires:    jss >= 4.2.6
BuildRequires:    ldapjdk
BuildRequires:    pki-util

Requires:         idm-console-framework
Requires:         java >= 1:1.6.0
Requires:         jss >= 4.2.6
Requires:         ldapjdk
Requires:         pki-console-theme

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Certificate System (CS) is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The PKI Console is a java application used to administer CS.

For deployment purposes, a PKI Console requires ONE AND ONLY ONE of the
following "Mutually-Exclusive" PKI Theme packages:

  * dogtag-pki-theme (Dogtag Certificate System deployments)
  * redhat-pki-theme (Red Hat Certificate System deployments)


%prep


%setup -q


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVAR_INSTALL_DIR:PATH=/var -DBUILD_PKI_CONSOLE:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot}


%files
%defattr(-,root,root,-)
%doc base/console/LICENSE
%{_bindir}/pkiconsole
%{_javadir}/pki/


%changelog
* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision. (kwright@redhat.com & mharmsen@redhat.com)

