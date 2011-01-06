###############################################################################
###                       P A C K A G E   H E A D E R                       ###
###############################################################################

Name:             pki-tps
Version:          9.0.0
Release:          1%{?dist}
Summary:          Certificate System - Token Processing System
URL:              http://pki.fedoraproject.org/
License:          LGPLv2
Group:            System Environment/Daemons

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake
BuildRequires:    apr-devel
BuildRequires:    apr-util-devel
BuildRequires:    cyrus-sasl-devel
BuildRequires:    httpd-devel >= 2.2.3
BuildRequires:    mozldap-devel
BuildRequires:    nspr-devel >= 4.6.99
BuildRequires:    nss-devel >= 3.12.3.99
BuildRequires:    pcre-devel
BuildRequires:    svrcore-devel
BuildRequires:    zlib
BuildRequires:    zlib-devel

Requires:         mod_nss >= 1.0.8
Requires:         mod_perl >= 1.99_16
Requires:         mod_revocator >= 1.0.3
Requires:         mozldap >= 6.0.2
Requires:         pki-native-tools
Requires:         pki-selinux
Requires:         pki-setup
Requires:         pki-tps-theme
Requires(post):   chkconfig
Requires(preun):  chkconfig
Requires(preun):  initscripts
Requires(postun): initscripts

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%global overview                                                          \
Certificate System (CS) is an enterprise software system designed         \
to manage enterprise Public Key Infrastructure (PKI) deployments.         \
                                                                          \
The Token Processing System (TPS) is an optional PKI subsystem that acts  \
as a Registration Authority (RA) for authenticating and processing        \
enrollment requests, PIN reset requests, and formatting requests from     \
the Enterprise Security Client (ESC).                                     \
                                                                          \
TPS is designed to communicate with tokens that conform to                \
Global Platform's Open Platform Specification.                            \
                                                                          \
TPS communicates over SSL with various PKI backend subsystems (including  \
the Certificate Authority (CA), the Data Recovery Manager (DRM), and the  \
Token Key Service (TKS)) to fulfill the user's requests.                  \
                                                                          \
TPS also interacts with the token database, an LDAP server that stores    \
information about individual tokens.                                      \
                                                                          \
For deployment purposes, a TPS requires the following components from the \
PKI Core package:                                                         \
                                                                          \
  * pki-setup                                                             \
  * pki-native-tools                                                      \
  * pki-selinux                                                           \
                                                                          \
and can also make use of the following optional components from the       \
PKI CORE package:                                                         \
                                                                          \
  * pki-silent                                                            \
                                                                          \
Additionally, Certificate System requires ONE AND ONLY ONE of the         \
following "Mutually-Exclusive" PKI Theme packages:                        \
                                                                          \
  * dogtag-pki-theme (Dogtag Certificate System deployments)              \
  * redhat-pki-theme (Red Hat Certificate System deployments)             \
                                                                          \
%{nil}

%description %{overview}


%package devel
Group:            Development/Libraries
Summary:          Dogtag Certificate System - Token Processing System Library Symlinks

Requires:         %{name} = %{version}-%{release}

%description devel
This package contains symlinks to the Certificate System (CS)
Token Processing System (TPS) library files required to link executables.


==================================
||  ABOUT "CERTIFICATE SYSTEM"  ||
================================== 
${overview}


%prep


%setup -q -n %{name}-%{version}

cat << \EOF > %{name}-prov
#!/bin/sh
%{__perl_provides} $* |\
sed -e '/perl(PKI.*)/d' -e '/perl(Template.*)/d'
EOF

%global __perl_provides %{_builddir}/%{name}-%{version}/%{name}-prov
chmod +x %{__perl_provides}

cat << \EOF > %{name}-req
#!/bin/sh
%{__perl_requires} $* |\
sed -e '/perl(PKI.*)/d' -e '/perl(Template.*)/d'
EOF

%global __perl_requires %{_builddir}/%{name}-%{version}/%{name}-req
chmod +x %{__perl_requires}


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVAR_INSTALL_DIR:PATH=/var -DBUILD_PKI_TPS:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"

# This should be done in CMAKE
cd %{buildroot}/%{_datadir}/pki/tps/docroot
%{__ln_s} tokendb tus


%pre


%post
/sbin/ldconfig
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add pki-tpsd || :


%preun
if [ $1 = 0 ] ; then
    /sbin/service pki-tpsd stop >/dev/null 2>&1
    /sbin/chkconfig --del pki-tpsd || :
fi


%postun
if [ "$1" -ge "1" ] ; then
    /sbin/service pki-tpsd condrestart >/dev/null 2>&1 || :
fi


%files
%defattr(-,root,root,-)
%doc base/tps/LICENSE
%{_initrddir}/pki-tpsd
%{_bindir}/tpsclient
%{_libdir}/httpd/modules/*
%{_libdir}/lib*
%dir %{_datadir}/pki/tps
%dir %{_datadir}/pki/tps/applets
%{_datadir}/pki/tps/applets/*
%dir %{_datadir}/pki/tps/cgi-bin
%{_datadir}/pki/tps/cgi-bin/*
%dir %{_datadir}/pki/tps/conf
%{_datadir}/pki/tps/conf/*
%dir %{_datadir}/pki/tps/docroot
%{_datadir}/pki/tps/docroot/*
%dir %{_datadir}/pki/tps/lib
%{_datadir}/pki/tps/lib/*
%dir %{_datadir}/pki/tps/samples
%{_datadir}/pki/tps/samples/*
%dir %{_datadir}/pki/tps/scripts
%{_datadir}/pki/tps/scripts/*
%dir %{_datadir}/pki/tps/setup
%{_datadir}/pki/tps/setup/*
%dir %{_localstatedir}/lock/pki/tps
%dir %{_localstatedir}/run/pki/tps


%files devel
%defattr(-,root,root,-)
%{_libdir}/libldapauth.so
%{_libdir}/libtokendb.so
%{_libdir}/libtps.so


%changelog
* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision. (kwright@redhat.com & mharmsen@redhat.com)

