Name:             pki-tps-client
Version:          10.2.0
Release:          0.3%{?dist}
Summary:          Certificate System - Token Processing System
URL:              http://pki.fedoraproject.org/
License:          LGPLv2
Group:            System Environment/Daemons

%bcond_without    javadoc
%define _unpackaged_files_terminate_build 0 
BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake >= 2.8.9-1
BuildRequires:    apr-devel
BuildRequires:    apr-util-devel
BuildRequires:    cyrus-sasl-devel
BuildRequires:    httpd-devel >= 2.4.2
BuildRequires:    java-devel >= 1:1.7.0
BuildRequires:    openldap-devel
BuildRequires:    nspr-devel
BuildRequires:    nss-devel >= 3.14.3
BuildRequires:    pcre-devel
BuildRequires:    pki-server >= 10.2.0
BuildRequires:    python
BuildRequires:    systemd
BuildRequires:    svrcore-devel
BuildRequires:    zlib
BuildRequires:    zlib-devel

Requires:         java >= 1:1.7.0
Requires:         mod_nss
Requires:         mod_perl
Requires:         mod_revocator
Requires:         nss >= 3.14.3
Requires:         nss-tools >= 3.14.3
Requires:         openldap-clients
Requires:         perl-Mozilla-LDAP
Requires:         pki-server >= 10.2.0
Requires:         pki-symkey >= 10.2.0

Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}%{?prerel}.tar.gz

%global overview                                                          \
Certificate System (CS) is an enterprise software system designed         \
to manage enterprise Public Key Infrastructure (PKI) deployments.         \
                                                                          \
The Token Processing System (TPS) is an optional PKI subsystem that acts  \
as a Registration Authority (RA) for authenticating and processing        \
enrollment requests, PIN reset requests, and formatting requests from     \
the Enterprise Security Client (ESC).                                     \
                                                                          \
The utitility "tpsclient"  is a test tool that interacts with TPS         \
This tool is useful to test TPS server configs without risking a real     \
smart card.                                                               \                                                                          
%{nil}

%description %{overview}


==================================
||  ABOUT "CERTIFICATE SYSTEM"  ||
==================================
${overview}


%prep

%setup -q -n %{name}-%{version}%{?prerel}

cat << \EOF > %{name}-prov

cat << \EOF > %{name}-req

%clean
%{__rm} -rf %{buildroot}

%build
%{__mkdir_p} build
cd build
%cmake -DVERSION=%{version}-%{release} \
	-DVAR_INSTALL_DIR:PATH=/var \
	-DBUILD_PKI_TPS:BOOL=ON \
	-DSYSTEMD_LIB_INSTALL_DIR=%{_unitdir} \
%if 0%{?rhel}
	-DRESTEASY_LIB=/usr/share/java/resteasy-base \
%else
	-DRESTEASY_LIB=/usr/share/java/resteasy \
%endif
%if ! %{with javadoc}
	-DWITH_JAVADOC:BOOL=OFF \
%endif
	..
%{__make} VERBOSE=1 %{?_smp_mflags}

%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"

cd %{buildroot}/%{_datadir}/pki/tps/docroot
%{__ln_s} tokendb tus

# Internal libraries for 'tps' are present in:
#
#     * '/usr/lib/tps'    (i386)
#     * '/usr/lib64/tps'  (x86_64)
#
mkdir %{buildroot}%{_sysconfdir}/ld.so.conf.d
echo %{_libdir}/tps > %{buildroot}%{_sysconfdir}/ld.so.conf.d/tps-%{_arch}.conf

# Details:
#
#     * https://fedoraproject.org/wiki/Features/var-run-tmpfs
#     * https://fedoraproject.org/wiki/Tmpfiles.d_packaging_draft
#
%{__mkdir_p} %{buildroot}%{_sysconfdir}/tmpfiles.d

%files
%defattr(-,root,root,-)
%doc base/tps-client/LICENSE
%{_bindir}/tpsclient
%{_libdir}/tps/libtps.so
%{_libdir}/tps/libtokendb.so

%changelog
* Mon Aug 18 2014 jmagne <jmagne@redhat.com> 10.2.0-0.3
- Initial appearance of pki-tps-client package.
- Package includes merely the "tpclient" command line utility.
- Original tps libararies must be built to support such a utility.
