Name:           pki-ocsp
Version:        9.0.0
Release:        1%{?dist}
Summary:        Dogtag Certificate System - Online Certificate Status Protocol Manager
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Daemons

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  jss >= 4.2.6
BuildRequires:  pki-common
BuildRequires:  pki-util
BuildRequires:  tomcatjss

Requires:       java >= 1:1.6.0
Requires:       pki-common
Requires:       pki-ocsp-ui
Requires:       pki-selinux
Requires(post):    chkconfig
Requires(preun):   chkconfig
Requires(preun):   initscripts
Requires(postun):  initscripts

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Online Certificate Status Protocol Manager is an optional
PKI subsystem that can act as a stand-alone Online Certificate
Status Protocol (OCSP) service.
The Dogtag Online Certificate Status Protocol Manager performs the task of an
online certificate validation authority by enabling OCSP-compliant clients to
do real-time verification of certificates.  Note that an online
certificate-validation authority is often referred to as an OCSP Responder.

Although the Dogtag Certificate Authority is already configured with an
internal OCSP service.  An external OCSP Responder is offered as a separate
subsystem in case the user wants the OCSP service provided outside of a
firewall while the Dogtag Certificate Authority resides inside of a firewall,
or to take the load of requests off of the Dogtag Certificate Authority.

The Dogtag Online Certificate Status Protocol Manager can receive Certificate
Revocation Lists (CRLs) from multiple Dogtag Certificate Authority servers,
and clients can query the Dogtag Online Certificate Status Protocol Manager
for the revocation status of certificates issued by all of these
Dogtag Certificate Authority servers.

When an instance of Dogtag Online Certificate Status Protocol Manager is
set up with an instance of Dogtag Certificate Authority, and publishing
is set up to this Dogtag Online Certificate Status Protocol Manager,
CRLs are published to it whenever they are issued or updated.

%prep

%setup -q

%build
ant \
    -Dinit.d="rc.d/init.d" \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="ocsp" \
    -Dversion="%{version}"

%install
%define major_version %(echo `echo %{version} | awk -F. '{ print $1 }'`)
%define minor_version %(echo `echo %{version} | awk -F. '{ print $2 }'`)
%define patch_version %(echo `echo %{version} | awk -F. '{ print $3 }'`)

rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}
sed -i 's/^preop.product.version=.*$/preop.product.version=%{version}/' %{buildroot}%{_datadir}/pki/ocsp/conf/CS.cfg
sed -i 's/^cms.version=.*$/cms.version=%{major_version}.%{minor_version}/' %{buildroot}%{_datadir}/pki/ocsp/conf/CS.cfg
mkdir -p %{buildroot}%{_localstatedir}/lock/pki/ocsp
mkdir -p %{buildroot}%{_localstatedir}/run/pki/ocsp
cd %{buildroot}%{_javadir}
mv ocsp.jar ocsp-%{version}.jar
ln -s ocsp-%{version}.jar ocsp.jar

# supply convenience symlink(s) for backwards compatibility
mkdir -p %{buildroot}%{_javadir}/pki/ocsp
cd %{buildroot}%{_javadir}/pki/ocsp
ln -s ../../ocsp.jar ocsp.jar

%clean
rm -rf %{buildroot}

%post
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add pki-ocspd || :

%preun
if [ $1 = 0 ] ; then
    /sbin/service pki-ocspd stop >/dev/null 2>&1
    /sbin/chkconfig --del pki-ocspd || :
fi

%postun
if [ "$1" -ge "1" ] ; then
    /sbin/service pki-ocspd condrestart >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_initrddir}/*
%{_javadir}/*
%{_datadir}/pki/
%{_localstatedir}/lock/*
%{_localstatedir}/run/*

%changelog
* Fri Nov 19 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0 --> Dogtag 9.0.0.
