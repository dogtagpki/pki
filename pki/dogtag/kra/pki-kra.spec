Name:           pki-kra
Version:        9.0.0
Release:        1%{?dist}
Summary:        Dogtag Certificate System - Data Recovery Manager
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
Requires:       pki-kra-ui
Requires:       pki-selinux
Requires(post):    chkconfig
Requires(preun):   chkconfig
Requires(preun):   initscripts
Requires(postun):  initscripts

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Data Recovery Manager is an optional PKI subsystem that can act
as a Key Recovery Authority (KRA).  When configured in conjunction with the
Dogtag Certificate Authority, the Dogtag Data Recovery Manager stores
private encryption keys as part of the certificate enrollment process.  The
key archival mechanism is triggered when a user enrolls in the PKI and creates
the certificate request.  Using the Certificate Request Message Format (CRMF)
request format, a request is generated for the user's private encryption key.
This key is then stored in the Dogtag Data Recovery Manager which is
configured to store keys in an encrypted format that can only be decrypted by
several agents requesting the key at one time, providing for protection of the
public encryption keys for the users in the PKI deployment.

Note that the Dogtag Data Recovery Manager archives encryption keys; it does
not archive signing keys, since such archival would undermine nonrepudiation
properties of signing keys.

%prep

%setup -q

%build
ant \
    -Dinit.d="rc.d/init.d" \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="kra" \
    -Dversion="%{version}"

%install
%define major_version %(echo `echo %{version} | awk -F. '{ print $1 }'`)
%define minor_version %(echo `echo %{version} | awk -F. '{ print $2 }'`)
%define patch_version %(echo `echo %{version} | awk -F. '{ print $3 }'`)

rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}
cd %{buildroot}%{_datadir}/pki/kra/conf
mv CS.cfg.in CS.cfg
sed -i 's/^preop.product.version=.*$/preop.product.version=%{version}/' %{buildroot}%{_datadir}/pki/kra/conf/CS.cfg
sed -i 's/^cms.version=.*$/cms.version=%{major_version}.%{minor_version}/' %{buildroot}%{_datadir}/pki/kra/conf/CS.cfg
mkdir -p %{buildroot}%{_localstatedir}/lock/pki/kra
mkdir -p %{buildroot}%{_localstatedir}/run/pki/kra
cd %{buildroot}%{_datadir}/pki/kra/setup
mv config.desktop.in config.desktop
cd %{buildroot}%{_javadir}
mv kra.jar kra-%{version}.jar
ln -s kra-%{version}.jar kra.jar

# supply convenience symlink(s) for backwards compatibility
mkdir -p %{buildroot}%{_javadir}/pki/kra
cd %{buildroot}%{_javadir}/pki/kra
ln -s ../../kra.jar kra.jar

%clean
rm -rf %{buildroot}

%post
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add pki-krad || :

%preun
if [ $1 = 0 ] ; then
    /sbin/service pki-krad stop >/dev/null 2>&1
    /sbin/chkconfig --del pki-krad || :
fi

%postun
if [ "$1" -ge "1" ] ; then
    /sbin/service pki-krad condrestart >/dev/null 2>&1 || :
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
