Name:           pki-kra
Version:        1.3.0
Release:        3%{?dist}
Summary:        Dogtag Certificate System - Data Recovery Manager
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Daemons

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  dogtag-pki-kra-ui
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
Requires:       pki-silent
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
sed -i 's/^preop.product.version=.*$/preop.product.version=%{version}/' %{buildroot}%{_datadir}/pki/kra/conf/CS.cfg
sed -i 's/^cms.version=.*$/cms.version=%{major_version}.%{minor_version}/' %{buildroot}%{_datadir}/pki/kra/conf/CS.cfg
mkdir -p %{buildroot}%{_localstatedir}/lock/pki/kra
mkdir -p %{buildroot}%{_localstatedir}/run/pki/kra
cd %{buildroot}%{_javadir}
mv kra.jar kra-%{version}.jar
ln -s kra-%{version}.jar kra.jar

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
* Fri Jan 8 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Corrected "|| :" scriptlet logic (see Bugzilla Bug #475895)
- Bugzilla Bug #553072 - Apply "registry" logic to pki-kra . . .
- Bugzilla Bug #553842 - New Package for Dogtag PKI: pki-kra

* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-2
- Removed 'with exceptions' from License

* Thu Oct 15 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Packaging for Fedora Dogtag
