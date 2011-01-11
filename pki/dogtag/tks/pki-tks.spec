Name:           pki-tks
Version:        9.0.0
Release:        1%{?dist}
Summary:        Dogtag Certificate System - Token Key Service
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
Requires:       pki-tks-ui
Requires:       pki-common
Requires:       pki-selinux
Requires(post):    chkconfig
Requires(preun):   chkconfig
Requires(preun):   initscripts
Requires(postun):  initscripts

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Token Key Service is an optional PKI subsystem that
manages the master key(s) and the transport key(s) required to generate and
distribute keys for hardware tokens.  Dogtag Token Key Service provides
the security between tokens and an instance of Dogtag Token Processing System,
where the security relies upon the relationship between the master key
and the token keys.  A Dogtag Token Processing System communicates with a
Dogtag Token Key Service over SSL using client authentication.

Dogtag Token Key Service helps establish a secure channel (signed and
encrypted) between the token and the Dogtag Token Processing System,
provides proof of presence of the security token during enrollment, and
supports key changeover when the master key changes on the
Dogtag Token Key Service.  Tokens with older keys will get new token keys.

Because of the sensitivity of the data that Dogtag Token Key Service manages,
Dogtag Token Key Service should be set up behind the firewall with
restricted access.

%prep

%setup -q

%build
ant \
    -Dinit.d="rc.d/init.d" \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="tks" \
    -Dversion="%{version}"

%install
%define major_version %(echo `echo %{version} | awk -F. '{ print $1 }'`)
%define minor_version %(echo `echo %{version} | awk -F. '{ print $2 }'`)
%define patch_version %(echo `echo %{version} | awk -F. '{ print $3 }'`)

rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}
cd %{buildroot}%{_datadir}/pki/tks/conf
mv CS.cfg.in CS.cfg
sed -i 's/^preop.product.version=.*$/preop.product.version=%{version}/' %{buildroot}%{_datadir}/pki/tks/conf/CS.cfg
sed -i 's/^cms.version=.*$/cms.version=%{major_version}.%{minor_version}/' %{buildroot}%{_datadir}/pki/tks/conf/CS.cfg
mkdir -p %{buildroot}%{_localstatedir}/lock/pki/tks
mkdir -p %{buildroot}%{_localstatedir}/run/pki/tks
cd %{buildroot}%{_datadir}/pki/tks/setup
mv config.desktop.in config.desktop
cd %{buildroot}%{_javadir}/pki
mv pki-tks.jar pki-tks-%{version}.jar
ln -s pki-tks-%{version}.jar pki-tks.jar

%clean
rm -rf %{buildroot}

%post
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add pki-tksd || :

%preun
if [ $1 = 0 ] ; then
    /sbin/service pki-tksd stop >/dev/null 2>&1
    /sbin/chkconfig --del pki-tksd || :
fi

%postun
if [ "$1" -ge "1" ] ; then
    /sbin/service pki-tksd condrestart >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_initrddir}/*
%{_javadir}/pki/
%{_datadir}/pki/
%{_localstatedir}/lock/*
%{_localstatedir}/run/*

%changelog
* Fri Nov 19 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0 --> Dogtag 9.0.0.
