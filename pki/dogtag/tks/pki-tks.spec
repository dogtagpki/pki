Name:           pki-tks
Version:        1.3.0
Release:        2%{?dist}
Summary:        Dogtag Certificate System - Token Key Service
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Daemons

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  dogtag-pki-tks-ui
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
sed -i 's/^preop.product.version=.*$/preop.product.version=%{version}/' %{buildroot}%{_datadir}/pki/tks/conf/CS.cfg
sed -i 's/^cms.version=.*$/cms.version=%{major_version}.%{minor_version}/' %{buildroot}%{_datadir}/pki/tks/conf/CS.cfg
cd %{buildroot}%{_javadir}/pki/tks
mv tks.jar tks-%{version}.jar
ln -s tks-%{version}.jar tks.jar

%clean
rm -rf %{buildroot}

%pre
if [ `grep -c pkiuser /etc/group` -eq 0 ] ; then
        echo "Adding default PKI group \"pkiuser\" to /etc/group."
        groupadd pkiuser
fi
if [ `grep -c pkiuser /etc/passwd` -eq 0 ] ; then
        echo "Adding default PKI user \"pkiuser\" to /etc/passwd."
        useradd -g pkiuser -d %{_datadir}/pki -s /sbin/nologin -c "Dogtag Certificate System" -m pkiuser
fi


%post
%{_datadir}/pki/tks/setup/postinstall pki tks %{version} %{release}
echo ""
echo "Install finished."


%preun
if [ -d /var/lib/pki-tks ] ; then
        echo "WARNING:  The default instance \"/var/lib/pki-tks\" was NOT removed!"
        echo ""
        echo "NOTE:  This means that the data in the default instance called"
        echo "       \"/var/lib/pki-tks\" will NOT be overwritten once the"
        echo "       \"%{name}\" package is re-installed."
        echo ""
        echo "Shutting down the default instance \"/var/lib/pki-tks\""
        echo "PRIOR to uninstalling the \"%{name}\" package:"
        echo ""
        /etc/init.d/pki-tks stop
fi

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_javadir}/pki/tks/*
%{_datadir}/pki/tks/*

%changelog
* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-2
- Removed 'with exceptions' from License

* Fri Oct 16 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Packaging for Fedora Dogtag
