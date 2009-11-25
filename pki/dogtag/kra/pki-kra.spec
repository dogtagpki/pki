Name:           pki-kra
Version:        1.3.0
Release:        1%{?dist}
Summary:        Dogtag Certificate System - Data Recovery Manager
URL:            http://pki.fedoraproject.org/
License:        GPLv2 with exceptions
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
cd %{buildroot}%{_javadir}/pki/kra
mv kra.jar kra-%{version}.jar
ln -s kra-%{version}.jar kra.jar

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
%{_datadir}/pki/kra/setup/postinstall pki kra %{version} %{release}
echo ""
echo "Install finished."

%preun
if [ -d /var/lib/pki-kra ] ; then
        echo "WARNING:  The default instance \"/var/lib/pki-kra\" was NOT removed!"
        echo ""
        echo "NOTE:  This means that the data in the default instance called"
        echo "       \"/var/lib/pki-kra\" will NOT be overwritten once the"
        echo "       \"%{name}\" package is re-installed."
        echo ""
        echo "Shutting down the default instance \"/var/lib/pki-kra\""
        echo "PRIOR to uninstalling the \"%{name}\" package:"
        echo ""
        /etc/init.d/pki-kra stop
fi

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_javadir}/pki/kra/*
%{_datadir}/pki/kra/*

%changelog
* Thu Oct 15 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Packaging for Fedora Dogtag
