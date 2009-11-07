Name:           pki-ca
Version:        1.3.0
Release:        4%{?dist}
Summary:        Dogtag Certificate System - Certificate Authority
URL:            http://pki.fedoraproject.org/
License:        GPLv2 with exceptions
Group:          System Environment/Daemons

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  dogtag-pki-ca-ui
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  jss >= 4.2.6
BuildRequires:  pki-common
BuildRequires:  pki-util
BuildRequires:  tomcatjss

Requires:       java >= 1:1.6.0
Requires:       pki-ca-ui
Requires:       pki-common
Requires:       pki-selinux

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Certificate Authority is a required PKI subsystem which issues,
renews, revokes, and publishes certificates as well as compiling and
publishing Certificate Revocation Lists (CRLs).
The Dogtag Certificate Authority can be configured as a self-signing
Certificate Authority (CA), where it is the root CA, or it can act as a
subordinate CA, where it obtains its own signing certificate from a public CA.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="ca" \
    -Dversion="%{version}"

%install
%define major_version %(echo `echo %{version} | awk -F. '{ print $1 }'`)
%define minor_version %(echo `echo %{version} | awk -F. '{ print $2 }'`)
%define patch_version %(echo `echo %{version} | awk -F. '{ print $3 }'`)

rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}
sed -i 's/^preop.product.version=.*$/preop.product.version=%{version}/' %{buildroot}%{_datadir}/pki/ca/conf/CS.cfg
sed -i 's/^cms.version=.*$/cms.version=%{major_version}.%{minor_version}/' %{buildroot}%{_datadir}/pki/ca/conf/CS.cfg
cd %{buildroot}%{_datadir}/java/pki/ca
mv ca.jar ca-%{version}.jar
ln -s ca-%{version}.jar ca.jar

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
%{_datadir}/pki/ca/setup/postinstall pki ca %{version} %{release}
echo ""
echo "Install finished."

%preun
if [ -d /var/lib/pki-ca ] ; then
        echo "WARNING:  The default instance \"/var/lib/pki-ca\" was NOT removed!"
        echo ""
        echo "NOTE:  This means that the data in the default instance called"
        echo "       \"/var/lib/pki-ca\" will NOT be overwritten once the"
        echo "       \"%{name}\" package is re-installed."
        echo ""
        echo "Shutting down the default instance \"/var/lib/pki-ca\""
        echo "PRIOR to uninstalling the \"%{name}\" package:"
        echo ""
        /etc/init.d/pki-ca stop
fi

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_datadir}/java/pki/ca/
%{_datadir}/pki/ca/

%changelog
* Mon Nov 2 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-4
- Bugzilla Bug #522210 - Packaging for Fedora Dogtag
- Take ownership of directories
* Tue Oct 13 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #522210 - Packaging for Fedora Dogtag
* Fri Sep 18 2009 Ade Lee <alee@redhat.com> 1.3.0-2
- Bugzilla Bug 522210 - addtional changes for packaging for Fedora Dogtag
  remove unused defines, unneeded attr defs, unneeded comments, autoreqprov
* Wed Sep 9 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug 522210 - Packaging for Fedora Dogtag
