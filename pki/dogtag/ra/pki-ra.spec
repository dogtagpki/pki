Name:           pki-ra
Version:        1.3.0
Release:        2%{?dist}
Summary:        Dogtag Certificate System - Registration Authority
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Daemons

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  dogtag-pki-ra-ui

Requires:       mod_nss >= 1.0.7
Requires:       mod_perl >= 1.99_16
Requires:       mozldap >= 6.0.2
Requires:       perl-DBD-SQLite
Requires:       perl-DBI
Requires:       perl-HTML-Parser
Requires:       perl-HTML-Tagset
Requires:       perl-Parse-RecDescent
Requires:       perl-URI
Requires:       perl-XML-NamespaceSupport
Requires:       perl-XML-Parser
Requires:       perl-XML-Simple
Requires:       pki-ra-ui
Requires:       pki-selinux
Requires:       pki-setup
Requires:       sendmail
Requires:       sqlite

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Registration Authority is an optional PKI subsystem that
acts as a front-end for authenticating and processing
enrollment requests, PIN reset requests, and formatting requests.

Dogtag Registration Authority communicates over SSL with the
Dogtag Certificate Authority to fulfill the user's requests.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="" \
    -Dproduct.prefix="pki" \
    -Dproduct="ra" \
    -Dversion="%{version}"

%install
rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}
sed -i 's/^preop.product.version=.*$/preop.product.version=%{version}/' %{buildroot}%{_datadir}/pki/ra/conf/CS.cfg

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
%{_datadir}/pki/ra/setup/postinstall pki ra %{version} %{release}
echo ""
echo "Install finished."

%preun
if [ -d /var/lib/pki-ra ] ; then
        echo "WARNING:  The default instance \"/var/lib/pki-ra\" was NOT removed!"
        echo ""
        echo "NOTE:  This means that the data in the default instance called"
        echo "       \"/var/lib/pki-ra\" will NOT be overwritten once the"
        echo "       \"%{name}\" package is re-installed."
        echo ""
        echo "Shutting down the default instance \"/var/lib/pki-ra\""
        echo "PRIOR to uninstalling the \"%{name}\" package:"
        echo ""
        /etc/init.d/pki-ra stop
fi

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_datadir}/pki/ra/*

%changelog
* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-2
- Removed 'with exceptions' from License

* Fri Oct 16 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Fedora Packaging Changes
