Name:           pki-tps
Version:        1.3.0
Release:        3%{?dist}
Summary:        Dogtag Certificate System - Token Processing System
URL:            http://pki.fedoraproject.org/
License:        LGPLv2
Group:          System Environment/Daemons

# Suppress '/usr/lib/rpm/perl.req' and '/usr/lib/rpm/perl.prov'
AutoReqProv:    no

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  apr-devel
BuildRequires:  apr-util-devel
BuildRequires:  cyrus-sasl-devel
BuildRequires:  dogtag-pki-tps-ui
BuildRequires:  httpd-devel >= 2.2.3
BuildRequires:  mozldap-devel
BuildRequires:  nspr-devel >= 4.6.99
BuildRequires:  nss-devel >= 3.12.3.99
BuildRequires:  pcre-devel
BuildRequires:  svrcore-devel
BuildRequires:  zlib
BuildRequires:  zlib-devel

Requires:       mod_nss >= 1.0.7
Requires:       mod_perl
Requires:       mozldap
Requires:       perl-HTML-Parser
Requires:       perl-HTML-Tagset
Requires:       perl-Parse-RecDescent
Requires:       perl-URI
Requires:       perl-XML-NamespaceSupport
Requires:       perl-XML-Parser
Requires:       perl-XML-Simple
Requires:       pki-selinux
Requires:       pki-setup
Requires:       pki-tps-ui

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Token Processing System is an optional PKI subsystem
that acts as a Registration Authority (RA) for authenticating and processing
enrollment requests, PIN reset requests, and formatting requests from the
Enterprise Security Client (ESC).

Dogtag Token Processing System is designed to communicate with tokens that
conform to Global Platform's Open Platform Specification.

Dogtag Token Processing System communicates over SSL with various
PKI backend subsystems (including the Dogtag Certificate Authority,
the Dogtag Data Recovery Manager, and the Dogtag Token Key Service) to
fulfill the user's requests.

Dogtag Token Processing System also interacts with the token database,
an LDAP server that stores information about individual tokens.

%prep

%setup -q -n %{name}-%{version}

%build
%configure \
%ifarch ppc64 s390x sparc64 x86_64
    --enable-64bit \
%endif
    --libdir=%{_libdir}
make

%install
rm -rf %{buildroot}
make install DESTDIR=%{buildroot}

## rearrange files to be in the desired native packaging layout
./setup_package %{buildroot} pki tps %{version} %{release} %{buildroot}/opt
sed -i 's/^preop.product.version=.*$/preop.product.version=%{version}/' %{buildroot}%{_datadir}/pki/tps/conf/CS.cfg

## remove unwanted files
rm -rf %{buildroot}/opt/
rm -rf %{buildroot}%{_libdir}/debug/
rm -rf %{buildroot}/usr/libexec/
rm -rf %{buildroot}/etc/init.d/
rm -rf %{buildroot}%{_libdir}/lib*.la

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
chmod 00755 %{_datadir}/pki/tps/setup/postinstall
%{_datadir}/pki/tps/setup/postinstall pki tps %{version} %{release}
echo ""
echo "Install finished."

%preun
if [ -d /var/lib/pki-tps ] ; then
    echo "WARNING:  The default instance \"/var/lib/pki-tps\" was NOT removed!"
    echo ""
    echo "NOTE:  This means that the data in the default instance called"
    echo "       \"/var/lib/pki-tps\" will NOT be overwritten once the"
    echo "       \"%{name}\" package is re-installed."
    echo ""
    echo "Shutting down the default instance \"/var/lib/pki-tps\""
    echo "PRIOR to uninstalling the \"%{name}\" package:"
    echo ""
    /etc/init.d/pki-tps stop
fi

%files
%defattr(-,root,root,-)
%doc LICENSE
/etc/httpd/modules/*
%{_bindir}/*
%{_libdir}/*
%{_datadir}/pki/tps/

%changelog
* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-3
- Removed BuildRequires bash
- Removed 'with exceptions' from License

* Mon Nov 2 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-2
- Bugzilla Bug #X - Packaging for Fedora Dogtag PKI
- Prepended directory path in front of setup_package
- Take ownership of pki tps directory.

* Fri Oct 16 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Packaging for Fedora Dogtag PKI
