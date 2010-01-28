Name:           pki-tps
Version:        1.3.0
Release:        5%{?dist}
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
Requires:       pki-selinux
Requires:       pki-setup
Requires:       pki-silent
Requires:       pki-tps-ui
Requires(post):    chkconfig
Requires(preun):   chkconfig
Requires(preun):   initscripts
Requires(postun):  initscripts

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

%package devel
Group:      Development/Libraries
Summary:    Dogtag Certificate System - Token Processing System Library Symlinks

Requires:   %{name} = %{version}-%{release}

%description devel
This package contains symlinks to the Dogtag Certificate System Token
Processing System library files required to link executables.

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
make install DESTDIR=%{buildroot} INSTALL="install -p"

## rearrange files to be in the desired native packaging layout
# create the appropriate subdirectories
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_libdir}/httpd/modules
mkdir -p %{buildroot}%{_libdir}/pki/tps
mkdir -p %{buildroot}%{_datadir}/pki/tps/docroot
mkdir -p %{buildroot}%{_datadir}/pki/tps/lib/perl/PKI/Base
mkdir -p %{buildroot}%{_datadir}/pki/tps/lib/perl/PKI/Service
mkdir -p %{buildroot}%{_datadir}/pki/tps/lib/perl/PKI/TPS
mkdir -p %{buildroot}%{_datadir}/pki/tps/lib/perl/Template
mkdir -p %{buildroot}%{_localstatedir}/lock/pki/tps
mkdir -p %{buildroot}%{_localstatedir}/run/pki/tps

# unpack the package contents to the appropriate subdirectories
cp -p  %{buildroot}/opt/apache/modules/*.so  %{buildroot}%{_libdir}/httpd/modules
cp -rp %{buildroot}/opt/alias*               %{buildroot}%{_datadir}/pki/tps
cp -rp %{buildroot}/opt/applets*             %{buildroot}%{_datadir}/pki/tps
cp -rp %{buildroot}/opt/cgi-bin*             %{buildroot}%{_datadir}/pki/tps
cp -rp %{buildroot}/opt/conf*                %{buildroot}%{_datadir}/pki/tps
cp -p  %{buildroot}/opt/docroot/index.cgi    %{buildroot}%{_datadir}/pki/tps/docroot
chmod 00755 %{buildroot}%{_datadir}/pki/tps/docroot/index.cgi
cp -p  %{buildroot}/opt/docroot/index.html   %{buildroot}%{_datadir}/pki/tps/docroot
cp -rp %{buildroot}/opt/docroot/demo*        %{buildroot}%{_datadir}/pki/tps/docroot
cp -rp %{buildroot}/opt/docroot/home*        %{buildroot}%{_datadir}/pki/tps/docroot
cp -rp %{buildroot}/opt/docroot/so*          %{buildroot}%{_datadir}/pki/tps/docroot
cp -rp %{buildroot}/opt/docroot/sow*         %{buildroot}%{_datadir}/pki/tps/docroot
cp -rp %{buildroot}/opt/docroot/tokendb*     %{buildroot}%{_datadir}/pki/tps/docroot
cp -rp %{buildroot}/opt/docroot/tps*         %{buildroot}%{_datadir}/pki/tps/docroot
cp -rp %{buildroot}/opt/logs*                %{buildroot}%{_datadir}/pki/tps
cp -rp %{buildroot}/opt/perl/base/*          %{buildroot}%{_datadir}/pki/tps/lib/perl/PKI/Base
chmod 00644 %{buildroot}%{_datadir}/pki/tps/lib/perl/PKI/Base/*.pm
cp -rp %{buildroot}/opt/perl/modules/*       %{buildroot}%{_datadir}/pki/tps/lib/perl/PKI/TPS
chmod 00644 %{buildroot}%{_datadir}/pki/tps/lib/perl/PKI/TPS/*.pm
cp -rp %{buildroot}/opt/perl/service/*       %{buildroot}%{_datadir}/pki/tps/lib/perl/PKI/Service
chmod 00644 %{buildroot}%{_datadir}/pki/tps/lib/perl/PKI/Service/*.pm
cp -rp %{buildroot}/opt/perl/templates/*     %{buildroot}%{_datadir}/pki/tps/lib/perl/Template
chmod 00644 %{buildroot}%{_datadir}/pki/tps/lib/perl/Template/*.pm
cp -rp %{buildroot}/opt/samples*             %{buildroot}%{_datadir}/pki/tps
cp -rp %{buildroot}/opt/scripts*             %{buildroot}%{_datadir}/pki/tps
cp -rp %{buildroot}/opt/setup*               %{buildroot}%{_datadir}/pki/tps
cp -rp %{buildroot}/opt/templates*           %{buildroot}%{_datadir}/pki/tps
cp -p  %{buildroot}%{_libexecdir}/apachectl* %{buildroot}%{_libdir}/pki/tps
cp -p  %{buildroot}%{_libexecdir}/tpsclient* %{buildroot}%{_libdir}/pki/tps

# strip symbolic information 
cd %{buildroot}%{_libdir} ;
%{__strip} libldapauth.so   ;
%{__strip} libtokendb.so    ;
%{__strip} libtps.so
cd %{buildroot}%{_libdir}/httpd/modules ;
%{__strip} mod_tokendb.so ;
%{__strip} mod_tps.so
cd %{buildroot}%{_libdir}/pki/tps ;
%{__strip} tpsclient

# create wrappers
for wrapper in tpsclient
do
    sed -e "s|\[PKI_PRODUCT\]|pki|g"        \
        -e "s|\[PKI_SUBSYSTEM\]|tps|g"      \
        -e "s|\[PKI_COMMAND\]|${wrapper}|g" \
        %{buildroot}/opt/templates/pki_subsystem_command_wrapper > %{buildroot}%{_bindir}/${wrapper} ;
done

# create useful symbolic links as appropriate
cd %{buildroot}%{_datadir}/pki/tps/docroot
ln -s tokendb tus

# fix version information in primary configuration file
sed -i 's/^preop.product.version=.*$/preop.product.version=%{version}/' %{buildroot}%{_datadir}/pki/tps/conf/CS.cfg

## remove unwanted files
rm -rf %{buildroot}/opt/
rm -rf %{buildroot}%{_libdir}/debug/
rm -rf %{buildroot}%{_libdir}/lib*.la
rm -rf %{buildroot}%{_libexecdir}
rm -rf %{buildroot}%{_datadir}/pki/tps/templates/

%clean
rm -rf %{buildroot}


%post
/sbin/ldconfig
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add pki-tpsd || :

%preun
if [ $1 = 0 ] ; then
    /sbin/service pki-tpsd stop >/dev/null 2>&1
    /sbin/chkconfig --del pki-tpsd || :
fi


%postun
/sbin/ldconfig
if [ "$1" -ge "1" ] ; then
    /sbin/service pki-tpsd condrestart >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_initrddir}/*
%{_bindir}/*
%{_libdir}/httpd/modules/*
%{_libdir}/libldapauth.so.*
%{_libdir}/libtokendb.so.*
%{_libdir}/libtps.so.*
%{_libdir}/pki/
%{_datadir}/pki/
%{_localstatedir}/lock/*
%{_localstatedir}/run/*

%files devel
%defattr(-,root,root,-)
%{_libdir}/libldapauth.so
%{_libdir}/libtokendb.so
%{_libdir}/libtps.so

%changelog
* Wed Jan 27 2010 Kevin Wright <kwright@redhat.com> 1.3.0-5
- Bugzilla Bug #553852 - Review Request: pki-tps - The Dogtag PKI System Token Processing System
  Per direction from the Fedora community, removed the following
  explicit "Requires":

      perl-DBD-SQLite (unused)
      perl-DBI
      perl-HTML-Parser
      perl-HTML-Tagset
      perl-Parse-RecDescent
      perl-URI
      perl-XML-NamespaceSupport (unused)
      perl-XML-Parser
      perl-XML-Simple

* Thu Jan 14 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-4
- Bugzilla Bug #512234 - Move pkiuser:pkiuser check from spec file into
  pkicreate . . .
- Bugzilla Bug #547471 - Apply PKI SELinux changes to PKI registry model
- Bugzilla Bug #553076 - Apply "registry" logic to pki-ra . . .
- Bugzilla Bug #553078 - Apply "registry" logic to pki-tps . . .
- Bugzilla Bug #553852 - Review Request: pki-tps - Dogtag Certificate System
  Token Processing System

* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-3
- Removed BuildRequires bash
- Removed 'with exceptions' from License

* Mon Nov 2 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-2
- Bugzilla Bug #X - Packaging for Fedora Dogtag PKI
- Prepended directory path in front of setup_package
- Take ownership of pki tps directory.

* Fri Oct 16 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Packaging for Fedora Dogtag PKI
