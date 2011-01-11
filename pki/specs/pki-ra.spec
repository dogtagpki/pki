###############################################################################
###                       P A C K A G E   H E A D E R                       ###
###############################################################################

Name:             pki-ra
Version:          9.0.0
Release:          1%{?dist}
Summary:          Certificate System - Registration Authority
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Daemons

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake

Requires:         mod_nss >= 1.0.8
Requires:         mod_perl >= 1.99_16
Requires:         mod_revocator >= 1.0.3
Requires:         mozldap >= 6.0.2
Requires:         pki-native-tools
Requires:         pki-ra-theme
Requires:         pki-selinux
Requires:         pki-setup
Requires:         perl-DBD-SQLite
Requires:         sqlite
Requires:         /usr/sbin/sendmail
Requires(post):   chkconfig
Requires(preun):  chkconfig
Requires(preun):  initscripts
Requires(postun): initscripts

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%description
Certificate System (CS) is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Registration Authority (RA) is an optional PKI subsystem that acts as a
front-end for authenticating and processing enrollment requests, PIN reset
requests, and formatting requests.

An RA communicates over SSL with a Certificate Authority (CA) to fulfill
the user's requests. An RA may often be located outside an organization's
firewall to allow external users the ability to communicate with that
organization's PKI deployment.

For deployment purposes, an RA requires the following components from the PKI
Core package:

  * pki-setup
  * pki-native-tools
  * pki-selinux

and can also make use of the following optional components from the PKI Core
package:

  * pki-silent

Additionally, Certificate System requires ONE AND ONLY ONE of the following
"Mutually-Exclusive" PKI Theme packages:

  * dogtag-pki-theme (Dogtag Certificate System deployments)
  * redhat-pki-theme (Red Hat Certificate System deployments)


%prep


%setup -q

cat << \EOF > %{name}-prov
#!/bin/sh
%{__perl_provides} $* |\
sed -e '/perl(PKI.*)/d' -e '/perl(Template.*)/d'
EOF

%global __perl_provides %{_builddir}/%{name}-%{version}/%{name}-prov
chmod +x %{__perl_provides}

cat << \EOF > %{name}-req
#!/bin/sh
%{__perl_requires} $* |\
sed -e '/perl(PKI.*)/d' -e '/perl(Template.*)/d'
EOF

%global __perl_requires %{_builddir}/%{name}-%{version}/%{name}-req
chmod +x %{__perl_requires}


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVAR_INSTALL_DIR:PATH=/var -DBUILD_PKI_RA:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot}


%pre


%post
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add pki-rad || :


%preun
if [ $1 = 0 ] ; then
    /sbin/service pki-rad stop >/dev/null 2>&1
    /sbin/chkconfig --del pki-rad || :
fi


%postun
if [ "$1" -ge "1" ] ; then
    /sbin/service pki-rad condrestart >/dev/null 2>&1 || :
fi


%files
%defattr(-,root,root,-)
%doc base/ra/LICENSE
%{_initrddir}/pki-rad
%dir %{_datadir}/pki
%dir %{_datadir}/pki/ra
%{_datadir}/pki/ra/conf/
%{_datadir}/pki/ra/docroot/
%{_datadir}/pki/ra/lib/
%{_datadir}/pki/ra/scripts/
%{_datadir}/pki/ra/setup/
%dir %{_localstatedir}/lock/pki
%dir %{_localstatedir}/lock/pki/ra
%dir %{_localstatedir}/run/pki
%dir %{_localstatedir}/run/pki/ra


%changelog
* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision. (kwright@redhat.com & mharmsen@redhat.com)

