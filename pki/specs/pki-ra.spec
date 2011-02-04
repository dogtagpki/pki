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
BuildRequires:    nspr-devel
BuildRequires:    nss-devel

Requires:         mod_nss >= 1.0.8
Requires:         mod_perl >= 1.99_16
Requires:         mod_revocator >= 1.0.3
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
%if 0%{?fedora} >= 15
# Details:
#
#     * https://fedoraproject.org/wiki/Features/var-run-tmpfs
#     * https://fedoraproject.org/wiki/Tmpfiles.d_packaging_draft
#
Requires:         initscripts
%endif

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
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"

%if 0%{?fedora} >= 15
# Details:
#
#     * https://fedoraproject.org/wiki/Features/var-run-tmpfs
#     * https://fedoraproject.org/wiki/Tmpfiles.d_packaging_draft
#
%{__mkdir_p} %{buildroot}%{_sysconfdir}/tmpfiles.d
# generate 'pki-ra.conf' under the 'tmpfiles.d' directory
echo "D /var/lock/pki 0755 root root -"    >  %{buildroot}%{_sysconfdir}/tmpfiles.d/pki-ra.conf
echo "D /var/lock/pki/ra 0755 root root -" >> %{buildroot}%{_sysconfdir}/tmpfiles.d/pki-ra.conf
echo "D /var/run/pki 0755 root root -"     >> %{buildroot}%{_sysconfdir}/tmpfiles.d/pki-ra.conf
echo "D /var/run/pki/ra 0755 root root -"  >> %{buildroot}%{_sysconfdir}/tmpfiles.d/pki-ra.conf
%endif


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
%dir %{_datadir}/pki/ra
%{_datadir}/pki/ra/conf/
%{_datadir}/pki/ra/docroot/
%{_datadir}/pki/ra/lib/
%{_datadir}/pki/ra/scripts/
%{_datadir}/pki/ra/setup/
%dir %{_localstatedir}/lock/pki/ra
%dir %{_localstatedir}/run/pki/ra
%if 0%{?fedora} >= 15
# Details:
#
#     * https://fedoraproject.org/wiki/Features/var-run-tmpfs
#     * https://fedoraproject.org/wiki/Tmpfiles.d_packaging_draft
#
%config(noreplace) %{_sysconfdir}/tmpfiles.d/pki-ra.conf
%endif


%changelog
* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0 --> Dogtag 9.0.0
- Bugzilla Bug #620925 - CC: auditor needs to be able to download audit logs
  in the java subsystems
- Bugzilla Bug #651916 - kra and ocsp are using incorrect ports
  to talk to CA and complete configuration in DonePanel
- Bugzilla Bug #632425 - Port to tomcat6
- Bugzilla Bug #638377 - Generate PKI UI components which exclude
  a GUI interface
- Bugzilla Bug #643206 - New CMake based build system for Dogtag
- Bugzilla Bug #499494 - change CA defaults to SHA2
- Bugzilla Bug #656664 - Please Update Spec File to use 'ghost' on files
  in /var/run and /var/lock
- Bugzilla Bug #606943 - Convert RA to use ldap utilities from
  OpenLDAP instead of the Mozldap

* Thu Apr 08 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.1-1
- Bugzilla Bug #564131 - Config wizard : all subsystems - done panel text
  needs correction

* Tue Feb 16 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-6
- Bugzilla Bug #566060 - Add 'pki-native-tools' as a runtime dependency
  for RA, and TPS . . .

* Fri Jan 29 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-5
- Bugzilla Bug #553076 - Apply "registry" logic to pki-ra . . .
- Applied filters for unwanted perl provides and requires
- Restored "perl-DBD-SQLite" runtime dependency

* Tue Jan 26 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-4
- Bugzilla Bug #553850 - Review Request: pki-ra - Dogtag Registration Authority
- Per direction from the Fedora community,
  removed the following explicit "Requires":
      perl-DBI
      perl-HTML-Parser
      perl-HTML-Tagset
      perl-Parse-RecDescent
      perl-URI
      perl-XML-NamespaceSupport
      perl-XML-Parser
      perl-XML-Simple

* Thu Jan 14 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #512234 - Move pkiuser:pkiuser check from spec file into pkicreate . . .
- Bugzilla Bug #547471 - Apply PKI SELinux changes to PKI registry model
- Bugzilla Bug #553076 - Apply "registry" logic to pki-ra . . .
- Bugzilla Bug #553078 - Apply "registry" logic to pki-tps . . .
- Bugzilla Bug #553850 - Review Request: pki-ra - Dogtag Registration Authority

* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-2
- Removed 'with exceptions' from License

* Fri Oct 16 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Fedora Packaging Changes

