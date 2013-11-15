Name:             pki-tps
Version:          10.1.0
Release:          1%{?dist}
Summary:          Certificate System - Token Processing System
URL:              http://pki.fedoraproject.org/
License:          LGPLv2
Group:            System Environment/Daemons

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake >= 2.8.9-1
BuildRequires:    apr-devel
BuildRequires:    apr-util-devel
BuildRequires:    cyrus-sasl-devel
BuildRequires:    httpd-devel >= 2.4.2
BuildRequires:    java-devel >= 1:1.7.0
BuildRequires:    openldap-devel
BuildRequires:    nspr-devel
BuildRequires:    nss-devel >= 3.14.3
BuildRequires:    pcre-devel
BuildRequires:    pki-server >= 10.1.0
BuildRequires:    python
BuildRequires:    systemd
BuildRequires:    svrcore-devel
BuildRequires:    zlib
BuildRequires:    zlib-devel

Requires:         java >= 1:1.7.0
Requires:         mod_nss
Requires:         mod_perl
Requires:         mod_revocator
Requires:         nss >= 3.14.3
Requires:         nss-tools >= 3.14.3
Requires:         openldap-clients
Requires:         perl-Mozilla-LDAP
Requires:         pki-server >= 10.1.0
Requires:         pki-symkey >= 10.1.0

Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}%{?prerel}.tar.gz

%global overview                                                          \
Certificate System (CS) is an enterprise software system designed         \
to manage enterprise Public Key Infrastructure (PKI) deployments.         \
                                                                          \
The Token Processing System (TPS) is an optional PKI subsystem that acts  \
as a Registration Authority (RA) for authenticating and processing        \
enrollment requests, PIN reset requests, and formatting requests from     \
the Enterprise Security Client (ESC).                                     \
                                                                          \
TPS is designed to communicate with tokens that conform to                \
Global Platform's Open Platform Specification.                            \
                                                                          \
TPS communicates over SSL with various PKI backend subsystems (including  \
the Certificate Authority (CA), the Data Recovery Manager (DRM), and the  \
Token Key Service (TKS)) to fulfill the user's requests.                  \
                                                                          \
TPS also interacts with the token database, an LDAP server that stores    \
information about individual tokens.                                      \
                                                                          \
For deployment purposes, a TPS requires the following components from the \
PKI Core package:                                                         \
                                                                          \
  * pki-server                                                            \
  * pki-tools                                                             \
                                                                          \
Additionally, Certificate System requires ONE AND ONLY ONE of the         \
following "Mutually-Exclusive" PKI Theme packages:                        \
                                                                          \
  * dogtag-pki-theme (Dogtag Certificate System deployments)              \
    * dogtag-pki-server-theme                                             \
  * redhat-pki-server-theme (Red Hat Certificate System deployments)      \
    * redhat-pki-server-theme                                             \
  * customized pki theme (Customized Certificate System deployments)      \
    * <customized>-pki-server-theme                                       \
                                                                          \
%{nil}

%description %{overview}


==================================
||  ABOUT "CERTIFICATE SYSTEM"  ||
==================================
${overview}


%prep


%setup -q -n %{name}-%{version}%{?prerel}

cat << \EOF > %{name}-prov
#!/bin/sh
%{__perl_provides} $* |\
sed -e '/perl(PKI.*)/d' -e '/perl(Template.*)/d'
EOF

%global __perl_provides %{_builddir}/%{name}-%{version}%{?prerel}/%{name}-prov
chmod +x %{__perl_provides}

cat << \EOF > %{name}-req
#!/bin/sh
%{__perl_requires} $* |\
sed -e '/perl(PKI.*)/d' -e '/perl(Template.*)/d'
EOF

%global __perl_requires %{_builddir}/%{name}-%{version}%{?prerel}/%{name}-req
chmod +x %{__perl_requires}


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVERSION=%{version}-%{release} \
	-DVAR_INSTALL_DIR:PATH=/var \
	-DBUILD_PKI_TPS:BOOL=ON \
	-DSYSTEMD_LIB_INSTALL_DIR=%{_unitdir} \
%if 0%{?rhel}
	-DRESTEASY_LIB=/usr/share/java/resteasy-base \
%else
	-DRESTEASY_LIB=/usr/share/java/resteasy \
%endif
	%{?_without_javadoc:-DWITH_JAVADOC:BOOL=OFF} \
	..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"

chmod 755 %{buildroot}%{_datadir}/pki/tps/cgi-bin/demo/*.cgi
chmod 755 %{buildroot}%{_datadir}/pki/tps/cgi-bin/home/*.cgi
chmod 755 %{buildroot}%{_datadir}/pki/tps/cgi-bin/so/*.cgi
chmod 755 %{buildroot}%{_datadir}/pki/tps/cgi-bin/sow/*.cgi
chmod 755 %{buildroot}%{_datadir}/pki/tps/cgi-bin/sow/cfg.pl

# This should be done in CMAKE
cd %{buildroot}/%{_datadir}/pki/tps/docroot
%{__ln_s} tokendb tus

# Internal libraries for 'tps' are present in:
#
#     * '/usr/lib/tps'    (i386)
#     * '/usr/lib64/tps'  (x86_64)
#
mkdir %{buildroot}%{_sysconfdir}/ld.so.conf.d
echo %{_libdir}/tps > %{buildroot}%{_sysconfdir}/ld.so.conf.d/tps-%{_arch}.conf

# Details:
#
#     * https://fedoraproject.org/wiki/Features/var-run-tmpfs
#     * https://fedoraproject.org/wiki/Tmpfiles.d_packaging_draft
#
%{__mkdir_p} %{buildroot}%{_sysconfdir}/tmpfiles.d
# generate 'pki-tps.conf' under the 'tmpfiles.d' directory
echo "D /run/lock/pki 0755 root root -"     >  %{buildroot}%{_sysconfdir}/tmpfiles.d/pki-tps.conf
echo "D /run/lock/pki/tps 0755 root root -" >> %{buildroot}%{_sysconfdir}/tmpfiles.d/pki-tps.conf
echo "D /run/pki 0755 root root -"      >> %{buildroot}%{_sysconfdir}/tmpfiles.d/pki-tps.conf
echo "D /run/pki/tps 0755 root root -"  >> %{buildroot}%{_sysconfdir}/tmpfiles.d/pki-tps.conf

%{__rm} %{buildroot}%{_initrddir}/pki-tpsd

%post
# Attempt to update ALL old "TPS" instances to "systemd"
if [ -d /etc/sysconfig/pki/tps ]; then
    for inst in `ls /etc/sysconfig/pki/tps`; do
        if [ ! -e "/etc/systemd/system/pki-tpsd.target.wants/pki-tpsd@${inst}.service" ]; then
            ln -s "/lib/systemd/system/pki-tpsd@.service" \
                  "/etc/systemd/system/pki-tpsd.target.wants/pki-tpsd@${inst}.service"

            if [ -e /var/run/${inst}.pid ]; then
                kill -9 `cat /var/run/${inst}.pid` || :
                rm -f /var/run/${inst}.pid
                echo "pkicreate.systemd.servicename=pki-tpsd@${inst}.service" >> \
                     /var/lib/${inst}/conf/CS.cfg || :
                /bin/systemctl daemon-reload >/dev/null 2>&1 || :
                /bin/systemctl restart pki-tpsd@${inst}.service || :
            else
                echo "pkicreate.systemd.servicename=pki-tpsd@${inst}.service" >> \
                     /var/lib/${inst}/conf/CS.cfg || :
            fi
        else
            # Conditionally restart this Dogtag 9 instance
            /bin/systemctl condrestart pki-tpsd@${inst}.service
        fi
    done
fi
/bin/systemctl daemon-reload >/dev/null 2>&1 || :

%preun
if [ $1 = 0 ] ; then
    /bin/systemctl --no-reload disable pki-tpsd.target > /dev/null 2>&1 || :
    /bin/systemctl stop pki-tpsd.target > /dev/null 2>&1 || :
fi

%postun
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -ge "1" ] ; then
    /bin/systemctl try-restart pki-tpsd.target >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
%doc base/tps/LICENSE
%dir %{_sysconfdir}/systemd/system/pki-tpsd.target.wants
%{_unitdir}/pki-tpsd@.service
%{_unitdir}/pki-tpsd.target
%config(noreplace) %{_sysconfdir}/ld.so.conf.d/tps-%{_arch}.conf
%{_bindir}/tpsclient
%{_libdir}/httpd/modules/*
%{_libdir}/tps/
%dir %{_datadir}/pki/tps
%{_datadir}/pki/tps/applets/
%{_datadir}/pki/tps/cgi-bin/
%{_datadir}/pki/tps/conf/
%{_datadir}/pki/tps/docroot/
%{_datadir}/pki/tps/lib/
%{_datadir}/pki/tps/samples/
%{_datadir}/pki/tps/scripts/
%{_datadir}/pki/tps/setup/
%dir %{_localstatedir}/lock/pki/tps
%dir %{_localstatedir}/run/pki/tps
# Details:
#
#     * https://fedoraproject.org/wiki/Features/var-run-tmpfs
#     * https://fedoraproject.org/wiki/Tmpfiles.d_packaging_draft
#
%config(noreplace) %{_sysconfdir}/tmpfiles.d/pki-tps.conf


%changelog
* Fri Nov 15 2013 Ade Lee <alee@redhat.com> 10.1.0-1
- Update release number for release build

* Sun Nov 10 2013 Ade Lee <alee@redhat.com> 10.1.0-0.7
- Change release number for beta build

* Thu Oct 31 2013 Ade Lee <alee@redhat.com> 10.1.0-0.6
- Fixed references to /var/run and /var/lock in tmpfiles. 

* Wed Aug 14 2013 Endi S. Dewata <edewata@redhat.com> 10.1.0-0.5
- Moved Tomcat-based TPS into pki-core.

* Thu Jul 11 2013 Ade Lee <alee@redhat.com> 10.1.0-0.4
- Add systemd build requirement to fix build failures in f19

* Fri Jun 14 2013 Kevin Wright <kwright@redhat.com> 10.1.0-0.3
- Added missing build dependency on Java.

* Tue Jun 11 2013 Endi S. Dewata <edewata@redhat.com> 10.1.0-0.2
- Fixed dependencies on pki-server and pki-symkey.

* Tue May 7 2013 Ade Lee <alee@redhat.com> 10.1.0-0.1
- Change release number for 10.1 development

* Tue Apr 30 2013 Ade Lee <alee@redhat.com> 10.0.2-2
- Added nss, nss-tools dependencies

* Fri Apr 26 2013 Ade Lee <alee@redhat.com> 10.0.2-1
- Change release number for official release.

* Wed Mar 27 2013 Endi S. Dewata <edewata@redhat.com> 10.0.2-0.1
- Updated version number to 10.0.2-0.1.

* Tue Mar 12 2013 Endi S. Dewata <edewata@redhat.com> 10.0.0-3
- Added python build-time dependency.

* Mon Mar  4 2013 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-2
- TRAC Ticket #517 - Clean up theme dependencies
- TRAC Ticket #518 - Remove UI dependencies from pkispawn . . .

* Fri Dec 7 2012 Ade Lee <alee@redhat.com> 10.0.0-1
- Update to official release for rc1

* Tue Nov 20 2012 Ade Lee <alee@redhat.com> 10.0.0-0.12.b3
- Update spec fiel to support fedora >= 17 and rhel 7+
- Update cmake version

* Mon Nov 12 2012 Ade Lee <alee@redhat.com> 10.0.0-0.11.b3
- Update release to b3

* Mon Oct 29 2012 Ade Lee <alee@redhat.com> 10.0.0-0.10.b2
- Update release to b2

* Mon Oct 8 2012 Ade Lee <alee@redhat.com> 10.0.0-0.9.b1
- Update release to b1

* Fri Oct 5 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.9.a2
- Merged pki-silent into pki-server.

* Mon Oct 1 2012 Ade Lee <alee@redhat.com> 10.0.0-0.8.a2
- Update release to a2

* Sun Sep 30 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.8.a1
- Modified CMake to use RPM version number

* Mon Sep 24 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.7.a1
- Merged pki-setup into pki-server

* Tue Sep 11 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.6.a1
- TRAC Ticket #312 - Dogtag 10: Automatically restart any running instances
  upon RPM "update" . . .

* Mon Aug 20 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.5.a1
- Removed direct dependency on 'pki-native-tools'.

* Mon Aug 20 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.4.a1
- Replaced 'pki-deploy' with 'pki-server'.

* Thu Aug 16 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.3.a1
- Changed 'httpd-devel' build-time dependency to require '2.4.2'
- Added 'pki-deploy' runtime dependency

* Mon Aug 13 2012 Ade Lee <alee@redhat.com> 10.0.0-0.2.a1
- Added systemd scripts
- Ported config files and init scripts to apache 2.4

* Wed Feb  1 2012 Nathan Kinder <nkinder@redhat.com> 10.0.0-0.1.a1
- Updated package version number

* Thu Sep 22 2011 Jack Magne <jmagne@redhat.com> 9.0.7-1
- Bugzilla Bug #730146 - SSL handshake picks non-FIPS ciphers in FIPS mode (cfu)
- Bugzilla Bug #730162 - TPS/TKS token enrollment failure in FIPS mode
  (hsm+NSS).  (jmagne)
- Bugzilla Bug #737184 - TPS UI display admin user name as
  "undefined TUS Administrator". (awnuk)
- Bugzilla Bug #735191 - in ou=tokens, token_type not getting updated if a
  card is changed from one type to another (awnuk)

* Wed Aug 10 2011 Jack Magne <jmagne@redhat.com> 9.0.6-1
- Bugzilla Bug #725572 - Starting TPS subsystem with no pre-existing audit
  log file does not write audit messages.

* Thu Jul 14 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.5-1
- Bugzilla Bug #697035 - TPS database schema not populated correctly
  (alee)
- Bugzilla Bug #694569 - parameter used by pkiremove not updated (alee)
- Bugzilla Bug #696851 - TPS crashes that cause AuditVerify on TPS audit
  logs - some of the signatures are failing. (jmagne)
- Bugzilla Bug #699837 - service command is not fully backwards
  compatible with Dogtag pki subsystems (mharmsen)
- Bugzilla Bug #696443 - ESC display Smartcard renewal operation success
  for a failed renewal operation. (jmagne)
- Bugzilla Bug #707095 - tps delete user operation should check for roles
  (not have them passed in) (alee)
- Bugzilla Bug #717813 - EV_AUDIT_LOG_SHUTDOWN audit log not generated
  for tps and ca on server shutdown (alee)
- Bugzilla Bug #717765 - TPS configuration: logging into security domain
  from tps does not work with clientauth=want. (alee)
- Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)

* Tue Apr 26 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.4-1
- Bugzilla Bug #697035 - TPS database schema not populated correctly
- Bugzilla Bug #694569 - parameter used by pkiremove not updated
- Bugzilla Bug #696851 - TPS crashes that cause AuditVerify on
  TPS audit logs - some of the signatures are failing.
- Bugzilla Bug #699837 - service command is not fully backwards compatible
  with Dogtag pki subsystems

* Tue Apr 5 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.3-1
- Bugzilla Bug #690950 - Update Dogtag Packages for Fedora 15 (beta)
- Bugzilla Bug #691867 - add ldaps support through perLDAP

* Fri Mar 25 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.2-1
- Bugzilla Bug #690950 - Update Dogtag Packages for Fedora 15 (beta)
- Bugzilla Bug #684381 - CS.cfg specifies incorrect type of comments
- Bugzilla Bug #689956 - TPS Configuration with nethsm: audit signing
  certificate location is not configured to nethsm in CS.cfg

* Thu Mar 17 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.1-1
- Bugzilla Bug #688763 - Rebase updated Dogtag Packages for Fedora 15 (alpha)
- Bugzilla Bug #676421 - CC: Remove unused TPS interface calls and add
  audit logging
- Bugzilla Bug #676678 - Missing audit log messages for Secure Channel
  Generation.
- Bugzilla Bug #606944 - Convert TPS to use ldap utilities and API from
  OpenLDAP instead of the Mozldap
- Bugzilla Bug #676152 - Token enrollment with symmetric key change over
  fails.
- Bugzilla Bug #674396 - TPS: some audit signatures failed to verify
- Bugzilla Bug #680567 - CC doc: remove update.applet.directory audit
  message from TPS doc.
- Bugzilla Bug #681066 - TPS authentication crash when exercising audit
  log message.
- Bugzilla Bug #684259 - incorrect group used for tps operators

* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0 --> Dogtag 9.0.0
- Bugzilla Bug #620863 - saved CS.cfg files should be moved to a subdirectory
  to avoid cluttering
- Bugzilla Bug #607373 - add self test framework to TPS subsytem
- Bugzilla Bug #607374 - add self test to TPS self test framework
- Bugzilla Bug #624847 - Installed TPS cannot be started to be configured.
- Bugzilla Bug #620925 - CC: auditor needs to be able to download audit logs
  in the java subsystems
- Bugzilla Bug #547507 - Token renewal: certs on the token is deleted when
  one of the certs on the token is outside renewal grace period.
- Bugzilla Bug #622535 - 64 bit host zlib uncompress operation fails when
  reading data from token.
- Bugzilla Bug #497931 - CS 8.0 -- Have to download and stall the trust chain
  through ESC even if it was already installed in the browser.
- Bugzilla Bug #579790 - errors in ESC communications can leave unusable
  tokens and inconsistent data in TPS
- Bugzilla Bug #631474 - Token enrollment with TPS Client fails with error
  'Applet memory exceeded when writing out final token data'
- Bugzilla Bug #488762 - Found HTTP TRACE method enabled on TPS
- Bugzilla Bug #633405 - Tps client unable to perform token enrollment when
  tried to load certificates with 2048 bit keys
- Bugzilla Bug #558100 - host challenge of the Secure Channel needs to be
  generated on TKS instead of TPS.
- Bugzilla Bug #574942 - TPS database has performance problems with a large
  number of tokens
- Bugzilla Bug #637982 - some selftest parameters are not properly substituted
- Bugzilla Bug #637824 - TPS UI: Profile state in CS.cfg is Pending Approval
  after agent approve and Enable
- Bugzilla Bug #223313 - should do random generated IV param
  for symmetric keys
- Bugzilla Bug #628995 - TPS CC requirement: Unused predicates for revocation
  controls for TPS enrollment profiles should be removed.
- Bugzilla Bug #642084 - CC feature: Key Management -provide signature
  verification functions (TPS subsystem)
- Bugzilla Bug #646545 - TPS Agent tab: displays approve list parameter with
  last character chopped.
- Bugzilla Bug #532724 - Feature: ESC Security officer work station should
  display % of operation complete for format SO card
- Bugzilla Bug #647364 - CC: audit signing certs for JAVA subsystems fail
  CIMC cert verification (expose updated cert verification function in JSS)
- Bugzilla Bug #651087 - TPS UI Admin tab display 'null' string in the
  General configuration
- Bugzilla Bug #651916 - kra and ocsp are using incorrect ports
  to talk to CA and complete configuration in DonePanel
- Bugzilla Bug #632425 - Port to tomcat6
- Bugzilla Bug #638377 - Generate PKI UI components which exclude
  a GUI interface
- Bugzilla Bug #640042 - TPS Installlation Wizard: need to move Module Panel
  up to before Security Domain Panel
- Bugzilla Bug #642357 - CC Feature- Self-Test plugins only check for
  validity
- Bugzilla Bug #643206 - New CMake based build system for Dogtag
- Bugzilla Bug #499494 - change CA defaults to SHA2
- Bugzilla Bug #661128 - incorrect CA ports used for revoke, unrevoke certs
  in TPS
- Bugzilla Bug #223314 - AOL: Better activities logs
- Bugzilla Bug #651001 - TPS does not create a password for entries in ldap.
  This violates STIG requirements
- Bugzilla Bug #512248 - Status mismatch for the encryption cert in tps agent
  and CA when a temporary smart card is issued.
- Bugzilla Bug #666902 - TPS needs to call CERT_VerifyCertificate() correctly
- Bugzilla Bug #223319 - Certificate Status inconsistency between token db
  and CA
- Bugzilla Bug #669055 - TPS server does not re-start when signedAudit
  logging is turned ON
- Bugzilla Bug #606944 - Convert TPS to use ldap utilities and API from
  OpenLDAP instead of the Mozldap
- Bugzilla Bug #606944 - Convert TPS to use ldap utilities and API from
  OpenLDAP instead of the Mozldap
- Bugzilla Bug #614639 - 64k gemalto usb token no longer works properly
  after a "logout" request is issued
- Bugzilla Bug #671522 - TPS AuditVerify fails.
- Bugzilla Bug #669804 - on active token re-enroll, TPS does not revoke and
  remove existing certs.
- Bugzilla Bug #656666 - Please Update Spec File to use 'ghost' on files
  in /var/run and /var/lock

* Wed Aug 04 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.2-1
- Bugzilla Bug #601299 - tps installation does not update security domain
- Bugzilla Bug #527593 - More robust signature digest alg, like SHA256
  instead of SHA1 for ECC
- Bugzilla Bug #528236 - rhcs80 web conf wizard - cannot specify CA signing
  algorithm
- Bugzilla Bug #533510 - tps exception, cannot start when signed audit true
- Bugzilla Bug #529280 - TPS returns HTTP data without ending in 0rn
  per RFC 2616
- Bugzilla Bug #498299 - Should not be able to change the status manually
  on a token marked as permanently lost or destroyed
- Bugzilla Bug #554892 - configurable frequency signed audit
- Bugzilla Bug #500700 - tps log rotation
- Bugzilla Bug #562893 - tps shutdown if audit logs full
- Bugzilla Bug #557346 - Name Constraints Extension cant be marked critical
- Bugzilla Bug #556152 - ACL changes to CA and OCSP
- Bugzilla Bug #556167 - ACL changes to CA and OCSP
- Bugzilla Bug #581004 - add more audit logging to the TPS
- Bugzilla Bug #566517 - CC: Add client auth to OCSP publishing,
  and move to a client-auth port
- Bugzilla Bug #565842 - Clone config throws errors - fix key_algorithm
- Bugzilla Bug #581017 - enabling log signing from tps ui pages causes tps
  crash
- Bugzilla Bug #581004 - add more audit logs
- Bugzilla Bug #595871 - CC: TKS needed audit message changes
- Bugzilla Bug #598752 - Common Criteria: TKS ACL analysis result.
- Bugzilla Bug #598666 - Common Criteria: incorrect ACLs for signedAudit
- Bugzilla Bug #504905 - Smart card renewal should load old encryption cert
  on the token.
- Bugzilla Bug #499292 - TPS - Enrollments where keys are recovered need
  to do both GenerateNewKey and RecoverLast operation for encryption key.
- Bugzilla Bug #498299 - fix case where no transitions available
- Bugzilla Bug #604186 - Common Criteria: TPS: Key Recovery needs
  to meet CC requirements
- Bugzilla Bug #604178 - Common Criteria: TPS: cert registration needs
  to meet CC requirements
- Bugzilla Bug #600968 - Common Criteria: TPS: cert registration needs
  to meet CC requirements
- Bugzilla Bug #607381 - Common Criteria: TPS: cert registration needs
  to meet CC requirements

* Thu Apr 08 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.1-1
- Bugzilla Bug #564131 - Config wizard : all subsystems - done panel text
  needs correction

* Tue Feb 16 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-8
- Bugzilla Bug #566060 - Add 'pki-native-tools' as a runtime dependency
  for RA, and TPS . . .

* Fri Jan 29 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-7
- Bugzilla Bug #553852 - Review Request: pki-tps - The Dogtag PKI System
  Token Processing System
- Bugzilla Bug #553078 - Apply "registry" logic to pki-tps . . .
- Applied filters for unwanted perl provides and requires
- Applied %{?_smp_mflags} option to 'make'
- Removed manual 'strip' commands

* Thu Jan 28 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-6
- Bugzilla Bug #553078 - Apply "registry" logic to pki-tps . . .
- Bugzilla Bug #553852 - Review Request: pki-tps - The Dogtag PKI System
  Token Processing System

* Wed Jan 27 2010 Kevin Wright <kwright@redhat.com> 1.3.0-5
- Bugzilla Bug #553852 - Review Request: pki-tps - The Dogtag PKI System
  Token Processing System
- Per direction from the Fedora community,
  removed the following explicit "Requires":
      perl-HTML-Parser
      perl-HTML-Tagset
      perl-Parse-RecDescent
      perl-URI
      perl-XML-NamespaceSupport
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
- Removed BuildRequires bash - Removed 'with exceptions' from License

* Mon Nov 02 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-2
- Bugzilla Bug #X - Packaging for Fedora Dogtag PKI
- Prepended directory path in front of setup_package
- Take ownership of pki tps directory.

* Fri Oct 16 2009 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Packaging for Fedora Dogtag PKI

