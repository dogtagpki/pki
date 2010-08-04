Name:           dogtag-pki-tps-ui
Version:        1.3.3
Release:        1%{?dist}
Summary:        Dogtag Certificate System - Token Processing System User Interface
URL:            http://pki.fedoraproject.org/
License:        GPLv2 and LGPLv2
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant

Provides:       pki-tps-ui =  %{version}-%{release}

Obsoletes:      pki-tps-ui <  %{version}-%{release}

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

# NOTE:  The 'Dogtag Certificate System' and 'Red Hat Certificate System'
#        may NOT co-exist on the same system!
#
#        For example, with the advent of EPEL packages, a user may attempt to
#        install a Dogtag Certificate System on a system which already contains
#        a Red Hat Certificate System.  Since the 'dogtag-pki-tps-ui' UI
#        package conflicts with the 'redhat-pki-tps-ui' UI package,
#        disallow this action by notifying the user that these two packages
#        conflict.  (see Bugzilla Bug #580282 for details)
#
Conflicts:        redhat-pki-tps-ui

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Token Processing System User Interface contains the graphical
user interface for the Dogtag Token Processing System.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="dogtag" \
    -Dproduct.prefix="pki" \
    -Dproduct="tps-ui" \
    -Dversion="%{version}"

%install
rm -rf %{buildroot}
cd dist/binary
unzip %{name}-%{version}.zip -d %{buildroot}

%clean
rm -rf %{buildroot}

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_datadir}/pki/

%changelog
* Wed Aug 4 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.3-1
- Bugzilla Bug #541031 - Security officer: Format card operation with a blank
  token throws 'Can't format a card that belong to security officer'.
- Bugzilla Bug #527593 - More robust signature digest alg, like SHA256
  instead of SHA1 for ECC
- Bugzilla Bug #528236 - rhcs80 web conf wizard - cannot specify CA signing
  algorithm
- Bugzilla Bug #533510 - tps exception, cannot start when signed audit true
- Bugzilla Bug #529280 - TPS returns HTTP data without ending in 0rn per
  RFC 2616
- Bugzilla Bug #498299 - Should not be able to change the status manually
  on a token marked as permanently lost or destroyed
- Bugzilla Bug #554892 - configurable frequency signed audit
- Bugzilla Bug #500700 - tps log rotation
- Bugzilla Bug #562893 - tps shutdown if audit logs full
- Bugzilla Bug #557346 - Name Constraints Extension cant be marked critical
- Bugzilla Bug #556152 - ACL changes to CA and OCSP
- Bugzilla Bug #556167 - ACL changes to CA and OCSP
- Bugzilla Bug #581004 - add more audit logging to the TPS
- Bugzilla Bug #566517 - CC: Add client auth to OCSP publishing, and move
  to a client-auth port
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
- Bugzilla Bug #604186 - Common Criteria: TPS: Key Recovery needs to meet CC
  requirements
- Bugzilla Bug #604178 - Common Criteria: TPS: cert registration needs to meet
  CC requirements
- Bugzilla Bug #600968 - Common Criteria: TPS: cert registration needs to meet
  CC requirements
- Bugzilla Bug #607381 - Common Criteria: TPS: cert registration needs to meet
  CC requirements
- Bugzilla Bug #436990 - browser tab shows no distinguishable names for systems

* Thu Apr 8 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.2-1
- Bugzilla Bug #564131 - Config wizard : all subsystems - done panel text
  needs correction

* Wed Apr 7 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.1-2
- Bugzilla Bug #580282 - Dogtag PKI UI Packages should "Conflict" with
  associated Red Hat PKI UI Packages . . .

* Wed Jan 20 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.1-1
- fixed "tarfileset" typo

* Wed Jan 20 2010 Dennis Gilmore <dennis@ausil.us> - 1.3.0-6
- add patch to deal with stricter syntax in ant 1.6.5

* Mon Jan 18 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-5
- Bugzilla Bug #553851 - New Package for Dogtag PKI: dogtag-pki-tps-ui
- Fixed various licensing headers

* Thu Jan 14 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-4
- Bugzilla Bug #553851 - New Package for Dogtag PKI: dogtag-pki-tps-ui
- Removed "Requires:  bash"

* Wed Jan 6 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Bugzilla Bug #553851 - New Package for Dogtag PKI: dogtag-pki-tps-ui
- Take ownership of directories

* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-2
- Removed 'with exceptions' from License

* Fri Oct 16 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Fedora Packaging Changes
