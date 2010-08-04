Name:           pki-tks
Version:        1.3.3
Release:        1%{?dist}
Summary:        Dogtag Certificate System - Token Key Service
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Daemons

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant
BuildRequires:  java-devel >= 1:1.6.0
BuildRequires:  jpackage-utils
BuildRequires:  jss >= 4.2.6
BuildRequires:  pki-common
BuildRequires:  pki-util
BuildRequires:  tomcatjss

Requires:       java >= 1:1.6.0
Requires:       pki-tks-ui
Requires:       pki-common
Requires:       pki-console
Requires:       pki-selinux
Requires:       pki-silent
Requires(post):    chkconfig
Requires(preun):   chkconfig
Requires(preun):   initscripts
Requires(postun):  initscripts

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
    -Dinit.d="rc.d/init.d" \
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
mkdir -p %{buildroot}%{_localstatedir}/lock/pki/tks
mkdir -p %{buildroot}%{_localstatedir}/run/pki/tks
cd %{buildroot}%{_javadir}
mv tks.jar tks-%{version}.jar
ln -s tks-%{version}.jar tks.jar

# supply convenience symlink(s) for backwards compatibility
mkdir -p %{buildroot}%{_javadir}/pki/tks
cd %{buildroot}%{_javadir}/pki/tks
ln -s ../../tks.jar tks.jar

%clean
rm -rf %{buildroot}

%post
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add pki-tksd || :

%preun
if [ $1 = 0 ] ; then
    /sbin/service pki-tksd stop >/dev/null 2>&1
    /sbin/chkconfig --del pki-tksd || :
fi

%postun
if [ "$1" -ge "1" ] ; then
    /sbin/service pki-tksd condrestart >/dev/null 2>&1 || :
fi

%files
%defattr(-,root,root,-)
%doc LICENSE
%{_initrddir}/*
%{_javadir}/*
%{_datadir}/pki/
%{_localstatedir}/lock/*
%{_localstatedir}/run/*

%changelog
* Wed Aug 4 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.3-1
- Bugzilla Bug #606556 - Add known session key test to TKS self test set
- Bugzilla Bug #608086 - CC: CA, OCSP, and DRM need to add more audit calls
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
- Bugzilla Bug #595391 - session domain table to be moved to ldap
- Bugzilla Bug #598643 - Common Criteria: incorrect ACLs (non-existing groups)
- Bugzilla Bug #504359 - pkiconsole - Administrator Group's Description
  References Fedora

* Mon Apr 26 2010 Ade Lee <alee@redhat.com> 1.3.2-1
- Bugzilla Bug 584917- Can not access CA Configuration Web UI after CA installation

* Tue Feb 16 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.1-2
- Bugzilla Bug #566059 -  Add 'pki-console' as a runtime dependency
  for CA, KRA, OCSP, and TKS . . .

* Mon Feb 8 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.1-1
- Bugzilla Bug #562986 -  Supply convenience symlink(s) for backwards
  compatibility (rename jar files as appropriate)

* Fri Jan 15 2010 Kevin Wright <kwright@redhat.com> 1.3.0-4
- Removed BuildRequires:  dogtag-pki-tks-ui

* Fri Jan 8 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-3
- Corrected "|| :" scriptlet logic (see Bugzilla Bug #475895)
- Bugzilla Bug #553075 - Apply "registry" logic to pki-tks . . .
- Bugzilla Bug #553847 - New Package for Dogtag PKI: pki-tks

* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-2
- Removed 'with exceptions' from License

* Fri Oct 16 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #X - Packaging for Fedora Dogtag
