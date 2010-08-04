Name:           dogtag-pki-ca-ui
Version:        1.3.2
Release:        1%{?dist}
Summary:        Dogtag Certificate System - Certificate Authority User Interface
URL:            http://pki.fedoraproject.org/
License:        GPLv2
Group:          System Environment/Base

BuildArch:      noarch

BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  ant

Provides:       pki-ca-ui = %{version}-%{release}

Obsoletes:      pki-ca-ui < %{version}-%{release}

Source0:        http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

# NOTE:  The 'Dogtag Certificate System' and 'Red Hat Certificate System'
#        may NOT co-exist on the same system!
#
#        For example, with the advent of EPEL packages, a user may attempt to
#        install a Dogtag Certificate System on a system which already contains
#        a Red Hat Certificate System.  Since the 'dogtag-pki-ca-ui' UI
#        package conflicts with the 'redhat-pki-ca-ui' UI package,
#        disallow this action by notifying the user that these two packages
#        conflict.  (see Bugzilla Bug #580282 for details)
#
Conflicts:        redhat-pki-ca-ui

%description
Dogtag Certificate System is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The Dogtag Certificate Authority User Interface contains the graphical
user interface for the Dogtag Certificate Authority.

%prep

%setup -q

%build
ant \
    -Dproduct.ui.flavor.prefix="dogtag" \
    -Dproduct.prefix="pki" \
    -Dproduct="ca-ui" \
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
* Wed Aug 4 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.2-1
- Bugzilla Bug #472597 - Disable policy code,UI
- Bugzilla Bug #436990 - browser tab shows no distinguishable names for systems

* Wed Apr 7 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.1-2
- Bugzilla Bug #580282 - Dogtag PKI UI Packages should "Conflict" with
  associated Red Hat PKI UI Packages . . .

* Tue Mar 9 2010 Ade Lee <alee@redhat.com> 1.3.1-1
- Bugzilla Bug #545935 -  Add new client-auth ee port to address CVE-2009-3555
  TLS: MITM attacks via session renegotiation

* Thu Jan 14 2010 Matthew Harmsen <mharmsen@redhat.com> 1.3.0-4
- Bugzilla Bug #522208 -  New Package for Dogtag PKI: dogtag-pki-ca-ui
- Removed "Requires:  bash"

* Mon Dec 14 2009 Kevin Wright <kwright@redhat.com> 1.3.0-3
- Removed 'with exceptions' from License

* Mon Nov 2 2009 Ade Lee <alee@redhat.com> 1.3.0-2
- Bugzilla Bug #522208 - Packaging for Fedora Dogtag
- Take ownership of directories

* Tue Oct 13 2009 Ade Lee <alee@redhat.com> 1.3.0-1
- Bugzilla Bug #522208 - Packaging for Fedora Dogtag
