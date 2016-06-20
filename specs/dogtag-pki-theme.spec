Name:             dogtag-pki-theme
Version:          10.3.3
Release:          1%{?dist}
Summary:          Certificate System - Dogtag PKI Theme Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Base

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake
BuildRequires:    java-1.8.0-openjdk-devel
BuildRequires:    jpackage-utils >= 1.7.5-10

%if 0%{?rhel}
# NOTE:  In the future, as a part of its path, this URL will contain a release
#        directory which consists of the fixed number of the upstream release
#        upon which this tarball was originally based.
Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{version}/%{release}/rhel/%{name}-%{version}%{?prerel}.tar.gz
%else
Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{version}/%{release}/%{name}-%{version}%{?prerel}.tar.gz
%endif

%global overview                                                       \
Several PKI packages utilize a "virtual" theme component.  These       \
"virtual" theme components are "Provided" by various theme "flavors"   \
including "dogtag" or a user customized theme package.  Consequently,  \
all "dogtag" and any customized theme components MUST be mutually      \
exclusive!                                                             \
%{nil}

%description %{overview}


%package -n       dogtag-pki-server-theme
Summary:          Certificate System - PKI Server Framework User Interface
Group:            System Environment/Base

Obsoletes:        dogtag-pki-common-theme <= %{version}-%{release}
Obsoletes:        dogtag-pki-common-ui
Obsoletes:        dogtag-pki-ca-theme <= %{version}-%{release}
Obsoletes:        dogtag-pki-ca-ui
Obsoletes:        dogtag-pki-kra-theme <= %{version}-%{release}
Obsoletes:        dogtag-pki-kra-ui
Obsoletes:        dogtag-pki-ocsp-theme <= %{version}-%{release}
Obsoletes:        dogtag-pki-ocsp-ui
Obsoletes:        dogtag-pki-tks-theme <= %{version}-%{release}
Obsoletes:        dogtag-pki-tks-ui
Obsoletes:        dogtag-pki-ra-theme <= %{version}-%{release}
Obsoletes:        dogtag-pki-ra-ui
Obsoletes:        dogtag-pki-tps-theme <= %{version}-%{release}
Obsoletes:        dogtag-pki-tps-ui

Provides:         dogtag-pki-common-theme = %{version}-%{release}
Provides:         pki-server-theme = %{version}-%{release}
Provides:         pki-common-theme = %{version}-%{release}
Provides:         pki-common-ui = %{version}-%{release}

Provides:         dogtag-pki-ca-theme = %{version}-%{release}
Provides:         pki-ca-theme = %{version}-%{release}
Provides:         pki-ca-ui = %{version}-%{release}

Provides:         dogtag-pki-kra-theme = %{version}-%{release}
Provides:         pki-kra-theme = %{version}-%{release}
Provides:         pki-kra-ui = %{version}-%{release}

Provides:         dogtag-pki-ocsp-theme = %{version}-%{release}
Provides:         pki-ocsp-theme = %{version}-%{release}
Provides:         pki-ocsp-ui = %{version}-%{release}

Provides:         dogtag-pki-tks-theme = %{version}-%{release}
Provides:         pki-tks-theme = %{version}-%{release}
Provides:         pki-tks-ui = %{version}-%{release}

Provides:         dogtag-pki-tps-theme = %{version}-%{release}
Provides:         pki-tps-theme = %{version}-%{release}
Provides:         pki-tps-ui = %{version}-%{release}

%description -n   dogtag-pki-server-theme
This PKI Server Framework User Interface contains
the Dogtag textual and graphical user interface for the PKI Server Framework.

This package is used by the Dogtag Certificate System.

%{overview}


%package -n       dogtag-pki-console-theme
Summary:          Certificate System - PKI Console User Interface
Group:            System Environment/Base

Requires:         java-1.8.0-openjdk

%if 0%{?rhel}
# EPEL version of Dogtag "theme" conflicts with all versions of Red Hat "theme"
Conflicts:        redhat-pki-console-theme
Conflicts:        redhat-pki-console-ui
%endif

Obsoletes:        dogtag-pki-console-ui <= 9

Provides:         pki-console-theme = %{version}-%{release}
Provides:         pki-console-ui = %{version}-%{release}

%description -n   dogtag-pki-console-theme
This PKI Console User Interface contains
the Dogtag textual and graphical user interface for the PKI Console.

This package is used by the Dogtag Certificate System.

%{overview}


%prep


%setup -q -n %{name}-%{version}%{?prerel}


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVERSION=%{version}-%{release} \
	-DVAR_INSTALL_DIR:PATH=/var \
	-DBUILD_DOGTAG_PKI_THEME:BOOL=ON \
	-DJAVA_LIB_INSTALL_DIR=%{_jnidir} \
	..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"


# NOTE:  Several "theme" packages require ownership of the "/usr/share/pki"
#        directory because the PKI subsystems (CA, KRA, OCSP, TKS, TPS)
#        which require them may be installed either independently or in
#        multiple combinations.

%files -n dogtag-pki-server-theme
%defattr(-,root,root,-)
%doc dogtag/common-ui/LICENSE
%dir %{_datadir}/pki
%{_datadir}/pki/common-ui/


%files -n dogtag-pki-console-theme
%defattr(-,root,root,-)
%doc dogtag/console-ui/LICENSE
%{_javadir}/pki/


%changelog
* Mon Jun 20 2016 Dogtag Team <pki-devel@redhat.com> 10.3.3-1
- Updated release number to 10.3.3-1

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.3-0.1
- Updated version number to 10.3.3-0.1

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-2
- Updated 'java', 'java-headless', and 'java-devel' dependencies to 1:1.8.0.

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-1
- Updated version number to 10.3.2-1

* Wed May 18 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-0.1
- Updated version number to 10.3.2-0.1

* Tue May 17 2016 Dogtag Team <pki-devel@redhat.com> 10.3.1-1
- Updated version number to 10.3.1-1 (to allow upgrade from 10.3.0.b1)

* Mon May 16 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0-1
- Updated version number to 10.3.0-1

* Mon Apr 18 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0.b1-1
- Build for F24 beta

* Thu Apr  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0.a2-1
- Updated build for F24 alpha

* Fri Mar  4 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0.a1-1
- Build for F24 alpha

* Sat Aug  8 2015 Dogtag Team <pki-devel@redhat.com> 10.3.0-0.1
- Updated version number to 10.3.0-0.1

* Sat Jul 18 2015 Dogtag Team <pki-devel@redhat.com> 10.2.7-0.1
- Updated version number to 10.2.7-0.1

* Sat Jul 18 2015 Dogtag Team <pki-devel@redhat.com> 10.2.6-1
- Update release number for release build

* Sat Jun 20 2015 Dogtag Team <pki-devel@redhat.com> 10.2.6-0.2
- Remove ExcludeArch directive

* Fri Jun 19 2015 Dogtag Team <pki-devel@redhat.com> 10.2.6-0.1
- Updated version number to 10.2.6-0.1

* Fri Jun 19 2015 Dogtag Team <pki-devel@redhat.com> 10.2.5-1
- Update release number for release build

* Tue May 26 2015 Dogtag Team <pki-devel@redhat.com> 10.2.5-0.1
- Updated version number to 10.2.5-0.1

* Tue May 26 2015 Dogtag Team <pki-devel@redhat.com> 10.2.4-1
- Update release number for release build

* Thu Apr 23 2015 Dogtag Team <pki-devel@redhat.com> 10.2.4-0.1
- Updated version number to 10.2.4-0.1

* Thu Apr 23 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-1
- Update release number for release build

* Thu Apr  9 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-0.1
- Reverted version number back to 10.2.3-0.1

* Mon Apr  6 2015 Dogtag Team <pki-devel@redhat.com> 10.3.0-0.1
- Updated version number to 10.3.0-0.1

* Wed Mar 18 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-0.1
- Updated version number to 10.2.3-0.1

* Tue Mar 17 2015 Dogtag Team <pki-devel@redhat.com> 10.2.2-1
- Update release number for release build

* Thu Jan  8 2015 Dogtag Team <pki-devel@redhat.com> 10.2.2-0.1
- Updated version number to 10.2.2-0.1

* Thu Jan  8 2015 Dogtag Team <pki-devel@redhat.com> 10.2.1-1
- Update release number for release build

* Mon Nov 24 2014 Christina Fu <cfu@redhat.com> 10.2.1-0.2
- Ticket 1198 Bugzilla 1158410 add TLS range support to server.xml by default and upgrade (cfu)
- PKI Trac Ticket #1211 - New release overwrites old source tarball (mharmsen)
- up the release number to 0.2

* Fri Oct 24 2014 Dogtag Team <pki-devel@redhat.com> 10.2.1-0.1
- Updated version number to 10.2.1-0.1.

* Tue Sep  9 2014 Matthew Harmsen <mharmsen@redhat.com> 10.2.0-2
- PKI TRAC Ticket #1136 - Remove ipa-pki-theme component
- Remove 'ca-ui', 'kra-ui', 'ocsp-ui', 'ra-ui', 'tks-ui', and 'tps-ui'
  directories
- Consolidate 'pki-core' packages

* Wed Sep  3 2014 Dogtag Team <pki-devel@redhat.com> 10.2.0-1
- Update release number for release build

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 10.1.0-2
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Fri Nov 22 2013 Dogtag Team <pki-devel@redhat.com> 10.2.0-0.1
- Updated version number to 10.2.0-0.1.

* Fri Nov 15 2013 Ade Lee <alee@redhat.com> 10.1.0-1
- Trac Ticket 788 - Clean up spec files
- Update release number for release build

* Sun Nov 10 2013 Ade Lee <alee@redhat.com> 10.1.0-0.3
- Change release number for beta build

* Fri Jun 14 2013 Endi S. Dewata <edewata@redhat.com> 10.1.0-0.2
- Updated dependencies to Java 1.7.

* Tue May 7 2013 Ade Lee <alee@redhat.com> 10.1.0-0.1
- Change release number for 10.1 development

* Fri Apr 26 2013 Ade Lee <alee@redhat.com> 10.0.2-1
- Change release number for official release.

* Wed Mar 27 2013 Endi S. Dewata <edewata@redhat.com> 10.0.2-0.1
- Updated version number to 10.0.2-0.1.

* Fri Dec 7 2012 Ade Lee <alee@redhat.com> 10.0.0-1
- Update to official release for rc1

* Wed Nov 21 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.9.b3
- Removed Dogtag RA and TPS packages.

* Tue Nov 13 2012 Ade Lee <alee@redhat.com> 10.0.0-0.8.b3
- Added needed Requires for dogtag-pki-common-theme

* Mon Nov 12 2012 Ade Lee <alee@redhat.com> 10.0.0-0.7.b3
- Update release to b3

* Fri Nov 9 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.6.b2
- Removed Dogtag CA, KRA, OCSP, TKS theme packages.

* Thu Nov 8 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.5.b2
- Renamed dogtag-pki-common-theme to dogtag-pki-server-theme.
- Fixed theme package dependencies.

* Mon Oct 29 2012 Ade Lee <alee@redhat.com> 10.0.0-0.4.b2
- Update release to b2

* Wed Oct 24 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.3.b1
- TRAC Ticket #350 - Dogtag 10: Remove version numbers from PKI jar files . . .

* Mon Oct 8 2012 Ade Lee <alee@redhat.com> 10.0.0-0.2.b1
- Update release to b1

* Mon Oct 1 2012 Ade Lee <alee@redhat.com> 10.0.0-0.2.a2
- Update release to a2

* Sun Sep 30 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.2.a1
- Modified CMake to use RPM version number

* Wed Feb  1 2012 Nathan Kinder <nkinder@redhat.com> 10.0.0-0.1.a1
- Updated package version number

* Thu Sep 22 2011 Andrew Wnuk <awnuk@redhat.com> 9.0.9-1
- 'dogtag-pki-ca-theme'
-      Bugzilla Bug #737423 - Ability to view migrated policy requests
       is very limited. (awnuk)
- 'dogtag-pki-common-theme'
- 'dogtag-pki-console-theme'
- 'dogtag-pki-kra-theme'
- 'dogtag-pki-ocsp-theme'
- 'dogtag-pki-ra-theme'
- 'dogtag-pki-tks-theme'
- 'dogtag-pki-tps-theme'
-      Bugzilla Bug #737184 - TPS UI display admin user name as
       "undefined TUS Administrator". (awnuk)

* Mon Sep 12 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.8-1
- 'dogtag-pki-ca-theme'
- 'dogtag-pki-common-theme'
- 'dogtag-pki-console-theme'
-      Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . .
- 'dogtag-pki-kra-theme'
- 'dogtag-pki-ocsp-theme'
- 'dogtag-pki-ra-theme'
- 'dogtag-pki-tks-theme'
- 'dogtag-pki-tps-theme'

* Tue Aug 23 2011 Ade Lee <alee@redhat.com> 9.0.7-1
- 'dogtag-pki-ca-theme'
-      Bugzilla Bug #712931 - CS requires too many ports
       to be open in the FW
- 'dogtag-pki-common-theme'
- 'dogtag-pki-console-theme'
- 'dogtag-pki-kra-theme'
-      Bugzilla Bug #712931 - CS requires too many ports
       to be open in the FW
- 'dogtag-pki-ocsp-theme'
-      Bugzilla Bug #712931 - CS requires too many ports
       to be open in the FW
- 'dogtag-pki-ra-theme'
- 'dogtag-pki-tks-theme'
-      Bugzilla Bug #712931 - CS requires too many ports
       to be open in the FW
- 'dogtag-pki-tps-theme'

* Thu Jul 14 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.6-1
- 'dogtag-pki-ca-theme'
-      Bugzilla Bug #695015 - Serial No. of a revoked certificate is not
       populated in the CA signedAudit messages (alee)
-      Bugzilla Bug #694143 - CA Agent not returning specified request (awnuk)
-      Bugzilla Bug #704351 - remove help buttons in agent and ee UI in all
       subsystems (alee)
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'dogtag-pki-common-theme'
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'dogtag-pki-console-theme'
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'dogtag-pki-kra-theme'
-      Bugzilla Bug #694143 - CA Agent not returning specified request (awnuk)
-      Bugzilla Bug #704351 - remove help buttons in agent and ee UI in all
       subsystems (alee)
-      Bugzilla Bug #714068 - KRA: remove monitor servlet from kra (alee)
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'dogtag-pki-ocsp-theme'
-      Bugzilla Bug #704351 - remove help buttons in agent and ee UI in all
       subsystems (alee)
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'dogtag-pki-ra-theme'
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'dogtag-pki-tks-theme'
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'dogtag-pki-tps-theme'
-      Bugzilla Bug #491008 - Security Officer: Format Card, Set Home URL and
       Format SO card has 'home phone URL' (jmagne)
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)

* Tue Apr 26 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.5-1
- 'dogtag-pki-ca-theme'
-     Bugzilla Bug #695015 - Serial No. of a revoked certificate is not
      populated in the CA signedAudit messages
-     Bugzilla Bug #694143 - CA Agent not returning specified request
- 'dogtag-pki-common-theme'
- 'dogtag-pki-console-theme'
- 'dogtag-pki-kra-theme'
-     Bugzilla Bug #694143 - CA Agent not returning specified request
- 'dogtag-pki-ocsp-theme'
- 'dogtag-pki-ra-theme'
- 'dogtag-pki-tks-theme'
- 'dogtag-pki-tps-theme'

* Tue Apr 5 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.4-1
- Bugzilla Bug #690950 - Update Dogtag Packages for Fedora 15 (beta)
- 'dogtag-pki-ca-theme'
- 'dogtag-pki-common-theme'
- 'dogtag-pki-console-theme'
- 'dogtag-pki-kra-theme'
- 'dogtag-pki-ocsp-theme'
- 'dogtag-pki-ra-theme'
- 'dogtag-pki-tks-theme'
- 'dogtag-pki-tps-theme'
-     Bugzilla Bug #691447 - TPS UI Admin tab 'Add new token' opens a
      page with text 'Agent operations: Add new tokens'.
-     Bugzilla Bug #691867 - add ldaps support through perLDAP

* Fri Mar 25 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.3-1
- Bugzilla Bug #690950 - Update Dogtag Packages for Fedora 15 (beta)
- 'dogtag-pki-ca-theme'
- 'dogtag-pki-common-theme'
-     Bugzilla Bug #683581 - CA configuration with ECC(Default
      EC curve-nistp521) CA fails with 'signing operation failed'
- 'dogtag-pki-console-theme'
- 'dogtag-pki-kra-theme'
- 'dogtag-pki-ocsp-theme'
- 'dogtag-pki-ra-theme'
- 'dogtag-pki-tks-theme'
- 'dogtag-pki-tps-theme'
-     Bugzilla Bug #684259 - wrong group used for tps operators

* Thu Mar 17 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.2-1
- Bugzilla Bug #688763 - Rebase updated Dogtag Packages for Fedora 15 (alpha)
- Bugzilla Bug #676421 - CC: Remove unused TPS interface calls and add
  audit logging
- Bugzilla Bug #606944 - Convert TPS to use ldap utilities and API from
  OpenLDAP instead of the Mozldap
- Bugzilla Bug #678142 - Flakey JAR packaging encountered on Fedora 15
  when using Mock

* Fri Feb 4 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.1-1
- Bugzilla Bug #606944 - Convert TPS to use ldap utilities and API from
  OpenLDAP instead of the Mozldap

* Fri Jan 21 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-3
- Bugzilla Bug #671030 - Review Request: dogtag-pki-theme - Certificate
  System, Dogtag PKI Theme Components
-    Augmented overview description.
-    Isolated and corrected EPEL information
-    Added comment regarding '/usr/share/pki' file ownership
- 'dogtag-pki-common-theme'
-     Bugzilla Bug #671058 - ipa2 - ipa-server-install fails on pkisilent -
      xml parsing string -- ?
- 'dogtag-pki-ca-theme'
-     Bugzilla Bug #564207 - Searches for completed requests in the agent
      interface returns zero entries

* Thu Jan 20 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-2
- Bugzilla Bug #671030 - Review Request: dogtag-pki-theme - Certificate
  System, Dogtag PKI Theme Components
-     Added 'java-devel' and 'jpackage' build requirements
-     Added 'java' runtime requirement to 'dogtag-pki-console-theme'
-     Added file mode change to installation section
-     Deleted explicit file mode change from files inventory section

* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Updated Dogtag 1.3.x --> Dogtag 2.0.0 --> Dogtag 9.0.0
- 'dogtag-pki-ca-theme' (formerly 'dogtag-pki-ca-ui')
-     Bugzilla Bug #555927 - rhcs80 - AgentRequestFilter servlet and port
      fowarding for agent services
-     Bugzilla Bug #524916 - ECC key constraints plug-ins should be based on
      ECC curve names (not on key sizes).
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #653576 - tomcat5 does not always run filters on servlets
      as expected
- 'dogtag-pki-common-theme' (formerly 'dogtag-pki-common-ui')
-     Bugzilla Bug #630126 - clone installation wizard basedn for internal
      db should not be changeable
-     Bugzilla Bug #533529 - rhcs80 web wizard - broken login page when
      using valid pin
-     Bugzilla Bug #223336 - ECC: unable to clone a ECC CA
-     Bugzilla Bug #528249 - rhcs80 - web pages, css -moz-opacity deprecated
-     Bugzilla Bug #638242 - Installation Wizard: at SizePanel, fix selection
      of signature algorithm; and for ECC curves
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #653576 - tomcat5 does not always run filters on servlets
      as expected
- 'dogtag-pki-console-theme' (formerly 'dogtag-pki-console-ui')
-     Bugzilla Bug #607380 - CC: Make sure Java Console can configure all
      security relevant config items
-     Bugzilla Bug #516632 - RHCS 7.1 - CS Incorrectly Issuing Multiple
      Certificates from the Same Request
-     Bugzilla Bug #451874 - RFE - Java console - Certificate Wizard missing
      e.c. support
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #643206 - New CMake based build system for Dogtag
-     Bugzilla Bug #656733 - Standardize jar install location and jar names
- 'dogtag-pki-kra-theme' (formerly 'dogtag-pki-kra-ui')
-     Bugzilla Bug #555927 - rhcs80 - AgentRequestFilter servlet and port
      fowarding for agent services
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #653576 - tomcat5 does not always run filters on servlets
      as expected
- 'dogtag-pki-ocsp-theme' (formerly 'dogtag-pki-ocsp-ui')
-     Bugzilla Bug #630121 - OCSP responder lacking option to delete or
      disable a CA that it serves
-     Bugzilla Bug #555927 - rhcs80 - AgentRequestFilter servlet and port
      fowarding for agent services
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #653576 - tomcat5 does not always run filters on servlets
      as expected
- 'dogtag-pki-ra-theme' (formerly 'dogtag-pki-ra-ui')
-     Bugzilla Bug #533529 - rhcs80 web wizard - broken login page when
      using valid pin
-     Bugzilla Bug #528249 - rhcs80 - web pages, css -moz-opacity deprecated
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
- 'dogtag-pki-tks-theme' (formerly 'dogtag-pki-tks-ui')
-     Bugzilla Bug #555927 - rhcs80 - AgentRequestFilter servlet and port
      fowarding for agent services
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #653576 - tomcat5 does not always run filters on servlets
      as expected
- 'dogtag-pki-tps-theme' (formerly 'dogtag-pki-tps-ui')
-     Bugzilla Bug #607373 - add self test framework to TPS subsytem
-     Bugzilla Bug #607374 - add self test to TPS self test framework
-     Bugzilla Bug #624847 - Installed TPS cannot be started to be configured.
-     Bugzilla Bug #630018 - Delete button missing from Edit Profile page.
-     Bugzilla Bug #609331 - Should not be able to manually change the status
      on a token marked as permanently lost or destroyed - fix confirmation
      page
-     Bugzilla Bug #533529 - rhcs80 web wizard - broken login page when
      using valid pin
-     Bugzilla Bug #642692 - TPS UI Admin tab: Remove 'Submit For Approval'
      greyed out button from the subsystem connection edit page.
-     Bugzilla Bug #646545 - TPS Agent tab: displays approve list parameter
      with last character chopped.
-     Bugzilla Bug #528249 - rhcs80 - web pages, css -moz-opacity deprecated
-     Bugzilla Bug #532724 - Feature: ESC Security officer work station should
      display % of operation complete for format SO card
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface

