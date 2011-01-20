Name:             dogtag-pki-theme
Version:          9.0.0
Release:          2%{?dist}
Summary:          Certificate System - Dogtag PKI Theme Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Base

BuildArch:        noarch

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake
BuildRequires:    java-devel >= 1:1.6.0
BuildRequires:    jpackage-utils

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%if 0%{?rhel}
ExcludeArch:      ppc ppc64 s390 s390x
%endif

%global overview                                                       \
Several PKI packages require a "virtual" Theme component.  These       \
"virtual" Theme components are "Provided" by various Theme "flavors"   \
including "dogtag", "redhat", and "ipa".  Consequently,                \
all "dogtag", "redhat", and "ipa" Theme components MUST be             \
mutually exclusive!                                                    \
%{nil}

%description %{overview}


%package -n       dogtag-pki-common-theme
Summary:          Certificate System - PKI Common Framework User Interface
Group:            System Environment/Base

Conflicts:        ipa-pki-common-theme
Conflicts:        ipa-pki-common-ui
Conflicts:        redhat-pki-common-theme
Conflicts:        redhat-pki-common-ui

Obsoletes:        dogtag-pki-common-ui <= 1.3.3

Provides:         pki-common-theme = %{version}-%{release}
Provides:         pki-common-ui = %{version}-%{release}

%description -n   dogtag-pki-common-theme
This PKI Common Framework User Interface contains
the Dogtag textual and graphical user interface for the PKI Common Framework.

This package is used by the Dogtag Certificate System.

%{overview}


%package -n       dogtag-pki-ca-theme
Summary:          Certificate System - Certificate Authority User Interface
Group:            System Environment/Base

Requires:         dogtag-pki-common-theme = %{version}-%{release}

Conflicts:        ipa-pki-ca-theme
Conflicts:        ipa-pki-ca-ui
Conflicts:        redhat-pki-ca-theme
Conflicts:        redhat-pki-ca-ui

Obsoletes:        dogtag-pki-ca-ui <= 1.3.2

Provides:         pki-ca-theme = %{version}-%{release}
Provides:         pki-ca-ui = %{version}-%{release}

%description -n   dogtag-pki-ca-theme
This Certificate Authority (CA) User Interface contains
the Dogtag textual and graphical user interface for the CA.

This package is used by the Dogtag Certificate System.

%{overview}


%package -n       dogtag-pki-kra-theme
Summary:          Certificate System - Data Recovery Manager User Interface
Group:            System Environment/Base

Requires:         dogtag-pki-common-theme = %{version}-%{release}

Conflicts:        redhat-pki-kra-theme
Conflicts:        redhat-pki-kra-ui

Obsoletes:        dogtag-pki-kra-ui <= 1.3.2

Provides:         pki-kra-theme = %{version}-%{release}
Provides:         pki-kra-ui = %{version}-%{release}

%description -n   dogtag-pki-kra-theme
This Data Recovery Manager (DRM) User Interface contains
the Dogtag textual and graphical user interface for the DRM.

This package is used by the Dogtag Certificate System.

%{overview}


%package -n       dogtag-pki-ocsp-theme
Summary:          Certificate System - Online Certificate Status Protocol Manager User Interface
Group:            System Environment/Base

Requires:         dogtag-pki-common-theme = %{version}-%{release}

Conflicts:        redhat-pki-ocsp-theme
Conflicts:        redhat-pki-ocsp-ui

Obsoletes:        dogtag-pki-ocsp-ui <= 1.3.1

Provides:         pki-ocsp-theme = %{version}-%{release}
Provides:         pki-ocsp-ui = %{version}-%{release}

%description -n   dogtag-pki-ocsp-theme
This Online Certificate Status Protocol (OCSP) Manager User Interface contains
the Dogtag textual and graphical user interface for the OCSP Manager.

This package is used by the Dogtag Certificate System.

%{overview}


%package -n       dogtag-pki-ra-theme
Summary:          Certificate System - Registration Authority User Interface
Group:            System Environment/Base

Conflicts:        redhat-pki-ra-theme
Conflicts:        redhat-pki-ra-ui

Obsoletes:        dogtag-pki-ra-ui <= 1.3.2

Provides:         pki-ra-theme = %{version}-%{release}
Provides:         pki-ra-ui = %{version}-%{release}

%description -n   dogtag-pki-ra-theme
This Registration Authority (RA) User Interface contains
the Dogtag textual and graphical user interface for the RA.

This package is used by the Dogtag Certificate System.

%{overview}


%package -n       dogtag-pki-tks-theme
Summary:          Certificate System - Token Key Service User Interface
Group:            System Environment/Base

Requires:         dogtag-pki-common-theme = %{version}-%{release}

Conflicts:        redhat-pki-tks-theme
Conflicts:        redhat-pki-tks-ui

Obsoletes:        dogtag-pki-tks-ui <= 1.3.1

Provides:         pki-tks-theme = %{version}-%{release}
Provides:         pki-tks-ui = %{version}-%{release}

%description -n   dogtag-pki-tks-theme
This Token Key Service (TKS) User Interface contains
the Dogtag textual and graphical user interface for the TKS.

This package is used by the Dogtag Certificate System.

%{overview}


%package -n       dogtag-pki-tps-theme
Summary:          Certificate System - Token Processing System User Interface
Group:            System Environment/Base

Conflicts:        redhat-pki-tps-theme
Conflicts:        redhat-pki-tps-ui

Obsoletes:        dogtag-pki-tps-ui <= 1.3.3

Provides:         pki-tps-theme = %{version}-%{release}
Provides:         pki-tps-ui = %{version}-%{release}

%description -n   dogtag-pki-tps-theme
This Token Processing System (TPS) User Interface contains
the Dogtag textual and graphical user interface for the TPS.

This package is used by the Dogtag Certificate System.

%{overview}


%package -n       dogtag-pki-console-theme
Summary:          Certificate System - PKI Console User Interface
Group:            System Environment/Base

Requires:         java >= 1:1.6.0

Conflicts:        redhat-pki-console-theme
Conflicts:        redhat-pki-console-ui

Obsoletes:        dogtag-pki-console-ui <= 1.3.2

Provides:         pki-console-theme = %{version}-%{release}
Provides:         pki-console-ui = %{version}-%{release}

%description -n   dogtag-pki-console-theme
This PKI Console User Interface contains
the Dogtag textual and graphical user interface for the PKI Console.

This package is used by the Dogtag Certificate System.

%{overview}


%prep


%setup -q


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DBUILD_DOGTAG_PKI_THEME:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"

chmod 755 %{buildroot}%{_datadir}/pki/tps-ui/cgi-bin/sow/cfg.pl


%files -n dogtag-pki-common-theme
%defattr(-,root,root,-)
%doc dogtag/common-ui/LICENSE
%dir %{_datadir}/pki
%{_datadir}/pki/common-ui/


%files -n dogtag-pki-ca-theme
%defattr(-,root,root,-)
%doc dogtag/ca-ui/LICENSE
%{_datadir}/pki/ca-ui/


%files -n dogtag-pki-kra-theme
%defattr(-,root,root,-)
%doc dogtag/kra-ui/LICENSE
%{_datadir}/pki/kra-ui/


%files -n dogtag-pki-ocsp-theme
%defattr(-,root,root,-)
%doc dogtag/ocsp-ui/LICENSE
%{_datadir}/pki/ocsp-ui/


%files -n dogtag-pki-ra-theme
%defattr(-,root,root,-)
%doc dogtag/ra-ui/LICENSE
%dir %{_datadir}/pki
%{_datadir}/pki/ra-ui/


%files -n dogtag-pki-tks-theme
%defattr(-,root,root,-)
%doc dogtag/tks-ui/LICENSE
%{_datadir}/pki/tks-ui/


%files -n dogtag-pki-tps-theme
%defattr(-,root,root,-)
%doc dogtag/tps-ui/LICENSE
%dir %{_datadir}/pki
%{_datadir}/pki/tps-ui/


%files -n dogtag-pki-console-theme
%defattr(-,root,root,-)
%doc dogtag/console-ui/LICENSE
%{_javadir}/pki/


%changelog
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

