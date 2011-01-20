Name:             pki-core
Version:          9.0.1
Release:          1%{?dist}
Summary:          Certificate System - PKI Core Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Daemons

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

# jss requires versioning to meet both build and runtime requirements
# tomcatjss requires versioning since version 2.0.0 requires tomcat6
# pki-common-theme requires versioning to meet runtime requirements
# pki-ca-theme requires versioning to meet runtime requirements
BuildRequires:    cmake
BuildRequires:    java-devel >= 1:1.6.0
BuildRequires:    jpackage-utils
BuildRequires:    jss >= 4.2.6-12
BuildRequires:    ldapjdk
BuildRequires:    nspr-devel
BuildRequires:    nss-devel
BuildRequires:    openldap-devel
BuildRequires:    osutil
BuildRequires:    pkgconfig
BuildRequires:    policycoreutils
BuildRequires:    selinux-policy-devel
BuildRequires:    tomcatjss >= 2.0.0
BuildRequires:    velocity
BuildRequires:    xalan-j2
BuildRequires:    xerces-j2

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

%if 0%{?rhel}
ExcludeArch:      ppc ppc64 s390 s390x
%endif

%global saveFileContext() \
if [ -s /etc/selinux/config ]; then \
     . %{_sysconfdir}/selinux/config; \
     FILE_CONTEXT=%{_sysconfdir}/selinux/%1/contexts/files/file_contexts; \
     if [ "${SELINUXTYPE}" == %1 -a -f ${FILE_CONTEXT} ]; then \
          cp -f ${FILE_CONTEXT} ${FILE_CONTEXT}.%{name}; \
     fi \
fi;

%global relabel() \
. %{_sysconfdir}/selinux/config; \
FILE_CONTEXT=%{_sysconfdir}/selinux/%1/contexts/files/file_contexts; \
selinuxenabled; \
if [ $? == 0  -a "${SELINUXTYPE}" == %1 -a -f ${FILE_CONTEXT}.%{name} ]; then \
     fixfiles -C ${FILE_CONTEXT}.%{name} restore; \
     rm -f ${FILE_CONTEXT}.%name; \
fi;

%global overview                                                       \
==================================                                     \
||  ABOUT "CERTIFICATE SYSTEM"  ||                                     \
==================================                                     \
                                                                       \
Certificate System (CS) is an enterprise software system designed      \
to manage enterprise Public Key Infrastructure (PKI) deployments.      \
                                                                       \
PKI Core contains fundamental packages required by Certificate System, \
and consists of the following components:                              \
                                                                       \
  * pki-setup                                                          \
  * pki-symkey                                                         \
  * pki-native-tools                                                   \
  * pki-util                                                           \
  * pki-util-javadoc                                                   \
  * pki-java-tools                                                     \
  * pki-java-tools-javadoc                                             \
  * pki-common                                                         \
  * pki-common-javadoc                                                 \
  * pki-selinux                                                        \
  * pki-ca                                                             \
  * pki-silent                                                         \
                                                                       \
which comprise the following PKI subsystems:                           \
                                                                       \
  * Certificate Authority (CA)                                         \
                                                                       \
For deployment purposes, Certificate System requires ONE AND ONLY ONE  \
of the following "Mutually-Exclusive" PKI Theme packages:              \
                                                                       \
  * ipa-pki-theme    (IPA deployments)                                 \
  * dogtag-pki-theme (Dogtag Certificate System deployments)           \
  * redhat-pki-theme (Red Hat Certificate System deployments)          \
                                                                       \
%{nil}

%description %{overview}


%package -n       pki-setup
Summary:          Certificate System - PKI Instance Creation & Removal Scripts
Group:            System Environment/Base

BuildArch:        noarch

Requires:         perl-Crypt-SSLeay
Requires:         policycoreutils
Requires:         openldap-clients

%description -n   pki-setup
PKI setup scripts are used to create and remove instances from PKI deployments.

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-symkey
Summary:          Symmetric Key JNI Package
Group:            System Environment/Libraries

Requires:         java >= 1:1.6.0
Requires:         jpackage-utils
Requires:         jss >= 4.2.6-12
Requires:         nss

Provides:         symkey = %{version}-%{release}

Obsoletes:        symkey < %{version}-%{release}

%description -n   pki-symkey
The Symmetric Key Java Native Interface (JNI) package supplies various native
symmetric key operations to Java programs.

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-native-tools
Summary:          Certificate System - Native Tools
Group:            System Environment/Base

Requires:         openldap-clients
Requires:         nss
Requires:         nss-tools

%description -n   pki-native-tools
These platform-dependent PKI executables are used to help make
Certificate System into a more complete and robust PKI solution.

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-util
Summary:          Certificate System - PKI Utility Framework
Group:            System Environment/Base

BuildArch:        noarch

Requires:         java >= 1:1.6.0
Requires:         jpackage-utils
Requires:         jss >= 4.2.6-12
Requires:         ldapjdk

%description -n   pki-util
The PKI Utility Framework is required by the following four PKI subsystems:

    the Certificate Authority (CA),
    the Data Recovery Manager (DRM),
    the Online Certificate Status Protocol (OCSP) Manager, and
    the Token Key Service (TKS).

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-util-javadoc
Summary:          Certificate System - PKI Utility Framework Javadocs
Group:            Documentation

BuildArch:        noarch

Requires:         pki-util = %{version}-%{release}

%description -n   pki-util-javadoc
This documentation pertains exclusively to version %{version} of
the PKI Utility Framework.

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-java-tools
Summary:          Certificate System - PKI Java-Based Tools
Group:            System Environment/Base

BuildArch:        noarch

Requires:         java >= 1:1.6.0
Requires:         pki-native-tools = %{version}-%{release}
Requires:         pki-util = %{version}-%{release}

%description -n   pki-java-tools
These platform-independent PKI executables are used to help make
Certificate System into a more complete and robust PKI solution.

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-java-tools-javadoc
Summary:          Certificate System - PKI Java-Based Tools Javadocs
Group:            Documentation

BuildArch:        noarch

Requires:         pki-java-tools = %{version}-%{release}

%description -n   pki-java-tools-javadoc
This documentation pertains exclusively to version %{version} of
the PKI Java-Based Tools.

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-common
Summary:          Certificate System - PKI Common Framework
Group:            System Environment/Base

BuildArch:        noarch

Requires:         java >= 1:1.6.0
Requires:         jss >= 4.2.6-12
Requires:         osutil
Requires:         pki-common-theme >= 9.0.0
Requires:         pki-java-tools = %{version}-%{release}
Requires:         pki-setup = %{version}-%{release}
Requires:         pki-symkey = %{version}-%{release}
Requires:         tomcatjss >= 2.0.0
Requires:         %{_javadir}/ldapjdk.jar
Requires:         %{_javadir}/velocity.jar
Requires:         %{_javadir}/xalan-j2.jar
Requires:         %{_javadir}/xalan-j2-serializer.jar
Requires:         %{_javadir}/xerces-j2.jar
Requires:         velocity

%description -n   pki-common
The PKI Common Framework is required by the following four PKI subsystems:

    the Certificate Authority (CA),
    the Data Recovery Manager (DRM),
    the Online Certificate Status Protocol (OCSP) Manager, and
    the Token Key Service (TKS).

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-common-javadoc
Summary:          Certificate System - PKI Common Framework Javadocs
Group:            Documentation

BuildArch:        noarch

Requires:         pki-common = %{version}-%{release}

%description -n   pki-common-javadoc
This documentation pertains exclusively to version %{version} of
the PKI Common Framework.

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-selinux
Summary:          Certificate System - PKI Selinux Policies
Group:            System Environment/Base

BuildArch:        noarch

Requires:         policycoreutils
Requires:         selinux-policy-targeted

%description -n   pki-selinux
Selinux policies for the PKI components.

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-ca
Summary:          Certificate System - Certificate Authority
Group:            System Environment/Daemons

BuildArch:        noarch

Requires:         java >= 1:1.6.0
Requires:         pki-ca-theme >= 9.0.0
Requires:         pki-common = %{version}-%{release}
Requires:         pki-selinux = %{version}-%{release}
Requires(post):   chkconfig
Requires(preun):  chkconfig
Requires(preun):  initscripts
Requires(postun): initscripts

%description -n   pki-ca
The Certificate Authority (CA) is a required PKI subsystem which issues,
renews, revokes, and publishes certificates as well as compiling and
publishing Certificate Revocation Lists (CRLs).

The Certificate Authority can be configured as a self-signing Certificate
Authority, where it is the root CA, or it can act as a subordinate CA,
where it obtains its own signing certificate from a public CA.

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-silent
Summary:          Certificate System - Silent Installer
Group:            System Environment/Base

BuildArch:        noarch

Requires:         java >= 1:1.6.0
Requires:         pki-common = %{version}-%{release}

%description -n   pki-silent
The PKI Silent Installer may be used to "automatically" configure
the following PKI subsystems in a non-graphical (batch) fashion
including:

    the Certificate Authority (CA),
    the Data Recovery Manager (DRM),
    the Online Certificate Status Protocol (OCSP) Manager,
    the Registration Authority (RA),
    the Token Key Service (TKS), and/or
    the Token Processing System (TPS).

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%prep


%setup -q


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVAR_INSTALL_DIR:PATH=/var -DBUILD_PKI_CORE:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"

cd %{buildroot}%{_libdir}/symkey
%{__rm} symkey.jar
%{__ln_s} symkey-%{version}.jar symkey.jar

cd %{buildroot}%{_jnidir}
%{__rm} symkey.jar
%{__ln_s} %{_libdir}/symkey/symkey.jar symkey.jar


%pre -n pki-selinux
%saveFileContext targeted


%post -n pki-selinux
semodule -s targeted -i %{_datadir}/selinux/modules/pki.pp
%relabel targeted


%preun -n pki-selinux
if [ $1 = 0 ]; then
     %saveFileContext targeted
fi


%postun -n pki-selinux
if [ $1 = 0 ]; then
     semodule -s targeted -r pki
     %relabel targeted
fi


%post -n pki-ca
# This adds the proper /etc/rc*.d links for the script
/sbin/chkconfig --add pki-cad || :


%preun -n pki-ca
if [ $1 = 0 ] ; then
    /sbin/service pki-cad stop >/dev/null 2>&1
    /sbin/chkconfig --del pki-cad || :
fi


%postun -n pki-ca
if [ "$1" -ge "1" ] ; then
    /sbin/service pki-cad condrestart >/dev/null 2>&1 || :
fi


%files -n pki-setup
%defattr(-,root,root,-)
%doc base/setup/LICENSE
%{_bindir}/pkicreate
%{_bindir}/pkiremove
%dir %{_datadir}/pki
%dir %{_datadir}/pki/scripts
%{_datadir}/pki/scripts/pkicommon.pm
%dir %{_localstatedir}/lock/pki
%dir %{_localstatedir}/run/pki


%files -n pki-symkey
%defattr(-,root,root,-)
%doc base/symkey/LICENSE
%{_jnidir}/symkey.jar
%{_libdir}/symkey/


%files -n pki-native-tools
%defattr(-,root,root,-)
%doc base/native-tools/LICENSE base/native-tools/doc/README
%{_bindir}/bulkissuance
%{_bindir}/p7tool
%{_bindir}/revoker
%{_bindir}/setpin
%{_bindir}/sslget
%{_bindir}/tkstool
%dir %{_datadir}/pki
%{_datadir}/pki/native-tools/


%files -n pki-util
%defattr(-,root,root,-)
%doc base/util/LICENSE
%dir %{_javadir}/pki
%{_javadir}/pki/pki-cmsutil-%{version}.jar
%{_javadir}/pki/pki-cmsutil.jar
%{_javadir}/pki/pki-nsutil-%{version}.jar
%{_javadir}/pki/pki-nsutil.jar

%files -n pki-util-javadoc
%defattr(-,root,root,-)
%{_javadocdir}/pki-util-%{version}/


%files -n pki-java-tools
%defattr(-,root,root,-)
%doc base/java-tools/LICENSE
%{_bindir}/AtoB
%{_bindir}/AuditVerify
%{_bindir}/BtoA
%{_bindir}/CMCEnroll
%{_bindir}/CMCRequest
%{_bindir}/CMCResponse
%{_bindir}/CMCRevoke
%{_bindir}/CRMFPopClient
%{_bindir}/ExtJoiner
%{_bindir}/GenExtKeyUsage
%{_bindir}/GenIssuerAltNameExt
%{_bindir}/GenSubjectAltNameExt
%{_bindir}/HttpClient
%{_bindir}/OCSPClient
%{_bindir}/PKCS10Client
%{_bindir}/PKCS12Export
%{_bindir}/PrettyPrintCert
%{_bindir}/PrettyPrintCrl
%{_bindir}/TokenInfo
%{_javadir}/pki/pki-tools-%{version}.jar
%{_javadir}/pki/pki-tools.jar

%files -n pki-java-tools-javadoc
%defattr(-,root,root,-)
%{_javadocdir}/pki-java-tools-%{version}/


%files -n pki-common
%defattr(-,root,root,-)
%doc base/common/LICENSE
%{_javadir}/pki/pki-certsrv-%{version}.jar
%{_javadir}/pki/pki-certsrv.jar
%{_javadir}/pki/pki-cms-%{version}.jar
%{_javadir}/pki/pki-cms.jar
%{_javadir}/pki/pki-cmsbundle-%{version}.jar
%{_javadir}/pki/pki-cmsbundle.jar
%{_javadir}/pki/pki-cmscore-%{version}.jar
%{_javadir}/pki/pki-cmscore.jar
%{_datadir}/pki/scripts/functions
%{_datadir}/pki/scripts/pki_apache_initscript
%{_datadir}/pki/setup/

%files -n pki-common-javadoc
%defattr(-,root,root,-)
%{_javadocdir}/pki-common-%{version}/


%files -n pki-selinux
%defattr(-,root,root,-)
%doc base/selinux/LICENSE
%{_datadir}/selinux/modules/pki.pp


%files -n pki-ca
%defattr(-,root,root,-)
%doc base/ca/LICENSE
%{_initrddir}/pki-cad
%{_javadir}/pki/pki-ca-%{version}.jar
%{_javadir}/pki/pki-ca.jar
%dir %{_datadir}/pki/ca
%{_datadir}/pki/ca/conf/
%{_datadir}/pki/ca/emails/
%dir %{_datadir}/pki/ca/profiles
%{_datadir}/pki/ca/profiles/ca/
%{_datadir}/pki/ca/webapps/
%{_datadir}/pki/ca/setup/
%dir %{_localstatedir}/lock/pki/ca
%dir %{_localstatedir}/run/pki/ca


%files -n pki-silent
%defattr(-,root,root,-)
%doc base/silent/LICENSE
%{_bindir}/pkisilent
%{_javadir}/pki/pki-silent-%{version}.jar
%{_javadir}/pki/pki-silent.jar
%{_datadir}/pki/silent/


%changelog
* Tue Jan 18 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.1-1
- Allow 'pki-native-tools' to be installed independently of 'pki-setup'
- Removed explicit 'pki-setup' requirement from 'pki-ca'
  (since it already requires 'pki-common')
- 'pki-setup'
-     Bugzilla Bug #223343 - pkicreate: should add 'pkiuser' to nfast group
-     Bugzilla Bug #629377 - Selinux errors during pkicreate CA, KRA, OCSP
      and TKS.
-     Bugzilla Bug #555927 - rhcs80 - AgentRequestFilter servlet and port
      fowarding for agent services
-     Bugzilla Bug #632425 - Port to tomcat6
-     Bugzilla Bug #606946 - Convert Native Tools to use ldapAPI from
      OpenLDAP instead of the Mozldap
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #643206 - New CMake based build system for Dogtag
-     Bugzilla Bug #658926 - org.apache.commons.lang class not found on F13
-     Bugzilla Bug #661514 - CMAKE build system requires rules to make
      javadocs
-     Bugzilla Bug #665388 - jakarta-* jars have been renamed to apache-*,
      pkicreate fails Fedora 14 and above
-     Bugzilla Bug #23346 - Two conflicting ACL list definitions in source
      repository
-     Bugzilla Bug #656733 - Standardize jar install location and jar names
- 'pki-symkey'
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #643206 - New CMake based build system for Dogtag
-     Bugzilla Bug #644056 - CS build contains warnings
- 'pki-native-tools'
-     template change
-     Bugzilla Bug #606946 - Convert Native Tools to use ldapAPI from
      OpenLDAP instead of the Mozldap
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #643206 - New CMake based build system for Dogtag
-     Bugzilla Bug #644056 - CS build contains warnings
- 'pki-util'
-     Bugzilla Bug #615814 - rhcs80 - profile policyConstraintsCritical
      cannot be set to true
-     Bugzilla Bug #224945 - javadocs has missing descriptions, contains
      empty packages
-     Bugzilla Bug #621337 - Limit the received senderNonce value to 16 bytes.
-     Bugzilla Bug #621338 - Include a server randomly-generated 16 byte
      senderNonce in all signed SCEP responses.
-     Bugzilla Bug #621327 - Provide switch disabling algorithm downgrade
      attack in SCEP
-     Bugzilla Bug #621334 - Provide an option to set default hash algorithm
      for signing SCEP response messages.
-     Bugzilla Bug #635033 - At installation wizard selecting key types other
      than CA's signing cert will fail
-     Bugzilla Bug #645874 - rfe ecc - add ecc curve name support in JSS and
      CS interface
-     Bugzilla Bug #488253 - com.netscape.cmsutil.ocsp.BasicOCSPResponse
      ASN.1 encoding/decoding is broken
-     Bugzilla Bug #551410 - com.netscape.cmsutil.ocsp.TBSRequest ASN.1
      encoding/decoding is incomplete
-     Bugzilla Bug #550331 - com.netscape.cmsutil.ocsp.ResponseData ASN.1
      encoding/decoding is incomplete
-     Bugzilla Bug #623452 - rhcs80 pkiconsole profile policy editor limit
      policy extension to 5 only
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #651977 - turn off ssl2 for java servers (server.xml)
-     Bugzilla Bug #643206 - New CMake based build system for Dogtag
-     Bugzilla Bug #661514 - CMAKE build system requires rules to make
      javadocs
-     Bugzilla Bug #658188 - remove remaining references to tomcat5
-     Bugzilla Bug #656733 - Standardize jar install location and jar names
-     Bugzilla Bug #223319 - Certificate Status inconsistency between token
      db and CA
-     Bugzilla Bug #531137 - RHCS 7.1 - Running out of Java Heap Memory
      During CRL Generation
- 'pki-java-tools'
-     Bugzilla Bug #224945 - javadocs has missing descriptions, contains
      empty packages
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #659004 - CC: AuditVerify hardcoded with SHA-1
-     Bugzilla Bug #643206 - New CMake based build system for Dogtag
-     Bugzilla Bug #661514 - CMAKE build system requires rules to make
      javadocs
-     Bugzilla Bug #662156 - HttpClient is hard-coded to handle only up to
      5000 bytes
-     Bugzilla Bug #656733 - Standardize jar install location and jar names
- 'pki-common'
-     Bugzilla Bug #583822 - CC: ACL issues from CA interface CC doc review
-     Bugzilla Bug #623745 - SessionTimer with LDAPSecurityDomainSessionTable
      started before configuration completed
-     Bugzilla Bug #620925 - CC: auditor needs to be able to download audit
      logs in the java subsystems
-     Bugzilla Bug #615827 - rhcs80 - profile policies need more than 5
      policy mappings (seem hardcoded)
-     Bugzilla Bug #224945 - javadocs has missing descriptions, contains
      empty packages
-     Bugzilla Bug #548699 - subCA's admin certificate should be generated by
      itself
-     Bugzilla Bug #621322 - Provide switch disabling SCEP support in CA
-     Bugzilla Bug #563386 - rhcs80 ca crash on invalid inputs to profile
      caAgentServerCert (null cert_request)
-     Bugzilla Bug #621339 - SCEP one-time PIN can be used an unlimited
      number of times
-     Bugzilla Bug #583825 - CC: Obsolete servlets to be removed from web.xml
      as part of CC interface review
-     Bugzilla Bug #629677 - TPS: token enrollment fails.
-     Bugzilla Bug #621350 - Unauthenticated user can decrypt a one-time PIN
      in a SCEP request
-     Bugzilla Bug #503838 - rhcs71-80 external publishing ldap connection
      pools not reliable - improve connections or discovery
-     Bugzilla Bug #629769 - password decryption logs plain text password
-     Bugzilla Bug #583823 - CC: Auditing issues found as result of
      CC - interface review
-     Bugzilla Bug #632425 - Port to tomcat6
-     Bugzilla Bug #586700 - OCSP Server throws fatal error while using
      OCSP console for renewing SSL Server certificate.
-     Bugzilla Bug #621337 - Limit the received senderNonce value to 16 bytes.
-     Bugzilla Bug #621338 - Include a server randomly-generated 16 byte
      senderNonce in all signed SCEP responses.
-     Bugzilla Bug #607380 - CC: Make sure Java Console can configure all
      security relevant config items
-     Bugzilla Bug #558100 - host challenge of the Secure Channel needs to be
      generated on TKS instead of TPS.
-     Bugzilla Bug #489342 -
      com.netscape.cms.servlet.common.CMCOutputTemplate.java
      doesn't support EC
-     Bugzilla Bug #630121 - OCSP responder lacking option to delete or
      disable a CA that it serves
-     Bugzilla Bug #634663 - CA CMC response default hard-coded to SHA1
-     Bugzilla Bug #621327 - Provide switch disabling algorithm downgrade
      attack in SCEP
-     Bugzilla Bug #621334 - Provide an option to set default hash algorithm
      for signing SCEP response messages.
-     Bugzilla Bug #635033 - At installation wizard selecting key types other
      than CA's signing cert will fail
-     Bugzilla Bug #621341 - Add CA support for new SCEP key pair dedicated
      for SCEP signing and encryption.
-     Bugzilla Bug #223336 - ECC: unable to clone a ECC CA
-     Bugzilla Bug #539781 - rhcs 71 - CRLs Partitioned
      by Reason Code - onlySomeReasons ?
-     Bugzilla Bug #637330 - CC feature: Key Management - provide signature
      verification functions (JAVA subsystems)
-     Bugzilla Bug #223313 - should do random generated IV param
      for symmetric keys
-     Bugzilla Bug #555927 - rhcs80 - AgentRequestFilter servlet and port
      fowarding for agent services
-     Bugzilla Bug #630176 - Improve reliability of the LdapAnonConnFactory
-     Bugzilla Bug #524916 - ECC key constraints plug-ins should be based on
      ECC curve names (not on key sizes).
-     Bugzilla Bug #516632 - RHCS 7.1 - CS Incorrectly Issuing Multiple
      Certificates from the Same Request
-     Bugzilla Bug #648757 - expose and use updated cert verification
      function in JSS
-     Bugzilla Bug #638242 - Installation Wizard: at SizePanel, fix selection
      of signature algorithm; and for ECC curves
-     Bugzilla Bug #451874 - RFE - Java console - Certificate Wizard missing
      e.c. support
-     Bugzilla Bug #651040 - cloning shoud not include sslserver
-     Bugzilla Bug #542863 - RHCS8: Default cert audit nickname written to
      CS.cfg files imcomplete when the cert is stored on a hsm
-     Bugzilla Bug #360721 - New Feature: Profile Integrity Check . . .
-     Bugzilla Bug #651916 - kra and ocsp are using incorrect ports
      to talk to CA and complete configuration in DonePanel
-     Bugzilla Bug #642359 - CC Feature - need to verify certificate when it
      is added
-     Bugzilla Bug #653713 - CC: setting trust on a CIMC cert requires
      auditing
-     Bugzilla Bug #489385 - references to rhpki
-     Bugzilla Bug #499494 - change CA defaults to SHA2
-     Bugzilla Bug #623452 - rhcs80 pkiconsole profile policy editor limit
      policy extension to 5 only
-     Bugzilla Bug #649910 - Console: an auditor or agent can be added to
      an administrator group.
-     Bugzilla Bug #632425 - Port to tomcat6
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #651977 - turn off ssl2 for java servers (server.xml)
-     Bugzilla Bug #653576 - tomcat5 does not always run filters on servlets
      as expected
-     Bugzilla Bug #642357 - CC Feature- Self-Test plugins only check for
      validity
-     Bugzilla Bug #643206 - New CMake based build system for Dogtag
-     Bugzilla Bug #659004 - CC: AuditVerify hardcoded with SHA-1
-     Bugzilla Bug #661196 - ECC(with nethsm) subca configuration fails with
      Key Type RSA Not Matched despite using ECC key pairs for rootCA & subCA.
-     Bugzilla Bug #661889 - The Servlet TPSRevokeCert of the CA returns an
      error to TPS even if certificate in question is already revoked.
-     Bugzilla Bug #663546 - Disable the functionalities that are not exposed
      in the console
-     Bugzilla Bug #661514 - CMAKE build system requires rules to make
      javadocs
-     Bugzilla Bug #658188 - remove remaining references to tomcat5
-     Bugzilla Bug #649343 - Publishing queue should recover from CA crash.
-     Bugzilla Bug #491183 - rhcs rfe - add rfc 4523 support for pkiUser and
      pkiCA, obsolete 2252 and 2256
-     Bugzilla Bug #640710 - Current SCEP implementation does not support HSMs
-     Bugzilla Bug #656733 - Standardize jar install location and jar names
-     Bugzilla Bug #661142 - Verification should fail when
      a revoked certificate is added
-     Bugzilla Bug #642741 - CS build uses deprecated functions
-     Bugzilla Bug #670337 - CA Clone configuration throws TCP connection error
-     Bugzilla Bug #662127 - CC doc Error: SignedAuditLog expiration time
      interface is no longer available through console
- 'pki-selinux'
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #643206 - New CMake based build system for Dogtag
-     Bugzilla Bug #667153 - store nuxwdog passwords in kernel ring buffer -
      selinux changes
- 'pki-ca'
-     Bugzilla Bug #583822 - CC: ACL issues from CA interface CC doc review
-     Bugzilla Bug #620925 - CC: auditor needs to be able to download audit
      logs in the java subsystems
-     Bugzilla Bug #621322 - Provide switch disabling SCEP support in CA
-     Bugzilla Bug #583824 - CC: Duplicate servlet mappings found as part of
      CC interface doc review
-     Bugzilla Bug #621602 - pkiconsole: Click on 'Publishing' option with
      admin privilege throws error "You are not authorized to perform this
      operation".
-     Bugzilla Bug #583825 - CC: Obsolete servlets to be removed from web.xml
      as part of CC interface review
-     Bugzilla Bug #583823 - CC: Auditing issues found as result of
      CC - interface review
-     Bugzilla Bug #519291 - Deleting a CRL Issuing Point after edits throws
      'Internal Server Error'.
-     Bugzilla Bug #586700 - OCSP Server throws fatal error while using
      OCSP console for renewing SSL Server certificate.
-     Bugzilla Bug #621337 - Limit the received senderNonce value to 16 bytes.
-     Bugzilla Bug #621338 - Include a server randomly-generated 16 byte
      senderNonce in all signed SCEP responses.
-     Bugzilla Bug #558100 - host challenge of the Secure Channel needs to be
      generated on TKS instead of TPS.
-     Bugzilla Bug #630121 - OCSP responder lacking option to delete or
      disable a CA that it serves
-     Bugzilla Bug #634663 - CA CMC response default hard-coded to SHA1
-     Bugzilla Bug #621327 - Provide switch disabling algorithm downgrade
      attack in SCEP
-     Bugzilla Bug #621334 - Provide an option to set default hash algorithm
      for signing SCEP response messages.
-     Bugzilla Bug #539781 - rhcs 71 - CRLs Partitioned
      by Reason Code - onlySomeReasons ?
-     Bugzilla Bug #637330 - CC feature: Key Management - provide signature
      verification functions (JAVA subsystems)
-     Bugzilla Bug #555927 - rhcs80 - AgentRequestFilter servlet and port
      fowarding for agent services
-     Bugzilla Bug #524916 - ECC key constraints plug-ins should be based on
      ECC curve names (not on key sizes).
-     Bugzilla Bug #516632 - RHCS 7.1 - CS Incorrectly Issuing Multiple
      Certificates from the Same Request
-     Bugzilla Bug #638242 - Installation Wizard: at SizePanel, fix selection
      of signature algorithm; and for ECC curves
-     Bugzilla Bug #529945 - (Instructions and sample only) CS 8.0 GA
      release -- DRM and TKS do not seem to have CRL checking enabled
-     Bugzilla Bug #609641 - CC: need procedure (and possibly tools) to help
      correctly set up CC environment
-     Bugzilla Bug #509481 - RFE: support sMIMECapabilities extensions in
      certificates (RFC 4262)
-     Bugzilla Bug #651916 - kra and ocsp are using incorrect ports
      to talk to CA and complete configuration in DonePanel
-     Bugzilla Bug #511990 - rhcs 7.3, 8.0 - re-activate missing object
      signing support in RHCS
-     Bugzilla Bug #651977 - turn off ssl2 for java servers (server.xml)
-     Bugzilla Bug #489385 - references to rhpki
-     Bugzilla Bug #499494 - change CA defaults to SHA2
-     Bugzilla Bug #623452 - rhcs80 pkiconsole profile policy editor limit
      policy extension to 5 only
-     Bugzilla Bug #649910 - Console: an auditor or agent can be added to
      an administrator group.
-     Bugzilla Bug #632425 - Port to tomcat6
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #653576 - tomcat5 does not always run filters on servlets
      as expected
-     Bugzilla Bug #642357 - CC Feature- Self-Test plugins only check for
      validity
-     Bugzilla Bug #643206 - New CMake based build system for Dogtag
-     Bugzilla Bug #661128 - incorrect CA ports used for revoke, unrevoke
      certs in TPS
-     Bugzilla Bug #512496 - RFE rhcs80 - crl updates and scheduling feature 
-     Bugzilla Bug #661196 - ECC(with nethsm) subca configuration fails with
      Key Type RSA Not Matched despite using ECC key pairs for rootCA & subCA.
-     Bugzilla Bug #649343 - Publishing queue should recover from CA crash.
-     Bugzilla Bug #491183 - rhcs rfe - add rfc 4523 support for pkiUser and
      pkiCA, obsolete 2252 and 2256
-     Bugzilla Bug #223346 - Two conflicting ACL list definitions in source
      repository
-     Bugzilla Bug #640710 - Current SCEP implementation does not support HSMs
-     Bugzilla Bug #656733 - Standardize jar install location and jar names
-     Bugzilla Bug #661142 - Verification should fail when
      a revoked certificate is added
-     Bugzilla Bug #668100 - DRM storage cert has OCSP signing extended key
      usage
-     Bugzilla Bug #662127 - CC doc Error: SignedAuditLog expiration time
      interface is no longer available through console
-     Bugzilla Bug #531137 - RHCS 7.1 - Running out of Java Heap Memory
      During CRL Generation
- 'pki-silent'
-     Bugzilla Bug #627309 - pkisilent subca configuration fails.
-     Bugzilla Bug #640091 - pkisilent panels need to match with changed java
      subsystems
-     Bugzilla Bug #527322 - pkisilent ConfigureDRM should configure DRM
      Clone.
-     Bugzilla Bug #643053 - pkisilent DRM configuration fails
-     Bugzilla Bug #583754 - pki-silent needs an option to configure signing
      algorithm for CA certificates
-     Bugzilla Bug #489385 - references to rhpki
-     Bugzilla Bug #638377 - Generate PKI UI components which exclude a GUI
      interface
-     Bugzilla Bug #651977 - turn off ssl2 for java servers (server.xml)
-     Bugzilla Bug #640042 - TPS Installlation Wizard: need to move Module
      Panel up to before Security Domain Panel
-     Bugzilla Bug #643206 - New CMake based build system for Dogtag
-     Bugzilla Bug #588323 - Failed to enable cipher 0xc001
-     Bugzilla Bug #656733 - Standardize jar install location and jar names
-     Bugzilla Bug #645895 - pkisilent: add ability to select ECC curves,
      signing algorithm
-     Bugzilla Bug #658641 - pkisilent doesn't not properly handle passwords
      with special characters
-     Bugzilla Bug #642741 - CS build uses deprecated functions

* Thu Jan 13 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-3
- Bugzilla Bug #668839 - Review Request: pki-core
-   Removed empty "pre" from "pki-ca"
-   Consolidated directory ownership
-   Corrected file ownership within subpackages
-   Removed all versioning from NSS and NSPR packages

* Thu Jan 13 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-2
- Bugzilla Bug #668839 - Review Request: pki-core
-   Added component versioning comments
-   Updated JSS from "4.2.6-10" to "4.2.6-12"
-   Modified installation section to preserve timestamps
-   Removed sectional comments

* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision. (kwright@redhat.com & mharmsen@redhat.com)

