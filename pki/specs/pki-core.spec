###############################################################################
###                       P A C K A G E   H E A D E R                       ###
###############################################################################

Name:             pki-core
Version:          9.0.0
Release:          1%{?dist}
Summary:          Certificate System - PKI Core Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Daemons

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake
BuildRequires:    java-devel >= 1:1.6.0
BuildRequires:    jpackage-utils
BuildRequires:    jss >= 4.2.6-10
BuildRequires:    ldapjdk
BuildRequires:    nspr-devel >= 4.6.99
BuildRequires:    nss-devel >= 3.12.3.99
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
  * ipa-pki-theme    (IPA deployments - Null Theme)                    \
  * dogtag-pki-theme (Dogtag Certificate System deployments)           \
  * redhat-pki-theme (Red Hat Certificate System deployments)          \
                                                                       \
%{nil}

%description %{overview}


###############################################################################
###                   S U B P A C K A G E   H E A D E R S                   ###
###############################################################################

########################
##     pki-setup      ##
########################

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


########################
##     pki-symkey     ##
########################

%package -n       pki-symkey
Summary:          Symmetric Key JNI Package
Group:            System Environment/Libraries

Requires:         java >= 1:1.6.0
Requires:         jpackage-utils
Requires:         jss >= 4.2.6
Requires:         nss >= 3.12.3.99

Provides:         symkey = %{version}-%{release}

Obsoletes:        symkey < %{version}-%{release}

%description -n   pki-symkey
The Symmetric Key Java Native Interface (JNI) package supplies various native
symmetric key operations to Java programs.

This package is a part of the PKI Core used by the Certificate System.

%{overview}


########################
##  pki-native-tools  ##
########################

%package -n       pki-native-tools
Summary:          Certificate System - Native Tools
Group:            System Environment/Base

Requires:         openldap-clients
Requires:         nss >= 3.12.3.99
Requires:         nss-tools >= 3.12.3.99

%description -n   pki-native-tools
These platform-dependent PKI executables are used to help make
Certificate System into a more complete and robust PKI solution.

This package is a part of the PKI Core used by the Certificate System.

%{overview}


########################
##      pki-util      ##
########################

%package -n       pki-util
Summary:          Certificate System - PKI Utility Framework
Group:            System Environment/Base

BuildArch:        noarch

Requires:         java >= 1:1.6.0
Requires:         jpackage-utils
Requires:         jss >= 4.2.6
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


########################
##   pki-java-tools   ##
########################

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


########################
##     pki-common     ##
########################

%package -n       pki-common
Summary:          Certificate System - PKI Common Framework
Group:            System Environment/Base

BuildArch:        noarch

Requires:         java >= 1:1.6.0
Requires:         jss >= 4.2.6
Requires:         osutil
Requires:         pki-common-theme
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


########################
##    pki-selinux     ##
########################

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


########################
##       pki-ca       ##
########################

%package -n       pki-ca
Summary:          Certificate System - Certificate Authority
Group:            System Environment/Daemons

BuildArch:        noarch

Requires:         java >= 1:1.6.0
Requires:         pki-ca-theme
Requires:         pki-common = %{version}-%{release}
Requires:         pki-selinux = %{version}-%{release}
Requires:         pki-setup = %{version}-%{release}
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


########################
##     pki-silent     ##
########################

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


###############################################################################
###                   P A C K A G E   P R O C E S S I N G                   ###
###############################################################################

%prep


%setup -q


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVAR_INSTALL_DIR:PATH=/var -DBUILD_PKI_CORE:BOOL=ON ..
%{__make} VERBOSE=1 %{?_smp_mflags}


###############################################################################
###                 P A C K A G E   I N S T A L L A T I O N                 ###
###############################################################################

%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot}


###############################################################################
###              S U B P A C K A G E   I N S T A L L A T I O N              ###
###############################################################################

########################
##     pki-setup      ##
########################


########################
##     pki-symkey     ##
########################

cd %{buildroot}%{_libdir}/symkey
%{__rm} symkey.jar
%{__ln_s} symkey-%{version}.jar symkey.jar

cd %{buildroot}%{_jnidir}
%{__rm} symkey.jar
%{__ln_s} %{_libdir}/symkey/symkey.jar symkey.jar


########################
##  pki-native-tools  ##
########################


########################
##      pki-util      ##
########################


########################
##   pki-java-tools   ##
########################


########################
##     pki-common     ##
########################


########################
##    pki-selinux     ##
########################


########################
##       pki-ca       ##
########################


########################
##     pki-silent     ##
########################


###############################################################################
###  P R E  &  P O S T   I N S T A L L / U N I N S T A L L   S C R I P T S  ###
###############################################################################

########################
##     pki-setup      ##
########################


########################
##     pki-symkey     ##
########################


########################
##  pki-native-tools  ##
########################


########################
##      pki-util      ##
########################


########################
##   pki-java-tools   ##
########################


########################
##     pki-common     ##
########################


########################
##    pki-selinux     ##
########################

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


########################
##       pki-ca       ##
########################

%pre -n pki-ca


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


########################
##     pki-silent     ##
########################


###############################################################################
###   I N V E N T O R Y   O F   F I L E S   A N D   D I R E C T O R I E S   ### 
###############################################################################

########################
##     pki-setup      ##
########################

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


########################
##     pki-symkey     ##
########################

%files -n pki-symkey
%defattr(-,root,root,-)
%doc base/symkey/LICENSE
%{_jnidir}/symkey.jar
%dir %{_libdir}/symkey
%{_libdir}/symkey/*


########################
##  pki-native-tools  ##
########################

%files -n pki-native-tools
%defattr(-,root,root,-)
%doc base/native-tools/LICENSE base/native-tools/doc/README
%{_bindir}/bulkissuance
%{_bindir}/p7tool
%{_bindir}/revoker
%{_bindir}/setpin
%{_bindir}/sslget
%{_bindir}/tkstool
%dir %{_datadir}/pki/native-tools
%{_datadir}/pki/native-tools/*


########################
##      pki-util      ##
########################

%files -n pki-util
%defattr(-,root,root,-)
%doc base/util/LICENSE
%dir %{_javadir}/pki
%{_javadir}/pki/cmsutil-%{version}.jar
%{_javadir}/pki/cmsutil.jar
%{_javadir}/pki/nsutil-%{version}.jar
%{_javadir}/pki/nsutil.jar

%files -n pki-util-javadoc
%defattr(-,root,root,-)
%dir %{_javadocdir}/pki-util-%{version}
%{_javadocdir}/pki-util-%{version}/*


########################
##   pki-java-tools   ##
########################

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
%{_javadir}/pkitools-%{version}.jar
%{_javadir}/pkitools.jar
#%{_javadir}/cstools.jar
#%{_javadir}/pki/pkitools-%{version}.jar
#%{_javadir}/pki/pkitools.jar
#%{_javadir}/pki/cstools.jar

%files -n pki-java-tools-javadoc
%defattr(-,root,root,-)
%dir %{_javadocdir}/pki-java-tools-%{version}
%{_javadocdir}/pki-java-tools-%{version}/*


########################
##     pki-common     ##
########################

%files -n pki-common
%defattr(-,root,root,-)
%doc base/common/LICENSE
%{_javadir}/pki/certsrv-%{version}.jar
%{_javadir}/pki/certsrv.jar
%{_javadir}/pki/cms-%{version}.jar
%{_javadir}/pki/cms.jar
%{_javadir}/pki/cmsbundle-%{version}.jar
%{_javadir}/pki/cmsbundle.jar
%{_javadir}/pki/cmscore-%{version}.jar
%{_javadir}/pki/cmscore.jar
%{_datadir}/pki/scripts/functions
%{_datadir}/pki/scripts/pki_apache_initscript
%dir %{_datadir}/pki/setup
%{_datadir}/pki/setup/CertServer.directory
%{_datadir}/pki/setup/menu.xml
%{_datadir}/pki/setup/web-app_2_3.dtd

%files -n pki-common-javadoc
%defattr(-,root,root,-)
%dir %{_javadocdir}/pki-common-%{version}
%{_javadocdir}/pki-common-%{version}/*


########################
##    pki-selinux     ##
########################

%files -n pki-selinux
%defattr(-,root,root,-)
%doc base/selinux/LICENSE
%{_datadir}/selinux/modules/pki.pp


########################
##       pki-ca       ##
########################

%files -n pki-ca
%defattr(-,root,root,-)
%doc base/ca/LICENSE
%{_initrddir}/pki-cad
%{_javadir}/ca-%{version}.jar
%{_javadir}/ca.jar
#%{_javadir}/pki/ca-%{version}.jar
#%{_javadir}/pki/ca/ca.jar
%dir %{_datadir}/pki/ca
%dir %{_datadir}/pki/ca/conf
%{_datadir}/pki/ca/conf/*
%dir %{_datadir}/pki/ca/emails
%{_datadir}/pki/ca/emails/*
%dir %{_datadir}/pki/ca/profiles
%dir %{_datadir}/pki/ca/profiles/ca
%{_datadir}/pki/ca/profiles/ca/*
%dir %{_datadir}/pki/ca/webapps
%{_datadir}/pki/ca/webapps/*
%dir %{_datadir}/pki/ca/setup
%{_datadir}/pki/ca/setup/*
%dir %{_localstatedir}/lock/pki/ca
%dir %{_localstatedir}/run/pki/ca


########################
##     pki-silent     ##
########################

%files -n pki-silent
%defattr(-,root,root,-)
%doc base/silent/LICENSE
%{_bindir}/pkisilent
%{_javadir}/silent-%{version}.jar
%{_javadir}/silent.jar
#%{_javadir}/pki/silent-%{version}.jar
#%{_javadir}/pki/silent.jar
%dir %{_datadir}/pki/silent
%{_datadir}/pki/silent/*


###############################################################################
###                            C H A N G E L O G                            ###
###############################################################################

%changelog
* Wed Dec 1 2010 Matthew Harmsen <mharmsen@redhat.com> 9.0.0-1
- Initial revision. (kwright@redhat.com & mharmsen@redhat.com)

