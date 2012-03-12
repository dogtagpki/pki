Name:             pki-core
Version:          9.0.18
Release:          1%{?dist}
Summary:          Certificate System - PKI Core Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Daemons

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

# specify '_unitdir' macro for platforms that don't use 'systemd'
%if 0%{?rhel} || 0%{?fedora} < 16
%define           _unitdir /lib/systemd/system
%endif

# tomcatjss requires versioning since version 2.0.0 requires tomcat6
BuildRequires:    cmake
BuildRequires:    java-devel >= 1:1.6.0
BuildRequires:    ldapjdk
BuildRequires:    nspr-devel
BuildRequires:    nss-devel
BuildRequires:    openldap-devel
BuildRequires:    pkgconfig
BuildRequires:    policycoreutils
BuildRequires:    selinux-policy-devel
BuildRequires:    velocity
BuildRequires:    xalan-j2
BuildRequires:    xerces-j2
%if 0%{?fedora} >= 16
BuildRequires:    jpackage-utils >= 0:1.7.5-10
BuildRequires:    jss >= 4.2.6-19.1
BuildRequires:    osutil >= 2.0.2
BuildRequires:    systemd-units
BuildRequires:    tomcatjss >= 6.0.2
%else
%if 0%{?fedora} >= 15
BuildRequires:    jpackage-utils
BuildRequires:    jss >= 4.2.6-17
BuildRequires:    osutil >= 2.0.1
BuildRequires:    tomcatjss >= 6.0.0
%else
BuildRequires:    jpackage-utils
BuildRequires:    jss >= 4.2.6-17
BuildRequires:    osutil
BuildRequires:    tomcatjss >= 2.0.0
%endif
%endif

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}.tar.gz

Patch0:	          %{name}-selinux-Dogtag-9-f16.patch
Patch1:	          %{name}-selinux-Dogtag-9-f17.patch

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

Requires:         perl(File::Slurp)
Requires:         perl(XML::LibXML)
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
Requires:         nss
%if 0%{?fedora} >= 16
Requires:         jpackage-utils >= 0:1.7.5-10
Requires:         jss >= 4.2.6-19.1
%else
Requires:         jpackage-utils
Requires:         jss >= 4.2.6-17
%endif

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
Requires:         ldapjdk
%if 0%{?fedora} >= 16
Requires:         jpackage-utils >= 0:1.7.5-10
Requires:         jss >= 4.2.6-19.1
Requires:         osutil >= 2.0.2
%else
%if 0%{?fedora} >= 15
Requires:         jpackage-utils
Requires:         jss >= 4.2.6-17
Requires:         osutil >= 2.0.1
%else
Requires:         jpackage-utils
Requires:         jss >= 4.2.6-17
Requires:         osutil
%endif
%endif

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
%if 0%{?fedora} >= 16
Requires:         jpackage-utils >= 0:1.7.5-10
%else
Requires:         jpackage-utils
%endif

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
Requires:         pki-common-theme >= 9.0.0
Requires:         pki-java-tools = %{version}-%{release}
Requires:         pki-setup = %{version}-%{release}
Requires:         pki-symkey = %{version}-%{release}
Requires:         %{_javadir}/ldapjdk.jar
Requires:         %{_javadir}/velocity.jar
Requires:         %{_javadir}/xalan-j2.jar
Requires:         %{_javadir}/xalan-j2-serializer.jar
Requires:         %{_javadir}/xerces-j2.jar
Requires:         %{_javadir}/xml-commons-apis.jar
Requires:         %{_javadir}/xml-commons-resolver.jar
Requires:         velocity
%if 0%{?fedora} >= 16
Requires:         apache-commons-lang
Requires:         apache-commons-logging
Requires:         jss >= 4.2.6-19.1
Requires:         tomcatjss >= 6.0.2
%else
%if 0%{?fedora} >= 15
Requires:         apache-commons-lang
Requires:         apache-commons-logging
Requires:         jss >= 4.2.6-17
Requires:         tomcatjss >= 6.0.0
%else
%if 0%{?fedora} >= 14
Requires:         apache-commons-lang
Requires:         apache-commons-logging
Requires:         jss >= 4.2.6-17
Requires:         tomcatjss >= 2.0.0
%else
Requires:         jakarta-commons-lang
Requires:         jakarta-commons-logging
Requires:         jss >= 4.2.6-17
Requires:         tomcatjss >= 2.0.0
%endif
%endif
%endif

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
%if 0%{?fedora} >= 16
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units
%else
%if 0%{?fedora} >= 15
Requires(post):   chkconfig
Requires(preun):  chkconfig
Requires(preun):  initscripts
Requires(postun): initscripts
# Details:
#
#     * https://fedoraproject.org/wiki/Features/var-run-tmpfs
#     * https://fedoraproject.org/wiki/Tmpfiles.d_packaging_draft
#
Requires:         initscripts
%else 
Requires(post):   chkconfig
Requires(preun):  chkconfig
Requires(preun):  initscripts
Requires(postun): initscripts
%endif
%endif

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


%if 0%{?fedora} >= 17
%patch0 -p2 -b .f17
%else
%if 0%{?fedora} >= 16
%patch0 -p2 -b .f16
%endif
%endif


%clean
%{__rm} -rf %{buildroot}


%build
%{__mkdir_p} build
cd build
%cmake -DVAR_INSTALL_DIR:PATH=/var -DBUILD_PKI_CORE:BOOL=ON -DJAVA_LIB_INSTALL_DIR=%{_jnidir} -DSYSTEMD_LIB_INSTALL_DIR=%{_unitdir} ..
%{__make} VERBOSE=1 %{?_smp_mflags}


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"

cd %{buildroot}%{_libdir}/symkey
%{__rm} symkey.jar
%if 0%{?fedora} >= 16
%{__rm} %{buildroot}%{_jnidir}/symkey.jar
%{__mv} symkey-%{version}.jar %{buildroot}%{_jnidir}/symkey.jar
%else
%{__ln_s} symkey-%{version}.jar symkey.jar
%endif

%if 0%{?rhel} || 0%{?fedora} < 16
cd %{buildroot}%{_jnidir}
%{__rm} symkey.jar
%{__ln_s} %{_libdir}/symkey/symkey.jar symkey.jar
%endif

%if 0%{?fedora} >= 15
# Details:
#
#     * https://fedoraproject.org/wiki/Features/var-run-tmpfs
#     * https://fedoraproject.org/wiki/Tmpfiles.d_packaging_draft
#
%{__mkdir_p} %{buildroot}%{_sysconfdir}/tmpfiles.d
# generate 'pki-ca.conf' under the 'tmpfiles.d' directory
echo "D /var/lock/pki 0755 root root -"    >  %{buildroot}%{_sysconfdir}/tmpfiles.d/pki-ca.conf
echo "D /var/lock/pki/ca 0755 root root -" >> %{buildroot}%{_sysconfdir}/tmpfiles.d/pki-ca.conf
echo "D /var/run/pki 0755 root root -"     >> %{buildroot}%{_sysconfdir}/tmpfiles.d/pki-ca.conf
echo "D /var/run/pki/ca 0755 root root -"  >> %{buildroot}%{_sysconfdir}/tmpfiles.d/pki-ca.conf
%endif

%if 0%{?fedora} >= 16
%{__rm} %{buildroot}%{_initrddir}/pki-cad
%else
%{__rm} %{buildroot}%{_bindir}/pkicontrol
%{__rm} -rf %{buildroot}%{_sysconfdir}/systemd/system/pki-cad.target.wants
%{__rm} -rf %{buildroot}%{_unitdir}
%endif


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

%if 0%{?rhel} || 0%{?fedora} < 16
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

%else 
%post -n pki-ca
# Attempt to update ALL old "CA" instances to "systemd"
if [ -d /etc/sysconfig/pki/ca ]; then
    for inst in `ls /etc/sysconfig/pki/ca`; do
        if [ ! -e "/etc/systemd/system/pki-cad.target.wants/pki-cad@${inst}.service" ]; then
            ln -s "/lib/systemd/system/pki-cad@.service" \
                  "/etc/systemd/system/pki-cad.target.wants/pki-cad@${inst}.service"
            [ -L /var/lib/${inst}/${inst} ] && unlink /var/lib/${inst}/${inst}
            ln -s /usr/sbin/tomcat6-sysd /var/lib/${inst}/${inst}

            if [ -e /var/run/${inst}.pid ]; then
                kill -9 `cat /var/run/${inst}.pid` || :
                rm -f /var/run/${inst}.pid
                echo "pkicreate.systemd.servicename=pki-cad@${inst}.service" >> \
                     /var/lib/${inst}/conf/CS.cfg || :
                /bin/systemctl daemon-reload >/dev/null 2>&1 || :
                /bin/systemctl restart pki-cad@${inst}.service || :
            else 
                echo "pkicreate.systemd.servicename=pki-cad@${inst}.service" >> \
                     /var/lib/${inst}/conf/CS.cfg || :
            fi
        fi
    done
fi
/bin/systemctl daemon-reload >/dev/null 2>&1 || :

%preun -n pki-ca
if [ $1 = 0 ] ; then
    /bin/systemctl --no-reload disable pki-cad.target > /dev/null 2>&1 || :
    /bin/systemctl stop pki-cad.target > /dev/null 2>&1 || :
fi


%postun -n pki-ca
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -ge "1" ] ; then
    /bin/systemctl try-restart pki-cad.target >/dev/null 2>&1 || :
fi
%endif


%files -n pki-setup
%defattr(-,root,root,-)
%doc base/setup/LICENSE
%{_bindir}/pkicreate
%{_bindir}/pkiremove
%{_bindir}/pki-setup-proxy
%dir %{_datadir}/pki
%dir %{_datadir}/pki/scripts
%{_datadir}/pki/scripts/pkicommon.pm
%{_datadir}/pki/scripts/functions
%{_datadir}/pki/scripts/pki_apache_initscript
%dir %{_localstatedir}/lock/pki
%dir %{_localstatedir}/run/pki
%if 0%{?fedora} >= 16
%{_bindir}/pkicontrol
%endif


%files -n pki-symkey
%defattr(-,root,root,-)
%doc base/symkey/LICENSE
%{_jnidir}/symkey.jar
%{_libdir}/symkey/

%files -n pki-native-tools
%defattr(-,root,root,-)
%doc base/native-tools/LICENSE base/native-tools/doc/README
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
%{_bindir}/DRMTool
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
%{_datadir}/pki/java-tools/

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
%if 0%{?fedora} >= 16
%dir %{_sysconfdir}/systemd/system/pki-cad.target.wants
%{_unitdir}/pki-cad@.service
%{_unitdir}/pki-cad.target
%else 
%{_initrddir}/pki-cad
%endif
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
%if 0%{?fedora} >= 15
# Details:
#
#     * https://fedoraproject.org/wiki/Features/var-run-tmpfs
#     * https://fedoraproject.org/wiki/Tmpfiles.d_packaging_draft
#
%config(noreplace) %{_sysconfdir}/tmpfiles.d/pki-ca.conf
%endif


%files -n pki-silent
%defattr(-,root,root,-)
%doc base/silent/LICENSE
%{_bindir}/pkisilent
%{_javadir}/pki/pki-silent-%{version}.jar
%{_javadir}/pki/pki-silent.jar
%{_datadir}/pki/silent/


%changelog
* Fri Mar  9 2012 Matthew Harmsen <mharmsen@redhat.com> 9.0.18-1
- Bugzilla Bug #796006 - Get DOGTAG_9_BRANCH GIT repository in-sync
  with DOGTAG_9_BRANCH SVN repository . . .
- 'pki-setup'
- 'pki-symkey'
- 'pki-native-tools'
- 'pki-util'
-      Bugzilla Bug #784387 - Configuration wizard does not provide option
       to issue ECC credentials for admin during ECC CA configuration.
- 'pki-java-tools'
- 'pki-common'
-      Bugzilla Bug #768138 - Make sure that paging works correctly in CA
       and DRM
-      Bugzilla Bug #771768 - "Agent-Authenticated File Signing" alters
       file digest for "logo_header.gif"
-      Bugzilla Bug #703608 - Enrollment Profile template Javascript code
       problem for handling non-dual ECC
-      Bugzilla Bug #223358 - new profile for ECC key generation
-      Bugzilla Bug #787806 - RSA should be default selection for transport
       key till "ECC phase 4" is implemented
- 'pki-selinux'
- 'pki-ca'
-      Bugzilla Bug #703608 - Enrollment Profile template Javascript code
       problem for handling non-dual ECC
-      Bugzilla Bug #223358 - new profile for ECC key generation
-      Bugzilla Bug #787806 - RSA should be default selection for transport
       key till "ECC phase 4" is implemented
- 'pki-silent'
-      Bugzilla Bug #801840 - pki_silent.template missing opening brace for
       ca_external variable

* Fri Mar  2 2012 Matthew Harmsen <mharmsen@redhat.com> 9.0.17-4
- For 'mock' purposes, removed platform-specific logic from around
  the 'patch' files so that ALL 'patch' files will be included in
  the SRPM.

* Tue Feb 28 2012 Ade Lee <alee@redhat.com> 9.0.17-3
- 'pki-selinux'
-      Added platform-dependent patches for SELinux component
-      Bugzilla Bug #739708 - Selinux fix for ephemeral ports (F16)
-      Bugzilla Bug #795966 - pki-selinux policy is kind of a mess (F17)

* Wed Feb 22 2012 Matthew Harmsen <mharmsen@redhat.com> 9.0.17-2
- Add '-DSYSTEMD_LIB_INSTALL_DIR' override flag to 'cmake' to address changes
  in fundamental path structure in Fedora 17
- 'pki-setup'
-      Hard-code Perl dependencies to protect against bugs such as
       Bugzilla Bug #772699 - Adapt perl and python fileattrs to
       changed file 5.10 magics
- 'pki-selinux'
-      Bugzilla Bug #795966 - pki-selinux policy is kind of a mess

* Thu Jan  5 2012 Matthew Harmsen <mharmsen@redhat.com> 9.0.17-1
- 'pki-setup'
- 'pki-symkey'
- 'pki-native-tools'
-      Bugzilla Bug #771357 - sslget does not work after FEDORA-2011-17400
       update, breaking FreeIPA install
- 'pki-util'
- 'pki-java-tools'
-      Bugzilla Bug #757848 - DRM re-key tool: introduces a blank line in the
       middle of an ldif entry.
- 'pki-common'
-      Bugzilla Bug #747019 - Migrated policy requests from 7.1->8.1 displays
       issuedcerts and cert_Info params as base 64 blobs.
-      Bugzilla Bug #756133 - Some DRM components are not referring properly
       to DRM's request and key records.
-      Bugzilla Bug #758505 - DRM's request list breaks after migration of
       request records with big IDs.
-      Bugzilla Bug #768138 - Make sure that paging works correctly in CA and
       DRM
- 'pki-selinux'
- 'pki-ca'
- 'pki-silent'

* Fri Oct 28 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.16-1
- 'pki-setup'
- 'pki-symkey'
- 'pki-native-tools'
- 'pki-util'
-      Bugzilla Bug #737122 - DRM: during archiving and recovering,
       wrapping unwrapping keys should be done in the token (cfu)
- 'pki-java-tools'
- 'pki-common'
-      Bugzilla Bug #744797 - KRA key recovery (retrieve pkcs#12) fails after
       the in-place upgrade( CS 8.0->8.1) (cfu)
- 'pki-selinux'
- 'pki-ca'
-      Bugzilla Bug #746367 - Typo in the profile name. (jmagne)
-      Bugzilla Bug #737122 - DRM: during archiving and recovering,
       wrapping unwrapping keys should be done in the token (cfu)
-      Bugzilla Bug #749927 - Java class conflicts using Java 7 in Fedora 17
       (rawhide) . . . (mharmsen)
-      Bugzilla Bug #749945 - Installation error reported during CA, DRM,
       OCSP, and TKS package installation . . . (mharmsen)
- 'pki-silent'

* Thu Sep 22 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.15-1
- Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . . (mharmsen)
- Bugzilla Bug #699809 - Convert CS to use systemd (alee)
- 'pki-setup'
-      Bugzilla Bug #730146 - SSL handshake picks non-FIPS ciphers in FIPS
       mode (cfu)
-      Bugzilla Bug #737192 - Need script to upgrade proxy configuration (alee)
- 'pki-symkey'
-      Bugzilla Bug #730162 - TPS/TKS token enrollment failure in FIPS mode
       (hsm+NSS). (jmagne)
- 'pki-native-tools'
-      Bugzilla Bug #730801 - Coverity issues in native-tools area (awnuk)
-      Bugzilla Bug #730146 - SSL handshake picks non-FIPS ciphers in FIPS
       mode (cfu)
- 'pki-util'
-      Bugzilla Bug #730146 - SSL handshake picks non-FIPS ciphers in FIPS
       mode (cfu)
- 'pki-java-tools'
- 'pki-common'
-      Bugzilla Bug #730146 - SSL handshake picks non-FIPS ciphers in FIPS
       mode (cfu)
-      Bugzilla Bug #737218 - Incorrect request attribute name matching
       ignores request attributes during request parsing. (awnuk)
-      Bugzilla Bug #730162 - TPS/TKS token enrollment failure in FIPS mode
       (hsm+NSS). (jmagne)
- 'pki-selinux'
-      Bugzilla Bug #739708 - pki-selinux lacks rules in F16 (alee)
- 'pki-ca'
-      Bugzilla Bug #712931 - CS requires too many ports
       to be open in the FW (alee)
-      Bugzilla Bug #730146 - SSL handshake picks non-FIPS ciphers in FIPS
       mode (cfu)
- 'pki-silent'
-      Bugzilla Bug #739201 - pkisilent does not take arch into account
       as Java packages migrated to arch-dependent directories (mharmsen)

* Fri Sep 9 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.14-1
- 'pki-setup'
-      Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . .
- 'pki-symkey'
-      Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . .
- 'pki-native-tools'
- 'pki-util'
-      Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . .
- 'pki-java-tools'
-      Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . .
- 'pki-common'
-      Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . .
- 'pki-selinux'
- 'pki-ca'
-      Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . .
-      Bugzilla Bug #699809 - Convert CS to use systemd (alee)
- 'pki-silent'
-      Bugzilla Bug #734590 - Refactor JNI libraries for Fedora 16+ . . .

* Tue Sep 6 2011 Ade Lee <alee@redhat.com> 9.0.13-1
- 'pki-setup'
-      Bugzilla Bug #699809 - Convert CS to use systemd (alee)
- 'pki-ca'
-      Bugzilla Bug #699809 - Convert CS to use systemd (alee)
- 'pki-common'
-      Bugzilla Bug #699809 - Convert CS to use systemd (alee)

* Tue Aug 23 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.12-1
- 'pki-setup'
-      Bugzilla Bug #712931 - CS requires too many ports
       to be open in the FW (alee)
- 'pki-symkey'
- 'pki-native-tools'
-      Bugzilla Bug #717643 - Fopen without NULL check and other Coverity
       issues (awnuk)
-      Bugzilla Bug #730801 - Coverity issues in native-tools area (awnuk)
- 'pki-util'
- 'pki-java-tools'
- 'pki-common'
-      Bugzilla Bug #700522 - pki tomcat6 instances currently running
       unconfined, allow server to come up when selinux disabled (alee)
-      Bugzilla Bug #731741 - some CS.cfg nickname parameters not updated
       correctly when subsystem cloned (using hsm) (alee)
-      Bugzilla Bug #712931 - CS requires too many ports
       to be open in the FW (alee)
- 'pki-selinux'
-      Bugzilla Bug #712931 - CS requires too many ports
       to be open in the FW (alee)
- 'pki-ca'
-      Bugzilla Bug #712931 - CS requires too many ports
       to be open in the FW (alee)
- 'pki-silent'

* Wed Aug 10 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.11-1
- 'pki-setup'
-      Bugzilla Bug #689909 - Dogtag installation under IPA takes too much
       time - remove the inefficient sleeps (alee)
- 'pki-symkey'
- 'pki-native-tools'
- 'pki-util'
- 'pki-java-tools'
-      Bugzilla Bug #724861 - DRMTool: fix duplicate "dn:" records by
       renumbering "cn=<value>" (mharmsen)
- 'pki-common'
-      Bugzilla Bug #717041 - Improve escaping of some enrollment inputs like
       (jmagne, awnuk)
-      Bugzilla Bug #689909 - Dogtag installation under IPA takes too much
       time - remove the inefficient sleeps (alee)
-      Bugzilla Bug #708075 - Clone installation does not work over NAT
       (alee)
-      Bugzilla Bug #726785 - If replication fails while setting up a clone
       it will wait forever (alee)
-      Bugzilla Bug #728332 - xml output has changed on cert requests (awnuk)
-      Bugzilla Bug #700505 - pki tomcat6 instances currently running
       unconfined (alee)
- 'pki-selinux'
-      Bugzilla Bug #700505 - pki tomcat6 instances currently running
       unconfined (alee)
- 'pki-ca'
-      Bugzilla Bug #728605 - RFE: increase default validity from 6mo to 2yrs
       in IPA profile (awnuk)
- 'pki-silent'
-      Bugzilla Bug #689909 - Dogtag installation under IPA takes too much
       time - remove the inefficient sleeps (alee)

* Fri Jul 22 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.10-1
- 'pki-setup'
- 'pki-symkey'
- 'pki-native-tools'
- 'pki-util'
-      Bugzilla Bug #719007 - Key Constraint keyParameter being ignored
       using an ECC CA to generate ECC certs from CRMF. (jmagne)
-      Bugzilla Bug #716307 - rhcs80 - DER shall not include an encoding
       for any component value which is equal to its default value (alee)
- 'pki-java-tools'
- 'pki-common'
-      Bugzilla Bug #720510 - Console: Adding a certificate into nethsm
       throws Token not found error. (jmagne)
-      Bugzilla Bug #719007 - Key Constraint keyParameter being ignored
       using an ECC CA to generate ECC certs from CRMF. (jmagne)
-      Bugzilla Bug #716307 - rhcs80 - DER shall not include an encoding
       for any component value which is equal to its default value (alee)
-      Bugzilla Bug #722989 - Registering an agent when a subsystem is
       created - does not log AUTHZ_SUCCESS event. (alee)
- 'pki-selinux'
- 'pki-ca'
-      Bugzilla Bug #719113 - Add client usage flag to caIPAserviceCert
       (awnuk)
- 'pki-silent'

* Thu Jul 14 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.9-1
- Updated release of 'jss'
- Updated release of 'tomcatjss' for Fedora 15
- 'pki-setup'
-      Bugzilla Bug #695157 - Auditverify on TPS audit log throws error.
       (mharmsen)
-      Bugzilla Bug #693815 - /var/log/tomcat6/catalina.out owned by pkiuser
       (jdennis)
-      Bugzilla Bug #694569 - parameter used by pkiremove not updated (alee)
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'pki-symkey'
-      Bugzilla Bug #695157 - Auditverify on TPS audit log throws error.
       (mharmsen)
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'pki-native-tools'
-      Bugzilla Bug #695157 - Auditverify on TPS audit log throws error.
       (mharmsen)
-      Bugzilla Bug #717765 - TPS configuration: logging into security domain
       from tps does not work with clientauth=want. (alee)
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'pki-util'
-      Bugzilla Bug #695157 - Auditverify on TPS audit log throws error.
       (mharmsen)
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'pki-java-tools'
-      Bugzilla Bug #695157 - Auditverify on TPS audit log throws error.
       (mharmsen)
-      Bugzilla Bug #532548 - Tool to do DRM re-key (mharmsen)
-      Bugzilla Bug #532548 - Tool to do DRM re-key (config file and record
       processing) (mharmsen)
-      Bugzilla Bug #532548 - Tool to do DRM re-key (tweaks) (mharmsen)
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'pki-common'
-      Bugzilla Bug #695157 - Auditverify on TPS audit log throws error.
       (mharmsen)
-      Bugzilla Bug #695403 - Editing signedaudit or transaction, system
       logs throws 'Invalid protocol' for OCSP subsystems (alee)
-      Bugzilla Bug #694569 - parameter used by pkiremove not updated (alee)
-      Bugzilla Bug #695015 - Serial No. of a revoked certificate is not
       populated in the CA signedAudit messages (alee)
-      Bugzilla Bug #694143 - CA Agent not returning specified request (awnuk)
-      Bugzilla Bug #695015 - Serial No. of a revoked certificate is not
       populated in the CA signedAudit messages (jmagne)
-      Bugzilla Bug #698885 - Race conditions during IPA installation (alee)
-      Bugzilla Bug #704792 - CC_LAB_EVAL: CA agent interface:
       SubjectID=$Unidentified$ fails audit evaluation (jmagne)
-      Bugzilla Bug #705914 - SCEP mishandles nicknames when processing
       subsequent SCEP requests. (awnuk)
-      Bugzilla Bug #661142 - Verification should fail when a revoked
       certificate is added. (jmagne)
-      Bugzilla Bug #707416 - CC_LAB_EVAL: Security Domain: missing audit msgs
       for modify/add (alee)
-      Bugzilla Bug #707416 - additional audit messages for GetCookie (alee)
-      Bugzilla Bug #707607 - Published certificate summary has list of
       non-published certificates with succeeded status (jmagne)
-      Bugzilla Bug #717813 - EV_AUDIT_LOG_SHUTDOWN audit log not generated
       for tps and ca on server shutdown (jmagne)
-      Bugzilla Bug #697939 - DRM signed audit log message - operation should
       be read instead of modify (jmagne)
-      Bugzilla Bug #718427 - When audit log is full, server continue to
       function. (alee)
-      Bugzilla Bug #718607 - CC_LAB_EVAL: No AUTH message is generated in
       CA's signedaudit log when a directory based user enrollment is
       performed (jmagne)
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'pki-selinux'
-      Bugzilla Bug #695157 - Auditverify on TPS audit log throws error.
       (mharmsen)
-      Bugzilla Bug #720503 - RA and TPS require additional SELinux
       permissions to run in "Enforcing" mode (alee)
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'pki-ca'
-      Bugzilla Bug #695157 - Auditverify on TPS audit log throws error.
       (mharmsen)
-      Bugzilla Bug #693815 - /var/log/tomcat6/catalina.out owned by pkiuser
       (jdennis)
-      Bugzilla Bug #699837 - service command is not fully backwards
       compatible with Dogtag pki subsystems (mharmsen)
-      Bugzilla Bug #649910 - Console: an auditor or agent can be added to an
       administrator group. (jmagne)
-      Bugzilla Bug #707416 - CC_LAB_EVAL: Security Domain: missing audit msgs
       for modify/add (alee)
-      Bugzilla Bug #716269 - make ra authenticated profiles non-visible on ee
       pages (alee)
-      Bugzilla Bug #718621 - CC_LAB_EVAL: PRIVATE_KEY_ARCHIVE_REQUEST occurs
       for a revocation invoked by EE user (awnuk)
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)
- 'pki-silent'
-      Bugzilla Bug #695157 - Auditverify on TPS audit log throws error.
       (mharmsen)
-      Bugzilla Bug #669226 - Remove Legacy Build System (mharmsen)

* Wed May 25 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.8-2
- 'pki-setup'
- 'pki-symkey'
- 'pki-native-tools'
- 'pki-util'
- 'pki-java-tools'
-     Added 'DRMTool.cfg' configuration file to inventory
- 'pki-common'
- 'pki-selinux'
- 'pki-ca'
- 'pki-silent'

* Wed May 25 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.8-1
- 'pki-setup'
- 'pki-symkey'
- 'pki-native-tools'
- 'pki-util'
- 'pki-java-tools'
-     Bugzilla Bug #532548 - Tool to do DRM re-key
- 'pki-common'
- 'pki-selinux'
- 'pki-ca'
- 'pki-silent'

* Tue Apr 26 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.7-1
- 'pki-setup'
-     Bugzilla Bug #693815 - /var/log/tomcat6/catalina.out owned by pkiuser
-     Bugzilla Bug #694569 - parameter used by pkiremove not updated
- 'pki-symkey'
- 'pki-native-tools'
- 'pki-util'
- 'pki-java-tools'
- 'pki-common'
-     Bugzilla Bug #695403 - Editing signedaudit or transaction, system logs
      throws 'Invalid protocol' for OCSP subsystems
-     Bugzilla Bug #694569 - parameter used by pkiremove not updated
-     Bugzilla Bug #695015 - Serial No. of a revoked certificate is not
      populated in the CA signedAudit messages
-     Bugzilla Bug #694143 - CA Agent not returning specified request
-     Bugzilla Bug #695015 - Serial No. of a revoked certificate is not
      populated in the CA signedAudit messages
-     Bugzilla Bug #698885 - Race conditions during IPA installation
- 'pki-selinux'
- 'pki-ca'
-     Bugzilla Bug #693815 - /var/log/tomcat6/catalina.out owned by pkiuser
-     Bugzilla Bug #699837 - service command is not fully backwards compatible
      with Dogtag pki subsystems
- 'pki-silent'

* Mon Apr 11 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.6-2
- Bugzilla Bug #695157 - Auditverify on TPS audit log throws error.

* Tue Apr 5 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.6-1
- Bugzilla Bug #690950 - Update Dogtag Packages for Fedora 15 (beta)
- Bugzilla Bug #693327 - Missing requires: tomcatjss
- 'pki-setup'
-     Bugzilla Bug #690626 - pkiremove removes the registry entry for
      all instances on a machine
- 'pki-symkey'
- 'pki-native-tools'
- 'pki-util'
- 'pki-java-tools'
-     Bugzilla Bug #689453 - CRMFPopClient request to CA's unsecure port
      throws file not found exception.
- 'pki-common'
-     Bugzilla Bug #692990 - Audit log messages needed to match CC doc:
      DRM Recovery audit log messages
- 'pki-selinux'
- 'pki-ca'
- 'pki-silent'

* Tue Apr 5 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.5-2
- Bugzilla Bug #693327 - Missing requires: tomcatjss

* Fri Mar 25 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.5-1
- Bugzilla Bug #690950 - Update Dogtag Packages for Fedora 15 (beta)
- Require "jss >= 4.2.6-15" as a build and runtime requirement
- Require "tomcatjss >= 2.1.1" as a build and runtime requirement
  for Fedora 15 and later platforms
- 'pki-setup'
-     Bugzilla Bug #688287 - Add "deprecation" notice regarding using
      "shared ports" in pkicreate -help . . .
-     Bugzilla Bug #688251 - Dogtag installation under IPA takes
      too much time - SELinux policy compilation
- 'pki-symkey'
- 'pki-native-tools'
- 'pki-util'
- 'pki-java-tools'
-     Bugzilla Bug #689501 - ExtJoiner tool fails to join the multiple
      extensions
- 'pki-common'
-     Bugzilla Bug #683581 - CA configuration with ECC(Default
      EC curve-nistp521) CA fails with 'signing operation failed'
-     Bugzilla Bug #689662 - ocsp publishing needs to be re-enabled
      on the EE port
- 'pki-selinux'
-     Bugzilla Bug #684871 - ldaps selinux link change
- 'pki-ca'
-     Bugzilla Bug #683581 - CA configuration with ECC(Default
      EC curve-nistp521) CA fails with 'signing operation failed'
-     Bugzilla Bug #684381 - CS.cfg specifies incorrect type of comments
-     Bugzilla Bug #689453 - CRMFPopClient request to CA's unsecure port
      throws file not found exception.(profile and CS.cfg only)
- 'pki-silent'

* Thu Mar 17 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.4-1
- Bugzilla Bug #688763 - Rebase updated Dogtag Packages for Fedora 15 (alpha)
- Bugzilla Bug #676182 - IPA installation failing - Fails to create CA
  instance
- Bugzilla Bug #675742 - Profile caIPAserviceCert Not Found
- 'pki-setup'
-     Bugzilla Bug #678157 - uninitialized variable warnings from Perl
-     Bugzilla Bug #679574 - Velocity fails to load all dependent classes
-     Bugzilla Bug #680420 - xml-commons-apis.jar dependency
-     Bugzilla Bug #682013 - pkisilent needs xml-commons-apis.jar in it's
      classpath
-     Bugzilla Bug #673508 - CS8 64 bit pkicreate script uses wrong library
      name for SafeNet LunaSA
- 'pki-common'
-     Bugzilla Bug #673638 - Installation within IPA hangs
-     Bugzilla Bug #678715 - netstat loop fixes needed
-     Bugzilla Bug #673609 - CC: authorize() call needs to be added to
      getStats servlet
- 'pki-selinux'
-     Bugzilla Bug #674195: SELinux error message thrown during token
      enrollment
- 'pki-ca'
-     Bugzilla Bug #673638 - Installation within IPA hangs
-     Bugzilla Bug #673609 - CC: authorize() call needs to be added to
      getStats servlet
-     Bugzilla Bug #676330 - init script cannot start service
- 'pki-silent'
-     Bugzilla Bug #682013 - pkisilent needs xml-commons-apis.jar in it's
      classpath

* Wed Feb 9 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.3-2
- 'pki-common'
-     Bugzilla Bug #676051 - IPA installation failing - Fails to create CA
      instance
-     Bugzilla Bug #676182 - IPA installation failing - Fails to create CA
      instance

* Fri Feb 4 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.3-1
- 'pki-common'
-     Bugzilla Bug #674894 - ipactl restart : an annoy output line
-     Bugzilla Bug #675179 - ipactl restart : an annoy output line

* Thu Feb 3 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.2-1
- Bugzilla Bug #673233 - Rebase pki-core to pick the latest features and fixes
- 'pki-setup'
-     Bugzilla Bug #673638 - Installation within IPA hangs
- 'pki-symkey'
- 'pki-native-tools'
- 'pki-util'
- 'pki-java-tools'
-     Bugzilla Bug #673614 - CC: Review of cryptographic algorithms provided
      by 'netscape.security.provider' package
- 'pki-common'
-     Bugzilla Bug #672291 - CA is not publishing certificates issued using
      "Manual User Dual-Use Certificate Enrollment"
-     Bugzilla Bug #670337 - CA Clone configuration throws TCP connection
      error.
-     Bugzilla Bug #504056 - Completed SCEP requests are assigned to the
      "begin" state instead of "complete".
-     Bugzilla Bug #504055 - SCEP requests are not properly populated
-     Bugzilla Bug #564207 - Searches for completed requests in the agent
      interface returns zero entries
-     Bugzilla Bug #672291 - CA is not publishing certificates issued using
      "Manual User Dual-Use Certificate Enrollment" -
-     Bugzilla Bug #673614 - CC: Review of cryptographic algorithms provided
      by 'netscape.security.provider' package
-     Bugzilla Bug #672920 - CA console: adding policy to a profile throws
      'Duplicate policy' error in some cases.
-     Bugzilla Bug #673199 - init script returns control before web apps have
      started
-     Bugzilla Bug #674917 - Restore identification of Tomcat-based PKI
      subsystem instances
- 'pki-selinux'
- 'pki-ca'
-     Bugzilla Bug #504013 - sscep request is rejected due to authentication
      error if submitted through one time pin router certificate enrollment.
-     Bugzilla Bug #672111 - CC doc: certServer.usrgrp.administration missing
      information
-     Bugzilla Bug #583825 - CC: Obsolete servlets to be removed from web.xml
      as part of CC interface review
-     Bugzilla Bug #672333 - Creation of RA agent fails in IPA installation
-     Bugzilla Bug #674917 - Restore identification of Tomcat-based PKI
      subsystem instances
- 'pki-silent'
-     Bugzilla Bug #673614 - CC: Review of cryptographic algorithms provided
      by 'netscape.security.provider' package

* Wed Feb 2 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.1-3
- Bugzilla Bug #656661 - Please Update Spec File to use 'ghost' on files
  in /var/run and /var/lock

* Thu Jan 20 2011 Matthew Harmsen <mharmsen@redhat.com> 9.0.1-2
- 'pki-symkey'
-     Bugzilla Bug #671265 - pki-symkey jar version incorrect
- 'pki-common'
-     Bugzilla Bug #564207 - Searches for completed requests in the agent
      interface returns zero entries

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

