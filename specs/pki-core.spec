%{!?python_sitelib: %global python_sitelib %(%{__python} -c "from
distutils.sysconfig import get_python_lib; print(get_python_lib())")}
%{!?python_sitearch: %global python_sitearch %(%{__python} -c "from
distutils.sysconfig import get_python_lib; print(get_python_lib(1))")}

Name:             pki-core
Version:          10.1.0
Release:          1%{?dist}
Summary:          Certificate System - PKI Core Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Daemons

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:    cmake >= 2.8.9-1
BuildRequires:    zip
BuildRequires:    java-devel >= 1:1.7.0
BuildRequires:    redhat-rpm-config
BuildRequires:    ldapjdk
BuildRequires:    apache-commons-cli
BuildRequires:    apache-commons-codec
BuildRequires:    apache-commons-io
BuildRequires:    nspr-devel
BuildRequires:    nss-devel
BuildRequires:    openldap-devel
BuildRequires:    pkgconfig
BuildRequires:    policycoreutils
BuildRequires:    velocity
BuildRequires:    xalan-j2
BuildRequires:    xerces-j2

%if  0%{?rhel}
BuildRequires:    resteasy-base-atom-provider
BuildRequires:    resteasy-base-jaxb-provider
BuildRequires:    resteasy-base-jaxrs
BuildRequires:    resteasy-base-jaxrs-api
BuildRequires:    resteasy-base-jettison-provider
%else
BuildRequires:    resteasy >= 3.0.1-3
%endif

BuildRequires:    pylint
BuildRequires:    python-requests
BuildRequires:    libselinux-python
BuildRequires:    policycoreutils-python
BuildRequires:    python-ldap
BuildRequires:    junit
BuildRequires:    jpackage-utils >= 0:1.7.5-10
BuildRequires:    jss >= 4.2.6-28
BuildRequires:    systemd-units
BuildRequires:    tomcatjss >= 7.1.0

Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{name}-%{version}%{?prerel}.tar.gz

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
PKI Core contains ALL top-level java-based Tomcat PKI components:      \
                                                                       \
  * pki-symkey                                                         \
  * pki-base                                                           \
  * pki-tools                                                          \
  * pki-server                                                         \
  * pki-ca                                                             \
  * pki-kra                                                            \
  * pki-ocsp                                                           \
  * pki-tks                                                            \
  * pki-tps-tomcat                                                     \
  * pki-javadoc                                                        \
                                                                       \
which comprise the following corresponding PKI subsystems:             \
                                                                       \
  * Certificate Authority (CA)                                         \
  * Data Recovery Manager (DRM)                                        \
  * Online Certificate Status Protocol (OCSP) Manager                  \
  * Token Key Service (TKS)                                            \
  * Token Processing Service (TPS)                                     \
                                                                       \
For deployment purposes, PKI Core contains fundamental packages        \
required by BOTH native-based Apache AND java-based Tomcat             \
Certificate System instances consisting of the following components:   \
                                                                       \
  * pki-tools                                                          \
                                                                       \
Additionally, PKI Core contains the following fundamental packages     \
required ONLY by ALL java-based Tomcat Certificate System instances:   \
                                                                       \
  * pki-symkey                                                         \
  * pki-base                                                           \
  * pki-tools                                                          \
  * pki-server                                                         \
                                                                       \
PKI Core also includes the following components:                       \
                                                                       \
  * pki-javadoc                                                        \
                                                                       \
Finally, if Certificate System is being deployed as an individual or   \
set of standalone rather than embedded server(s)/service(s), it is     \
strongly recommended (though not explicitly required) to include at    \
least one PKI Theme package:                                           \
                                                                       \
  * dogtag-pki-theme (Dogtag Certificate System deployments)           \
    * dogtag-pki-server-theme                                          \
  * redhat-pki-server-theme (Red Hat Certificate System deployments)   \
    * redhat-pki-server-theme                                          \
  * customized pki theme (Customized Certificate System deployments)   \
    * <customized>-pki-server-theme                                    \
                                                                       \
  NOTE:  As a convenience for standalone deployments, top-level meta   \
         packages may be provided which bind a particular theme to     \
         these certificate server packages.                            \
                                                                       \
%{nil}

%description %{overview}


%package -n       pki-symkey
Summary:          Symmetric Key JNI Package
Group:            System Environment/Libraries

Requires:         java >= 1:1.7.0
Requires:         nss
Requires:         jpackage-utils >= 0:1.7.5-10
Requires:         jss >= 4.2.6-28

Provides:         symkey = %{version}-%{release}

Obsoletes:        symkey < %{version}-%{release}

%description -n   pki-symkey
The Symmetric Key Java Native Interface (JNI) package supplies various native
symmetric key operations to Java programs.

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-base
Summary:          Certificate System - PKI Framework
Group:            System Environment/Base

BuildArch:        noarch

Provides:         pki-common = %{version}-%{release}
Provides:         pki-util = %{version}-%{release}

Obsoletes:        pki-common < %{version}-%{release}
Obsoletes:        pki-util < %{version}-%{release}

Conflicts:        freeipa-server < 3.0.0
Requires:         apache-commons-cli
Requires:         apache-commons-codec
Requires:         apache-commons-io
Requires:         apache-commons-lang
Requires:         apache-commons-logging
Requires:         java >= 1:1.7.0
Requires:         javassist
Requires:         jettison
Requires:         jpackage-utils >= 0:1.7.5-10
Requires:         jss >= 4.2.6-28
Requires:         ldapjdk
Requires:         python-ldap
Requires:         python-lxml
Requires:         python-requests >= 1.1.0-3
%if  0%{?rhel}
Requires:    resteasy-base-atom-provider
Requires:    resteasy-base-jaxb-provider
Requires:    resteasy-base-jaxrs
Requires:    resteasy-base-jaxrs-api
Requires:    resteasy-base-jettison-provider
%else
Requires:         resteasy >= 3.0.1-3
%endif
Requires:         xalan-j2
Requires:         xerces-j2
Requires:         xml-commons-apis
Requires:         xml-commons-resolver

%description -n   pki-base
The PKI Framework contains the common and client libraries and utilities.
This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-tools
Summary:          Certificate System - PKI Tools
Group:            System Environment/Base

Provides:         pki-native-tools = %{version}-%{release}
Provides:         pki-java-tools = %{version}-%{release}

Obsoletes:        pki-native-tools < %{version}-%{release}
Obsoletes:        pki-java-tools < %{version}-%{release}

Requires:         openldap-clients
Requires:         nss
Requires:         nss-tools
Requires:         java >= 1:1.7.0
Requires:         pki-base = %{version}-%{release}
Requires:         jpackage-utils >= 0:1.7.5-10

%description -n   pki-tools
This package contains PKI executables that can be used to help make
Certificate System into a more complete and robust PKI solution.

This package is a part of the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-server
Summary:          Certificate System - PKI Server Framework
Group:            System Environment/Base

BuildArch:        noarch

Provides:         pki-deploy = %{version}-%{release}
Provides:         pki-setup = %{version}-%{release}
Provides:         pki-silent = %{version}-%{release}

Obsoletes:        pki-deploy < %{version}-%{release}
Obsoletes:        pki-setup < %{version}-%{release}
Obsoletes:        pki-silent < %{version}-%{release}

Requires:         java >= 1:1.7.0
Requires:         java-atk-wrapper
Requires:         net-tools
Requires:         perl(File::Slurp)
Requires:         perl(XML::LibXML)
Requires:         perl-Crypt-SSLeay
Requires:         policycoreutils
Requires:         openldap-clients
Requires:         pki-base = %{version}-%{release}
Requires:         pki-tools = %{version}-%{release}

Requires:         selinux-policy-base >= 3.11.1-43
Obsoletes:        pki-selinux

Requires:         tomcat >= 7.0.47

Requires:         velocity
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units

Requires:         tomcatjss >= 7.1.0

%description -n   pki-server
The PKI Server Framework is required by the following four PKI subsystems:

    the Certificate Authority (CA),
    the Data Recovery Manager (DRM),
    the Online Certificate Status Protocol (OCSP) Manager,
    the Token Key Service (TKS), and
    the Token Processing Service (TPS).

This package is a part of the PKI Core used by the Certificate System.
The package contains scripts to create and remove PKI subsystems.

%{overview}

%package -n       pki-ca
Summary:          Certificate System - Certificate Authority
Group:            System Environment/Daemons

BuildArch:        noarch

Requires:         java >= 1:1.7.0
Requires:         pki-server = %{version}-%{release}
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units

%description -n   pki-ca
The Certificate Authority (CA) is a required PKI subsystem which issues,
renews, revokes, and publishes certificates as well as compiling and
publishing Certificate Revocation Lists (CRLs).

The Certificate Authority can be configured as a self-signing Certificate
Authority, where it is the root CA, or it can act as a subordinate CA,
where it obtains its own signing certificate from a public CA.

This package is one of the top-level java-based Tomcat PKI subsystems
provided by the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-kra
Summary:          Certificate System - Data Recovery Manager
Group:            System Environment/Daemons

BuildArch:        noarch

Requires:         java >= 1:1.7.0
Requires:         pki-server = %{version}-%{release}
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units

%description -n   pki-kra
The Data Recovery Manager (DRM) is an optional PKI subsystem that can act
as a Key Recovery Authority (KRA).  When configured in conjunction with the
Certificate Authority (CA), the DRM stores private encryption keys as part of
the certificate enrollment process.  The key archival mechanism is triggered
when a user enrolls in the PKI and creates the certificate request.  Using the
Certificate Request Message Format (CRMF) request format, a request is
generated for the user's private encryption key.  This key is then stored in
the DRM which is configured to store keys in an encrypted format that can only
be decrypted by several agents requesting the key at one time, providing for
protection of the public encryption keys for the users in the PKI deployment.

Note that the DRM archives encryption keys; it does NOT archive signing keys,
since such archival would undermine non-repudiation properties of signing keys.

This package is one of the top-level java-based Tomcat PKI subsystems
provided by the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-ocsp
Summary:          Certificate System - Online Certificate Status Protocol Manager
Group:            System Environment/Daemons

BuildArch:        noarch

Requires:         java >= 1:1.7.0
Requires:         pki-server = %{version}-%{release}
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units

%description -n   pki-ocsp
The Online Certificate Status Protocol (OCSP) Manager is an optional PKI
subsystem that can act as a stand-alone OCSP service.  The OCSP Manager
performs the task of an online certificate validation authority by enabling
OCSP-compliant clients to do real-time verification of certificates.  Note
that an online certificate-validation authority is often referred to as an
OCSP Responder.

Although the Certificate Authority (CA) is already configured with an
internal OCSP service.  An external OCSP Responder is offered as a separate
subsystem in case the user wants the OCSP service provided outside of a
firewall while the CA resides inside of a firewall, or to take the load of
requests off of the CA.

The OCSP Manager can receive Certificate Revocation Lists (CRLs) from
multiple CA servers, and clients can query the OCSP Manager for the
revocation status of certificates issued by all of these CA servers.

When an instance of OCSP Manager is set up with an instance of CA, and
publishing is set up to this OCSP Manager, CRLs are published to it
whenever they are issued or updated.

This package is one of the top-level java-based Tomcat PKI subsystems
provided by the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-tks
Summary:          Certificate System - Token Key Service
Group:            System Environment/Daemons

BuildArch:        noarch

Requires:         java >= 1:1.7.0
Requires:         pki-server = %{version}-%{release}
Requires:         pki-symkey = %{version}-%{release}
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units

%description -n   pki-tks
The Token Key Service (TKS) is an optional PKI subsystem that manages the
master key(s) and the transport key(s) required to generate and distribute
keys for hardware tokens.  TKS provides the security between tokens and an
instance of Token Processing System (TPS), where the security relies upon the
relationship between the master key and the token keys.  A TPS communicates
with a TKS over SSL using client authentication.

TKS helps establish a secure channel (signed and encrypted) between the token
and the TPS, provides proof of presence of the security token during
enrollment, and supports key changeover when the master key changes on the
TKS.  Tokens with older keys will get new token keys.

Because of the sensitivity of the data that TKS manages, TKS should be set up
behind the firewall with restricted access.

This package is one of the top-level java-based Tomcat PKI subsystems
provided by the PKI Core used by the Certificate System.

%{overview}


%package -n       pki-tps-tomcat
Summary:          Certificate System - Token Processing Service
Group:            System Environment/Daemons

BuildArch:        noarch

Provides:         pki-tps
Requires:         java >= 1:1.7.0
Requires:         pki-server = %{version}-%{release}
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units

%description -n   pki-tps-tomcat
The Token Processing System (TPS) is an optional PKI subsystem that acts
as a Registration Authority (RA) for authenticating and processing
enrollment requests, PIN reset requests, and formatting requests from
the Enterprise Security Client (ESC).

TPS is designed to communicate with tokens that conform to
Global Platform's Open Platform Specification.

TPS communicates over SSL with various PKI backend subsystems (including
the Certificate Authority (CA), the Data Recovery Manager (DRM), and the
Token Key Service (TKS)) to fulfill the user's requests.

TPS also interacts with the token database, an LDAP server that stores
information about individual tokens.

%{overview}


%package -n       pki-javadoc
Summary:          Certificate System - PKI Framework Javadocs
Group:            Documentation

BuildArch:        noarch

Provides:         pki-util-javadoc = %{version}-%{release}
Provides:         pki-java-tools-javadoc = %{version}-%{release}
Provides:         pki-common-javadoc = %{version}-%{release}

Obsoletes:        pki-util-javadoc < %{version}-%{release}
Obsoletes:        pki-java-tools-javadoc < %{version}-%{release}
Obsoletes:        pki-common-javadoc < %{version}-%{release}

%description -n   pki-javadoc
This documentation pertains exclusively to version %{version} of
the PKI Framework and Tools.

This package is a part of the PKI Core used by the Certificate System.

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
	-DBUILD_PKI_CORE:BOOL=ON \
	-DJAVA_LIB_INSTALL_DIR=%{_jnidir} \
	-DSYSTEMD_LIB_INSTALL_DIR=%{_unitdir} \
%if 0%{?rhel}
	-DRESTEASY_LIB=/usr/share/java/resteasy-base \
%else
	-DRESTEASY_LIB=/usr/share/java/resteasy \
%endif
	%{?_without_javadoc:-DWITH_JAVADOC:BOOL=OFF} \
	..
%{__make} VERBOSE=1 %{?_smp_mflags} all
# %{__make} VERBOSE=1 %{?_smp_mflags} test


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"

# Scanning the python code with pylint. A return value of 0 represents there are no
# errors or warnings reported by pylint.
sh ../pylint-build-scan.sh %{buildroot} `pwd`
if [ $? -eq 1 ]; then
    exit 1
fi

%{__rm} %{buildroot}%{_initrddir}/pki-cad
%{__rm} %{buildroot}%{_initrddir}/pki-krad
%{__rm} %{buildroot}%{_initrddir}/pki-ocspd
%{__rm} %{buildroot}%{_initrddir}/pki-tksd
%{__rm} %{buildroot}%{_initrddir}/pki-tpsd

%{__rm} -rf %{buildroot}%{_datadir}/pki/server/lib

# tomcat6 has changed how TOMCAT_LOG is used.
# Need to adjust accordingly
# This macro will be executed in the postinstall scripts
%define fix_tomcat_log() (                                                   \
if [ -d /etc/sysconfig/pki/%i ]; then                                        \
  for F in `find /etc/sysconfig/pki/%1 -type f`; do                          \
    instance=`basename $F`                                                   \
    if [ -f /etc/sysconfig/$instance ]; then                                 \
        sed -i -e 's/catalina.out/tomcat-initd.log/' /etc/sysconfig/$instance \
    fi                                                                       \
  done                                                                       \
fi                                                                           \
)
%{__mkdir_p} %{buildroot}%{_localstatedir}/log/pki
%{__mkdir_p} %{buildroot}%{_sharedstatedir}/pki

%if ! 0%{?rhel}
%pretrans -n pki-base -p <lua>
function test(a)
    if posix.stat(a) then
        for f in posix.files(a) do
            if f~=".." and f~="." then
                return true
            end
        end
    end
    return false
end

if (test("/etc/sysconfig/pki/ca") or
    test("/etc/sysconfig/pki/kra") or
    test("/etc/sysconfig/pki/ocsp") or
    test("/etc/sysconfig/pki/tks")) then
   msg = "Unable to upgrade to Fedora 20.  There are Dogtag 9 instances\n" ..
         "that will no longer work since they require Tomcat 6, and \n" ..
         "Tomcat 6 is no longer available in Fedora 20.\n\n" ..
         "Please follow these instructions to migrate the instances to \n" ..
         "Dogtag 10:\n\n" ..
         "http://pki.fedoraproject.org/wiki/Migrating_Dogtag_9_Instances_to_Dogtag_10"
   error(msg)
end
%endif

%post -n pki-base
sed -i -e 's/^JNI_JAR_DIR=.*$/JNI_JAR_DIR=\/usr\/lib\/java/' %{_datadir}/pki/etc/pki.conf

if [ $1 -eq 1 ]
then
    # On RPM installation create system upgrade tracker
    echo "Configuration-Version: %{version}" > %{_sysconfdir}/pki/pki.version

else
    # On RPM upgrade run system upgrade
    echo "Upgrading system at `/bin/date`." >> /var/log/pki/pki-upgrade-%{version}.log 2>&1
    /sbin/pki-upgrade --silent >> /var/log/pki/pki-upgrade-%{version}.log 2>&1
    echo >> /var/log/pki/pki-upgrade-%{version}.log 2>&1
fi

%postun -n pki-base

if [ $1 -eq 0 ]
then
    # On RPM uninstallation remove system upgrade tracker
    rm -f %{_sysconfdir}/pki/pki.version
fi

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
        else
            # Conditionally restart this Dogtag 9 instance
            /bin/systemctl condrestart pki-cad@${inst}.service
        fi
    done
fi
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
%fix_tomcat_log ca


%post -n pki-kra
# Attempt to update ALL old "KRA" instances to "systemd"
if [ -d /etc/sysconfig/pki/kra ]; then
    for inst in `ls /etc/sysconfig/pki/kra`; do
        if [ ! -e "/etc/systemd/system/pki-krad.target.wants/pki-krad@${inst}.service" ]; then
            ln -s "/lib/systemd/system/pki-krad@.service" \
                  "/etc/systemd/system/pki-krad.target.wants/pki-krad@${inst}.service"
            [ -L /var/lib/${inst}/${inst} ] && unlink /var/lib/${inst}/${inst}
            ln -s /usr/sbin/tomcat6-sysd /var/lib/${inst}/${inst}

            if [ -e /var/run/${inst}.pid ]; then
                kill -9 `cat /var/run/${inst}.pid` || :
                rm -f /var/run/${inst}.pid
                echo "pkicreate.systemd.servicename=pki-krad@${inst}.service" >> \
                     /var/lib/${inst}/conf/CS.cfg || :
                /bin/systemctl daemon-reload >/dev/null 2>&1 || :
                /bin/systemctl restart pki-krad@${inst}.service || :
            else 
                echo "pkicreate.systemd.servicename=pki-krad@${inst}.service" >> \
                     /var/lib/${inst}/conf/CS.cfg || :
            fi
        else
            # Conditionally restart this Dogtag 9 instance
            /bin/systemctl condrestart pki-krad@${inst}.service
        fi
    done
fi
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
%fix_tomcat_log kra


%post -n pki-ocsp
# Attempt to update ALL old "OCSP" instances to "systemd"
if [ -d /etc/sysconfig/pki/ocsp ]; then
    for inst in `ls /etc/sysconfig/pki/ocsp`; do
        if [ ! -e "/etc/systemd/system/pki-ocspd.target.wants/pki-ocspd@${inst}.service" ]; then
            ln -s "/lib/systemd/system/pki-ocspd@.service" \
                  "/etc/systemd/system/pki-ocspd.target.wants/pki-ocspd@${inst}.service"
            [ -L /var/lib/${inst}/${inst} ] && unlink /var/lib/${inst}/${inst}
            ln -s /usr/sbin/tomcat6-sysd /var/lib/${inst}/${inst}

            if [ -e /var/run/${inst}.pid ]; then
                kill -9 `cat /var/run/${inst}.pid` || :
                rm -f /var/run/${inst}.pid
                echo "pkicreate.systemd.servicename=pki-ocspd@${inst}.service" >> \
                     /var/lib/${inst}/conf/CS.cfg || :
                /bin/systemctl daemon-reload >/dev/null 2>&1 || :
                /bin/systemctl restart pki-ocspd@${inst}.service || :
            else 
                echo "pkicreate.systemd.servicename=pki-ocspd@${inst}.service" >> \
                     /var/lib/${inst}/conf/CS.cfg || :
            fi
        else
            # Conditionally restart this Dogtag 9 instance
            /bin/systemctl condrestart pki-ocspd@${inst}.service
        fi
    done
fi
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
%fix_tomcat_log ocsp


%post -n pki-tks
# Attempt to update ALL old "TKS" instances to "systemd"
if [ -d /etc/sysconfig/pki/tks ]; then
    for inst in `ls /etc/sysconfig/pki/tks`; do
        if [ ! -e "/etc/systemd/system/pki-tksd.target.wants/pki-tksd@${inst}.service" ]; then
            ln -s "/lib/systemd/system/pki-tksd@.service" \
                  "/etc/systemd/system/pki-tksd.target.wants/pki-tksd@${inst}.service"
            [ -L /var/lib/${inst}/${inst} ] && unlink /var/lib/${inst}/${inst}
            ln -s /usr/sbin/tomcat6-sysd /var/lib/${inst}/${inst}

            if [ -e /var/run/${inst}.pid ]; then
                kill -9 `cat /var/run/${inst}.pid` || :
                rm -f /var/run/${inst}.pid
                echo "pkicreate.systemd.servicename=pki-tksd@${inst}.service" >> \
                     /var/lib/${inst}/conf/CS.cfg || :
                /bin/systemctl daemon-reload >/dev/null 2>&1 || :
                /bin/systemctl restart pki-tksd@${inst}.service || :
            else 
                echo "pkicreate.systemd.servicename=pki-tksd@${inst}.service" >> \
                     /var/lib/${inst}/conf/CS.cfg || :
            fi
        else
            # Conditionally restart this Dogtag 9 instance
            /bin/systemctl condrestart pki-tksd@${inst}.service
        fi
    done
fi
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
%fix_tomcat_log tks


%post -n pki-server
## NOTE:  At this time, NO attempt has been made to update ANY PKI subsystem
##        from EITHER 'sysVinit' OR previous 'systemd' processes to the new
##        PKI deployment process

echo "Upgrading server at `/bin/date`." >> /var/log/pki/pki-server-upgrade-%{version}.log 2>&1
/sbin/pki-server-upgrade --silent >> /var/log/pki/pki-server-upgrade-%{version}.log 2>&1
echo >> /var/log/pki/pki-server-upgrade-%{version}.log 2>&1


%preun -n pki-ca
if [ $1 = 0 ] ; then
    /bin/systemctl --no-reload disable pki-cad.target > /dev/null 2>&1 || :
    /bin/systemctl stop pki-cad.target > /dev/null 2>&1 || :
fi


%preun -n pki-kra
if [ $1 = 0 ] ; then
    /bin/systemctl --no-reload disable pki-krad.target > /dev/null 2>&1 || :
    /bin/systemctl stop pki-krad.target > /dev/null 2>&1 || :
fi


%preun -n pki-ocsp
if [ $1 = 0 ] ; then
    /bin/systemctl --no-reload disable pki-ocspd.target > /dev/null 2>&1 || :
    /bin/systemctl stop pki-ocspd.target > /dev/null 2>&1 || :
fi


%preun -n pki-tks
if [ $1 = 0 ] ; then
    /bin/systemctl --no-reload disable pki-tksd.target > /dev/null 2>&1 || :
    /bin/systemctl stop pki-tksd.target > /dev/null 2>&1 || :
fi


## %preun -n pki-server
## NOTE:  At this time, NO attempt has been made to update ANY PKI subsystem
##        from EITHER 'sysVinit' OR previous 'systemd' processes to the new
##        PKI deployment process


%postun -n pki-ca
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -ge "1" ] ; then
    /bin/systemctl try-restart pki-cad.target >/dev/null 2>&1 || :
fi


%postun -n pki-kra
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -ge "1" ] ; then
    /bin/systemctl try-restart pki-krad.target >/dev/null 2>&1 || :
fi


%postun -n pki-ocsp
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -ge "1" ] ; then
    /bin/systemctl try-restart pki-ocspd.target >/dev/null 2>&1 || :
fi


%postun -n pki-tks
/bin/systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -ge "1" ] ; then
    /bin/systemctl try-restart pki-tksd.target >/dev/null 2>&1 || :
fi


## %postun -n pki-server
## NOTE:  At this time, NO attempt has been made to update ANY PKI subsystem
##        from EITHER 'sysVinit' OR previous 'systemd' processes to the new
##        PKI deployment process

%files -n pki-symkey
%defattr(-,root,root,-)
%doc base/symkey/LICENSE
%{_jnidir}/symkey.jar
%{_libdir}/symkey/


%files -n pki-base
%defattr(-,root,root,-)
%doc base/common/LICENSE
%dir %{_datadir}/pki
%{_datadir}/pki/VERSION
%{_datadir}/pki/etc/
%{_datadir}/pki/upgrade/
%dir %{_sysconfdir}/pki
%config(noreplace) %{_sysconfdir}/pki/pki.conf
%dir %{_javadir}/pki
%{_javadir}/pki/pki-cmsutil.jar
%{_javadir}/pki/pki-nsutil.jar
%{_javadir}/pki/pki-certsrv.jar
%dir %{python_sitelib}/pki
%{python_sitelib}/pki/*.py
%{python_sitelib}/pki/*.pyc
%{python_sitelib}/pki/*.pyo
%dir %{_localstatedir}/log/pki
%{_sbindir}/pki-upgrade
%{_mandir}/man8/pki-upgrade.8.gz

%files -n pki-tools
%defattr(-,root,root,-)
%doc base/native-tools/LICENSE base/native-tools/doc/README
%{_bindir}/pki
%{_bindir}/p7tool
%{_bindir}/revoker
%{_bindir}/setpin
%{_bindir}/sslget
%{_bindir}/tkstool
%{_datadir}/pki/native-tools/
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
%{_javadir}/pki/pki-tools.jar
%{_datadir}/pki/java-tools/
%{_mandir}/man1/pki.1.gz


%files -n pki-server
%defattr(-,root,root,-)
%doc base/common/THIRD_PARTY_LICENSES
%doc base/server/LICENSE
%{_sysconfdir}/pki/default.cfg
%{_sbindir}/pkispawn
%{_sbindir}/pkidestroy
%{_sbindir}/pki-server-upgrade
#%{_bindir}/pki-setup-proxy
%{python_sitelib}/pki/server/
%dir %{_datadir}/pki/deployment
%{_datadir}/pki/deployment/config/
%dir %{_datadir}/pki/scripts
%{_datadir}/pki/scripts/operations
%{_datadir}/pki/scripts/pkicommon.pm
%{_datadir}/pki/scripts/functions
%{_datadir}/pki/scripts/pki_apache_initscript
%{_bindir}/pkidaemon
%dir %{_sysconfdir}/systemd/system/pki-tomcatd.target.wants
%{_unitdir}/pki-tomcatd@.service
%{_unitdir}/pki-tomcatd.target
%{_javadir}/pki/pki-cms.jar
%{_javadir}/pki/pki-cmsbundle.jar
%{_javadir}/pki/pki-cmscore.jar
%{_javadir}/pki/pki-silent.jar
%{_javadir}/pki/pki-tomcat.jar
%dir %{_sharedstatedir}/pki
%{_bindir}/pkicreate
%{_bindir}/pkiremove
%{_bindir}/pki-setup-proxy
%{_bindir}/pkisilent
%{_datadir}/pki/silent/
%{_bindir}/pkicontrol
%{_mandir}/man5/pki_default.cfg.5.gz
%{_mandir}/man8/pki-server-upgrade.8.gz
%{_mandir}/man8/pkidestroy.8.gz
%{_mandir}/man8/pkispawn.8.gz

%{_datadir}/pki/setup/
%{_datadir}/pki/server/

%files -n pki-ca
%defattr(-,root,root,-)
%doc base/ca/LICENSE
%dir %{_sysconfdir}/systemd/system/pki-cad.target.wants
%{_unitdir}/pki-cad@.service
%{_unitdir}/pki-cad.target
%{_javadir}/pki/pki-ca.jar
%dir %{_datadir}/pki/ca
%{_datadir}/pki/ca/conf/
%{_datadir}/pki/ca/emails/
%dir %{_datadir}/pki/ca/profiles
%{_datadir}/pki/ca/profiles/ca/
%{_datadir}/pki/ca/setup/
%{_datadir}/pki/ca/webapps/

%files -n pki-kra
%defattr(-,root,root,-)
%doc base/kra/LICENSE
%dir %{_sysconfdir}/systemd/system/pki-krad.target.wants
%{_unitdir}/pki-krad@.service
%{_unitdir}/pki-krad.target
%{_javadir}/pki/pki-kra.jar
%dir %{_datadir}/pki/kra
%{_datadir}/pki/kra/conf/
%{_datadir}/pki/kra/setup/
%{_datadir}/pki/kra/webapps/

%files -n pki-ocsp
%defattr(-,root,root,-)
%doc base/ocsp/LICENSE
%dir %{_sysconfdir}/systemd/system/pki-ocspd.target.wants
%{_unitdir}/pki-ocspd@.service
%{_unitdir}/pki-ocspd.target
%{_javadir}/pki/pki-ocsp.jar
%dir %{_datadir}/pki/ocsp
%{_datadir}/pki/ocsp/conf/
%{_datadir}/pki/ocsp/setup/
%{_datadir}/pki/ocsp/webapps/

%files -n pki-tks
%defattr(-,root,root,-)
%doc base/tks/LICENSE
%dir %{_sysconfdir}/systemd/system/pki-tksd.target.wants
%{_unitdir}/pki-tksd@.service
%{_unitdir}/pki-tksd.target
%{_javadir}/pki/pki-tks.jar
%dir %{_datadir}/pki/tks
%{_datadir}/pki/tks/conf/
%{_datadir}/pki/tks/setup/
%{_datadir}/pki/tks/webapps/

%files -n pki-tps-tomcat
%defattr(-,root,root,-)
%doc base/tps/LICENSE
%dir %{_sysconfdir}/systemd/system/pki-tpsd.target.wants
%{_unitdir}/pki-tpsd@.service
%{_unitdir}/pki-tpsd.target
%{_javadir}/pki/pki-tps.jar
%dir %{_datadir}/pki/tps
%{_datadir}/pki/tps/conf/
%{_datadir}/pki/tps/setup/
%{_datadir}/pki/tps/webapps/

%if %{?_without_javadoc:0}%{!?_without_javadoc:1}
%files -n pki-javadoc
%defattr(-,root,root,-)
%{_javadocdir}/pki-%{version}/
%endif


%changelog
* Fri Nov 15 2013 Ade Lee <alee@redhat.com> 10.1.0-1
- Trac Ticket 788 - Clean up spec files
- Update release number for release build
- Updated requirements for resteasy

* Sun Nov 10 2013 Ade Lee <alee@redhat.com> 10.1.0-0.14
- Change release number for beta build

* Thu Nov 7 2013 Ade Lee <alee@redhat.com> 10.1.0-0.13
- Updated requirements for tomcat

* Fri Oct 4 2013 Ade Lee <alee@redhat.com> 10.1.0-0.12
- Removed additional /var/run, /var/lock references.

* Fri Oct 4 2013 Ade Lee <alee@redhat.com> 10.1.0-0.11
- Removed delivery of /var/lock and /var/run directories for fedora 20.

* Wed Aug 14 2013 Endi S. Dewata <edewata@redhat.com> 10.1.0-0.10
- Moved Tomcat-based TPS into pki-core.

* Wed Aug 14 2013 Abhishek Koneru <akoneru@redhat.com> 10.1.0.0.9
- Listed new packages required during build, due to issues reported
  by pylint.
- Packages added: python-requests, python-ldap, libselinux-python,
                  policycoreutils-python

* Fri Aug 09 2013 Abhishek Koneru <akoneru@redhat.com> 10.1.0.0.8
- Added pylint scan to the build process.
 
* Mon Jul 22 2013 Endi S. Dewata <edewata@redhat.com> 10.1.0-0.7
- Added man pages for upgrade tools.

* Wed Jul 17 2013 Endi S. Dewata <edewata@redhat.com> 10.1.0-0.6
- Cleaned up the code to install man pages.

* Tue Jul 16 2013 Endi S. Dewata <edewata@redhat.com> 10.1.0-0.5
- Reorganized deployment tools.

* Tue Jul 9 2013 Ade Lee <alee@redhat.com> 10.1.0-0.4
- Bugzilla Bug 973224 -  resteasy-base must be split into subpackages
  to simplify dependencies

* Fri Jun 14 2013 Endi S. Dewata <edewata@redhat.com> 10.1.0-0.3
- Updated dependencies to Java 1.7.

* Wed Jun 5 2013 Matthew Harmsen <mharmsen@redhat.com> 10.1.0-0.2
- TRAC Ticket 606 - add restart / start at boot info to pkispawn man page
- TRAC Ticket 610 - Document limitation in using GUI install
- TRAC Ticket 629 - Package ownership of '/usr/share/pki/etc/' directory

* Tue May 7 2013 Ade Lee <alee@redhat.com> 10.1.0-0.1
- Change release number for 10.1 development

* Mon May 6 2013 Endi S. Dewata <edewata@redhat.com> 10.0.2-5
- Fixed incorrect JNI_JAR_DIR.

* Sat May 4 2013 Ade Lee <alee@redhat.com> 10.0.2-4
- TRAC Ticket 605 Junit internal function used in TestRunner,
  breaks F19 build

* Sat May 4 2013 Ade Lee <alee@redhat.com> 10.0.2-3
- TRAC Ticket 604 Added fallback methods for pkispawn tests

* Mon Apr 29 2013 Endi S. Dewata <edewata@redhat.com> 10.0.2-2
- Added default pki.conf in /usr/share/pki/etc
- Create upgrade tracker on install and remove it on uninstall

* Fri Apr 26 2013 Ade Lee <alee@redhat.com> 10.0.2-1
- Change release number for official release.

* Thu Apr 25 2013 Ade Lee <alee@redhat.com> 10.0.2-0.8
- Added %pretrans script for f19
- Added java-atk-wrapper dependency

* Wed Apr 24 2013 Endi S. Dewata <edewata@redhat.com> 10.0.2-0.7
- Added pki-server-upgrade script and pki.server module.
- Call upgrade scripts in %post for pki-base and pki-server.

* Tue Apr 23 2013 Endi S. Dewata <edewata@redhat.com> 10.0.2-0.6
- Added dependency on commons-io.

* Mon Apr 22 2013 Ade Lee <alee@redhat.com> 10.0.2-0.5
- Add /var/log/pki and /var/lib/pki directories

* Tue Apr 16 2013 Endi S. Dewata <edewata@redhat.com> 10.0.2-0.4
- Run pki-upgrade on post server installation.

* Mon Apr 15 2013 Endi S. Dewata <edewata@redhat.com> 10.0.2-0.3
- Added dependency on python-lxml.

* Fri Apr 5 2013 Endi S. Dewata <edewata@redhat.com> 10.0.2-0.2
- Added pki-upgrade script.

* Fri Apr 5 2013 Endi S. Dewata <edewata@redhat.com> 10.0.2-0.1
- Updated version number to 10.0.2-0.1.

* Fri Apr 5 2013 Endi S. Dewata <edewata@redhat.com> 10.0.1-9
- Renamed base/deploy to base/server.
- Moved pki.conf into pki-base.
- Removed redundant pki/server folder declaration.

* Tue Mar 19 2013 Ade Lee <alee@redhat.com> 10.0.1-8
- Removed jython dependency

* Mon Mar 11 2013 Endi S. Dewata <edewata@redhat.com> 10.0.1-7
- Added minimum python-requests version.

* Fri Mar 8 2013 Matthew Harmsen <mharmsen@redhat.com> 10.0.1-6
- Bugzilla Bug #919476 - pkispawn crashes due to dangling symlink to jss4.jar

* Thu Mar 7 2013 Endi S. Dewata <edewata@redhat.com> 10.0.1-5
- Added dependency on python-requests.
- Reorganized Python module packaging.

* Thu Mar 7 2013 Endi S. Dewata <edewata@redhat.com> 10.0.1-4
- Added dependency on python-ldap.

* Mon Mar  4 2013 Matthew Harmsen <mharmsen@redhat.com> 10.0.1-3
- TRAC Ticket #517 - Clean up theme dependencies
- TRAC Ticket #518 - Remove UI dependencies from pkispawn . . .

* Fri Mar  1 2013 Matthew Harmsen <mharmsen@redhat.com> 10.0.1-2
- Removed runtime dependency on 'pki-server-theme' to resolve
  Bugzilla Bug #916134 - unresolved dependency in pki-server: pki-server-theme

* Tue Jan 15 2013 Ade Lee <alee@redhat.com> 10.0.1-1
- TRAC Ticket 214 - Missing error description for duplicate user
- TRAC Ticket 213 - Add nonces for cert revocation
- TRAC Ticket 367 - pkidestroy does not remove connector
- TRAC Ticket #430 - License for 3rd party code
- Bugzilla Bug 839426 - [RFE] ECC CRL support for OCSP
- Fix spec file to allow f17 to work with latest tomcatjss
- TRAC Ticket 466 - Increase root CA validity to 20 years
- TRAC Ticket 469 - Fix tomcatjss issue in spec files
- TRAC Ticket 468 - pkispawn throws exception
- TRAC Ticket 191 - Mapping HTTP Exceptions to HTTP error codes
- TRAC Ticket 271 - Dogtag 10: Fix 'status' command in 'pkidaemon' . . .
- TRAC Ticket 437 - Make admin cert p12 file location configurable
- TRAC Ticket 393 - pkispawn fails when selinux is disabled
- Punctuation and formatting changes in man pages
- Revert to using default config file for pkidestroy
- Hardcode setting of resteasy-lib for instance
- TRAC Ticket 436 - Interpolation for pki_subsystem
- TRAC Ticket 433 - Interpolation for paths
- TRAC Ticket 435 - Identical instance id and instance name
- TRAC Ticket 406 - Replace file dependencies with package dependencies

* Wed Jan  9 2013 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-5
- TRAC Ticket #430 - License for 3rd party code

* Fri Jan  4 2013 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-4
- TRAC Ticket #469 - Dogtag 10: Fix tomcatjss issue in pki-core.spec and
  dogtag-pki.spec . . .
- TRAC Ticket #468 - pkispawn throws exception

* Wed Dec 12 2012 Ade Lee <alee@redhat.com> 10.0.0-3
- Replaced file dependencies with package dependencies

* Mon Dec 10 2012 Ade Lee <alee@redhat.com> 10.0.0-2
- Updated man pages

* Fri Dec 7 2012 Ade Lee <alee@redhat.com> 10.0.0-1
- Update to official release for rc1

* Thu Dec  6 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.56.b3
- TRAC Ticket #315 - Man pages for pkispawn/pkidestroy.
- Added place-holders for 'pki.1' and 'pki_default.cfg.5' man pages.

* Thu Dec 6 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.55.b3
- Added system-wide configuration /etc/pki/pki.conf.
- Removed redundant lines in %files.

* Tue Dec 4 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.54.b3
- Moved default deployment configuration to /etc/pki.

* Mon Nov 19 2012 Ade Lee <alee@redhat.com> 10.0.0-0.53.b3
- Cleaned up spec file to provide only support rhel 7+, f17+
- Added resteasy-base dependency for rhel 7
- Update cmake version

* Mon Nov 12 2012 Ade Lee <alee@redhat.com> 10.0.0-0.52.b3
- Update release to b3

* Fri Nov 9 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.51.b2
- Removed dependency on CA, KRA, OCSP, TKS theme packages.

* Thu Nov 8 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.50.b2
- Renamed pki-common-theme to pki-server-theme.

* Thu Nov  8 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.49.b2
- TRAC Ticket #395 - Dogtag 10: Add a Tomcat 7 runtime requirement to
  'pki-server'

* Mon Oct 29 2012 Ade Lee <alee@redhat.com> 10.0.0-0.48.b2
- Update release to b2

* Wed Oct 24 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.47.b1
- TRAC Ticket #350 - Dogtag 10: Remove version numbers from PKI jar files . . .

* Tue Oct 23 2012 Ade Lee <alee@redhat.com> 10.0.0-0.46.b1
- Added Obsoletes for pki-selinux

* Tue Oct 23 2012 Ade Lee <alee@redhat.com> 10.0.0-0.45.b1
- Remove build of pki-selinux for f18, use system policy instead

* Fri Oct 12 2012 Ade Lee <alee@redhat.com> 10.0.0-0.44.b1
- Update required tomcatjss version
- Added net-tools dependency

* Mon Oct 8 2012 Ade Lee <alee@redhat.com> 10.0.0-0.43.b1
- Update selinux-policy version to fix error from latest policy changes

* Mon Oct 8 2012 Ade Lee <alee@redhat.com> 10.0.0-0.42.b1
- Fix typo in selinux policy versions

* Mon Oct 8 2012 Ade Lee <alee@redhat.com> 10.0.0-0.41.b1
- Added build requires for correct version of selinux-policy-devel

* Mon Oct 8 2012 Ade Lee <alee@redhat.com> 10.0.0-0.40.b1
- Update release to b1

* Fri Oct 5 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.40.a2
- Merged pki-silent into pki-server.

* Fri Oct 5 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.39.a2
- Renamed "shared" folder to "server".

* Fri Oct 5 2012 Ade Lee <alee@redhat.com> 10.0.0-0.38.a2
- Added required selinux versions for new policy.

* Tue Oct 2 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.37.a2
- Added Provides to packages replacing obsolete packages.

* Mon Oct 1 2012 Ade Lee <alee@redhat.com> 10.0.0-0.36.a2
- Update release to a2

* Sun Sep 30 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.36.a1
- Modified CMake to use RPM version number

* Tue Sep 25 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.35.a1
- Added VERSION file

* Mon Sep 24 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.34.a1
- Merged pki-setup into pki-server

* Thu Sep 13 2012 Ade Lee <alee@redhat.com> 10.0.0-0.33.a1
- Added Conflicts for IPA 2.X
- Added build requires for zip to work around mock problem

* Wed Sep 12 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.32.a1
- TRAC Ticket #312 - Dogtag 10: Automatically restart any running instances
  upon RPM "update" . . .
- TRAC Ticket #317 - Dogtag 10: Move "pkispawn"/"pkidestroy"
  from /usr/bin to /usr/sbin . . .

* Wed Sep 12 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.31.a1
- Fixed pki-server to include everything in shared dir.

* Tue Sep 11 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.30.a1
- Added build dependency on redhat-rpm-config.

* Thu Aug 30 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.29.a1
- Merged Javadoc packages.

* Thu Aug 30 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.28.a1
- Added pki-tomcat.jar.

* Thu Aug 30 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.27.a1
- Moved webapp creation code into pkispawn.

* Mon Aug 20 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.26.a1
- Split pki-client.jar into pki-certsrv.jar and pki-tools.jar.

* Mon Aug 20 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.25.a1
- Merged pki-native-tools and pki-java-tools into pki-tools.
- Modified pki-server to depend on pki-tools.

* Mon Aug 20 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.24.a1
- Split pki-common into pki-base and pki-server.
- Merged pki-util into pki-base.
- Merged pki-deploy into pki-server.

* Thu Aug 16 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.23.a1
- Updated release of 'tomcatjss' to rely on Tomcat 7 for Fedora 17
- Changed Dogtag 10 build-time and runtime requirements for 'pki-deploy'
- Altered PKI Package Dependency Chain (top-to-bottom):
  pki-ca, pki-kra, pki-ocsp, pki-tks --> pki-deploy --> pki-common

* Mon Aug 13 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.22.a1
- Added pki-client.jar.

* Fri Jul 27 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.21.a1
- Merged pki-jndi-realm.jar into pki-cmscore.jar.

* Tue Jul 24 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.20.a1
- PKI TRAC Task #254 - Dogtag 10: Fix spec file to build successfully
  via mock on Fedora 17 . . .

* Wed Jul 11 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.19.a1
- Moved 'pki-jndi-real.jar' link from 'tomcat6' to 'tomcat' (Tomcat 7)

* Thu Jun 14 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.18.a1
- Updated release of 'tomcatjss' to rely on Tomcat 7 for Fedora 18

* Tue May 29 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.17.a1
- Added CLI for REST services

* Fri May 18 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.16.a1
- Integration of Tomcat 7
- Addition of centralized 'pki-tomcatd' systemd functionality to the
  PKI Deployment strategy
- Removal of 'pki_flavor' attribute

* Mon Apr 16 2012 Ade Lee <alee@redhat.com> 10.0.0-0.15.a1
- BZ 813075 - selinux denial for file size access

* Thu Apr  5 2012 Christina Fu <cfu@redhat.com> 10.0.0-0.14.a1
- Bug 745278 - [RFE] ECC encryption keys cannot be archived

* Tue Mar 27 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.13.a1
- Replaced candlepin-deps with resteasy

* Fri Mar 23 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.12.a1
- Added option to build without Javadoc

* Fri Mar 16 2012 Ade Lee <alee@redhat.com> 10.0.0-0.11.a1
- BZ 802396 - Change location of TOMCAT_LOG to match tomcat6 changes
- Corrected patch selected for selinux f17 rules

* Wed Mar 14 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.10.a1
- Corrected 'junit' dependency check

* Mon Mar 12 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.9.a1
- Initial attempt at PKI deployment framework described in
  'http://pki.fedoraproject.org/wiki/PKI_Instance_Deployment'.

* Fri Mar 09 2012 Jack Magne <jmagne@redhat.com> 10.0.0-0.8.a1
- Added support for pki-jndi-realm in tomcat6 in pki-common
  and pki-kra.
- Ticket #69.

* Fri Mar  2 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.7.a1
- For 'mock' purposes, removed platform-specific logic from around
  the 'patch' files so that ALL 'patch' files will be included in
  the SRPM.

* Wed Feb 29 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.6.a1
- Removed dependency on OSUtil.

* Tue Feb 28 2012 Ade Lee <alee@redhat.com> 10.0.0-0.5.a1
- 'pki-selinux'
-      Added platform-dependent patches for SELinux component
-      Bugzilla Bug #739708 - Selinux fix for ephemeral ports (F16)
-      Bugzilla Bug #795966 - pki-selinux policy is kind of a mess (F17)

* Thu Feb 23 2012 Endi S. Dewata <edewata@redhat.com> 10.0.0-0.4.a1
- Added dependency on Apache Commons Codec.

* Wed Feb 22 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.3.a1
- Add '-DSYSTEMD_LIB_INSTALL_DIR' override flag to 'cmake' to address changes
  in fundamental path structure in Fedora 17
- 'pki-setup'
-      Hard-code Perl dependencies to protect against bugs such as
       Bugzilla Bug #772699 - Adapt perl and python fileattrs to
       changed file 5.10 magics
- 'pki-selinux'
-      Bugzilla Bug #795966 - pki-selinux policy is kind of a mess

* Mon Feb 20 2012 Matthew Harmsen <mharmsen@redhat.com> 10.0.0-0.2.a1
- Integrated 'pki-kra' into 'pki-core'
- Integrated 'pki-ocsp' into 'pki-core'
- Integrated 'pki-tks' into 'pki-core'
- Bugzilla Bug #788787 - added 'junit'/'junit4' build-time requirements

* Wed Feb  1 2012 Nathan Kinder <nkinder@redhat.com> 10.0.0-0.1.a1
- Updated package version number

* Mon Jan 16 2012 Ade Lee <alee@redhat.com> 9.0.16-3
- Added resteasy-jettison-provider-2.3-RC1.jar to pki-setup

* Mon Nov 28 2011 Endi S. Dewata <edewata@redhat.com> 9.0.16-2
- Added JUnit tests
 
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

