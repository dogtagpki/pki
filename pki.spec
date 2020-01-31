################################################################################
Name:             pki
################################################################################
#
#  This spec file is a combination of pki-core.spec and pki-console.spec
#  for supporting COPR autobuild. When modifying the spec file please
#  synchronize the changes with the following command:
#
#    $ meld pki.spec specs/pki-core.spec
#    $ meld pki.spec specs/pki-console.spec
#
################################################################################

%global           vendor dogtag
%global           brand Dogtag

Summary:          Certificate System
URL:              https://www.dogtagpki.org/
License:          GPLv2

Version:          10.5.17
Release:          1%{?_timestamp}%{?_commit_id}%{?dist}

%if 0%{?rhel}
# NOTE:  In the future, as a part of its path, this URL will contain a release
#        directory which consists of the fixed number of the upstream release
#        upon which this tarball was originally based.
Source:           https://www.dogtagpki.org/pki/sources/%{name}/%{version}/%{release}/rhel/%{name}-%{version}%{?prerel}.tar.gz
%else
Source:           https://github.com/dogtagpki/pki/archive/v%{version}/pki-%{version}.tar.gz
%endif

#Patch0:           pki-core-CA-OCSP-SystemCertsVerification.patch

# Obtain version phase number (e. g. - used by "alpha", "beta", etc.)
#
#     NOTE:  For "alpha" releases, will be ".a1", ".a2", etc.
#            For "beta" releases, will be ".b1", ".b2", etc.
#
%define version_phase "%(echo `echo %{version} | awk -F. '{ print $4 }'`)"

################################################################################
# Python
################################################################################

%if 0%{?fedora} || 0%{?rhel} > 7
%global with_python3 1
%else
%global with_python3 0
%endif

%if 0%{?rhel}
# Package RHEL-specific RPMS Only
%global package_rhel_packages 1
# Package RHCS-specific RPMS Only
%global package_rhcs_packages 1
%define pki_core_rhel_version 10.5.17
%else
# Fedora always packages all RPMS
%global package_fedora_packages 1
%endif

################################################################################
# Java
################################################################################

%define java_home %{_usr}/lib/jvm/jre-1.8.0-openjdk

# Tomcat
%if 0%{?fedora} || 0%{?rhel} > 7
%define with_tomcat7 0
%define with_tomcat8 1
%else
%define with_tomcat7 1
%define with_tomcat8 0
%endif

################################################################################
# RESTEasy
################################################################################

%if 0%{?rhel} && 0%{?rhel} <= 7
%define jaxrs_api_jar /usr/share/java/resteasy-base/jaxrs-api.jar
%define resteasy_lib /usr/share/java/resteasy-base
%else
%define jaxrs_api_jar /usr/share/java/jboss-jaxrs-2.0-api.jar
%define resteasy_lib /usr/share/java/resteasy
%endif

################################################################################
# PKI
################################################################################

%bcond_without    server
%bcond_without    javadoc

# ignore unpackaged files from native 'tpsclient'
# REMINDER:  Remove this '%%define' once 'tpsclient' is rewritten as a Java app
%define _unpackaged_files_terminate_build 0

# pkiuser and group. The uid and gid are preallocated
# see /usr/share/doc/setup/uidgid
%define pki_username pkiuser
%define pki_uid 17
%define pki_groupname pkiuser
%define pki_gid 17
%define pki_homedir /usr/share/pki

################################################################################
# Build Dependencies
################################################################################

# autosetup
BuildRequires:    git

BuildRequires:    cmake >= 2.8.9-1
BuildRequires:    gcc-c++
BuildRequires:    zip
BuildRequires:    java-1.8.0-openjdk-devel
BuildRequires:    redhat-rpm-config
BuildRequires:    ldapjdk >= 4.19-5
BuildRequires:    apache-commons-cli
BuildRequires:    apache-commons-codec
BuildRequires:    apache-commons-io
BuildRequires:    apache-commons-lang
BuildRequires:    jakarta-commons-httpclient
BuildRequires:    slf4j
%if 0%{?rhel} && 0%{?rhel} <= 7
# no slf4j-jdk14
%else
BuildRequires:    slf4j-jdk14
%endif
BuildRequires:    nspr-devel
BuildRequires:    nss-devel >= 3.28.3

%if 0%{?rhel} && 0%{?rhel} <= 7
BuildRequires:    nuxwdog-client-java >= 1.0.3-8
%else
BuildRequires:    nuxwdog-client-java >= 1.0.3-14
%endif

BuildRequires:    openldap-devel
BuildRequires:    pkgconfig
BuildRequires:    policycoreutils
BuildRequires:    python-lxml
BuildRequires:    python-sphinx
BuildRequires:    velocity
BuildRequires:    xalan-j2
BuildRequires:    xerces-j2

%if 0%{?rhel} && 0%{?rhel} <= 7
# 'resteasy-base' is a subset of the complete set of
# 'resteasy' packages and consists of what is needed to
# support the PKI Restful interface on certain RHEL platforms
BuildRequires:    resteasy-base-atom-provider >= 3.0.6-1
BuildRequires:    resteasy-base-client >= 3.0.6-1
BuildRequires:    resteasy-base-jaxb-provider >= 3.0.6-1
BuildRequires:    resteasy-base-jaxrs >= 3.0.6-1
BuildRequires:    resteasy-base-jaxrs-api >= 3.0.6-1
BuildRequires:    resteasy-base-jackson-provider >= 3.0.6-1
%else
BuildRequires:    jboss-annotations-1.2-api
BuildRequires:    jboss-jaxrs-2.0-api
BuildRequires:    jboss-logging
BuildRequires:    resteasy-atom-provider >= 3.0.17-1
BuildRequires:    resteasy-client >= 3.0.17-1
BuildRequires:    resteasy-jaxb-provider >= 3.0.17-1
BuildRequires:    resteasy-core >= 3.0.17-1
BuildRequires:    resteasy-jackson-provider >= 3.0.17-1
%endif

%if 0%{?fedora} || 0%{?rhel} > 7
BuildRequires:    pylint
BuildRequires:    python-flake8 >= 2.5.4
BuildRequires:    python3-flake8 >= 2.5.4
# python-flake8 2.5.4 package should require pyflakes >= 1.2.3
BuildRequires:    pyflakes >= 1.2.3
# python3-flake8 2.5.4 package should require python3-pyflakes >= 1.2.3
BuildRequires:    python3-pyflakes >= 1.2.3
%endif

BuildRequires:    python2-cryptography
BuildRequires:    python-nss
BuildRequires:    python-requests >= 2.6.0
BuildRequires:    python-six
BuildRequires:    libselinux-python
BuildRequires:    policycoreutils-python
%if 0%{?fedora} || 0%{?rhel} > 7
BuildRequires:    policycoreutils-python-utils
%endif
BuildRequires:    python-ldap
BuildRequires:    junit
BuildRequires:    jpackage-utils >= 0:1.7.5-10
%if 0%{?rhel} && 0%{?rhel} <= 7
BuildRequires:    jss >= 4.4.4-5
BuildRequires:    tomcatjss >= 7.2.1-8
%else
BuildRequires:    jss >= 4.4.4-3
BuildRequires:    tomcatjss >= 7.2.4-4
%endif
BuildRequires:    systemd-units

%if 0%{?with_python3}
BuildRequires:    python3-cryptography
BuildRequires:    python3-devel
BuildRequires:    python3-lxml
BuildRequires:    python3-nss
BuildRequires:    python3-pyldap
BuildRequires:    python3-requests >= 2.6.0
BuildRequires:    python3-six
%endif  # with_python3
BuildRequires:    python-devel

# additional build requirements needed to build native 'tpsclient'
# REMINDER:  Revisit these once 'tpsclient' is rewritten as a Java app
BuildRequires:    apr-devel
BuildRequires:    apr-util-devel
BuildRequires:    cyrus-sasl-devel
BuildRequires:    httpd-devel >= 2.4.2
BuildRequires:    pcre-devel
BuildRequires:    python
BuildRequires:    systemd
BuildRequires:    zlib
BuildRequires:    zlib-devel

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
  * pki-base-python2 (alias for pki-base)                              \
  * pki-base-python3                                                   \
  * pki-base-java                                                      \
  * pki-tools                                                          \
  * pki-server                                                         \
  * pki-ca                                                             \
  * pki-kra                                                            \
  * pki-ocsp                                                           \
  * pki-tks                                                            \
  * pki-tps                                                            \
  * pki-javadoc                                                        \
                                                                       \
which comprise the following corresponding PKI subsystems:             \
                                                                       \
  * Certificate Authority (CA)                                         \
  * Key Recovery Authority (KRA)                                        \
  * Online Certificate Status Protocol (OCSP) Manager                  \
  * Token Key Service (TKS)                                            \
  * Token Processing Service (TPS)                                     \
                                                                       \
Python clients need only install the pki-base package.  This           \
package contains the python REST client packages and the client        \
upgrade framework.                                                     \
                                                                       \
Java clients should install the pki-base-java package.  This package   \
contains the legacy and REST Java client packages.  These clients      \
should also consider installing the pki-tools package, which contain   \
native and Java-based PKI tools and utilities.                         \
                                                                       \
Certificate Server instances require the fundamental classes and       \
modules in pki-base and pki-base-java, as well as the utilities in     \
pki-tools.  The main server classes are in pki-server, with subsystem  \
specific Java classes and resources in pki-ca, pki-kra, pki-ocsp etc.  \
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

################################################################################
%package -n       pki-symkey
################################################################################

Summary:          Symmetric Key JNI Package

Requires:         java-1.8.0-openjdk-headless
Requires:         jpackage-utils >= 0:1.7.5-10
%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:         jss >= 4.4.4-5
%else
Requires:         jss >= 4.4.4-3
%endif
Requires:         nss >= 3.28.3

Provides:         symkey = %{version}-%{release}

Obsoletes:        symkey < %{version}-%{release}

%if 0%{?rhel} && 0%{?rhel} <= 7
## Because RHCS 9.0 does not run on RHEL 7.3+, obsolete all
## RHCS 9.0 packages that can be replaced by RHCS 9.1 packages:
# pki-console
Obsoletes:        pki-console < 10.3.0
# pki-core
Obsoletes:        pki-core-debug = 10.2.6
Obsoletes:        pki-ocsp < 10.3.0
Obsoletes:        pki-tks < 10.3.0
Obsoletes:        pki-tps < 10.3.0
# redhat-pki
Obsoletes:        redhat-pki < 10.3.0
# redhat-pki-theme
Obsoletes:        redhat-pki-console-theme < 10.3.0
Obsoletes:        redhat-pki-server-theme < 10.3.0
%endif

%description -n   pki-symkey
The Symmetric Key Java Native Interface (JNI) package supplies various native
symmetric key operations to Java programs.

This package is a part of the PKI Core used by the Certificate System.

%{overview}

################################################################################
%package -n       pki-base
################################################################################

Summary:          Certificate System - PKI Framework
BuildArch:        noarch

Provides:         pki-common = %{version}-%{release}
Provides:         pki-util = %{version}-%{release}
Provides:         pki-base-python2 = %{version}-%{release}

Obsoletes:        pki-common < %{version}-%{release}
Obsoletes:        pki-util < %{version}-%{release}

Conflicts:        freeipa-server < 3.0.0

Requires:         nss >= 3.28.3
Requires:         python2-cryptography
Requires:         python-nss
Requires:         python-requests >= 2.6.0
Requires:         python-six

%description -n   pki-base
The PKI Framework contains the common and client libraries and utilities
written in Python.  This package is a part of the PKI Core used by the
Certificate System.

%{overview}

################################################################################
%package -n       pki-base-java
################################################################################

Summary:          Certificate System - Java Framework
BuildArch:        noarch

Requires:         java-1.8.0-openjdk-headless
Requires:         apache-commons-cli
Requires:         apache-commons-codec
Requires:         apache-commons-io
Requires:         apache-commons-lang
Requires:         apache-commons-logging
Requires:         jakarta-commons-httpclient
Requires:         slf4j
%if 0%{?rhel} && 0%{?rhel} <= 7
# no slf4j-jdk14
%else
Requires:         slf4j-jdk14
%endif
Requires:         javassist
Requires:         jpackage-utils >= 0:1.7.5-10
%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:         jss >= 4.4.4-5
%else
Requires:         jss >= 4.4.4-3
%endif
Requires:         ldapjdk >= 4.19-5
Requires:         pki-base = %{version}-%{release}

%if 0%{?rhel} && 0%{?rhel} <= 7
# 'resteasy-base' is a subset of the complete set of
# 'resteasy' packages and consists of what is needed to
# support the PKI Restful interface on certain RHEL platforms
Requires:         resteasy-base-atom-provider >= 3.0.6-1
Requires:         resteasy-base-client >= 3.0.6-1
Requires:         resteasy-base-jaxb-provider >= 3.0.6-1
Requires:         resteasy-base-jaxrs >= 3.0.6-1
Requires:         resteasy-base-jaxrs-api >= 3.0.6-1
Requires:         resteasy-base-jackson-provider >= 3.0.6-1
%else
Requires:         resteasy-atom-provider >= 3.0.17-1
Requires:         resteasy-client >= 3.0.17-1
Requires:         resteasy-jaxb-provider >= 3.0.17-1
Requires:         resteasy-core >= 3.0.17-1
Requires:         resteasy-jackson-provider >= 3.0.17-1
%endif

Requires:         xalan-j2
Requires:         xerces-j2
Requires:         xml-commons-apis
Requires:         xml-commons-resolver

%description -n   pki-base-java
The PKI Framework contains the common and client libraries and utilities
written in Java.  This package is a part of the PKI Core used by the
Certificate System.

This package is a part of the PKI Core used by the Certificate System.

%{overview}

%if 0%{?with_python3}
################################################################################
%package -n       pki-base-python3
################################################################################

Summary:          Certificate System - PKI Framework
BuildArch:        noarch

Requires:         pki-base = %{version}-%{release}

Requires:         python3-cryptography
Requires:         python3-lxml
Requires:         python3-nss
Requires:         python3-requests >= 2.6.0
Requires:         python3-six

%description -n   pki-base-python3
This package contains PKI client library for Python 3.

This package is a part of the PKI Core used by the Certificate System.

%{overview}

%endif  # with_python3 for python3-pki

################################################################################
%package -n       pki-tools
################################################################################

Summary:          Certificate System - PKI Tools

Provides:         pki-native-tools = %{version}-%{release}
Provides:         pki-java-tools = %{version}-%{release}

Obsoletes:        pki-native-tools < %{version}-%{release}
Obsoletes:        pki-java-tools < %{version}-%{release}

Requires:         openldap-clients
Requires:         nss-tools >= 3.28.3
Requires:         java-1.8.0-openjdk-headless
Requires:         pki-base = %{version}-%{release}
Requires:         pki-base-java = %{version}-%{release}
Requires:         jpackage-utils >= 0:1.7.5-10
%if 0%{?fedora} || 0%{?rhel} > 7
Requires:         tomcat-servlet-3.1-api
%endif

%description -n   pki-tools
This package contains PKI executables that can be used to help make
Certificate System into a more complete and robust PKI solution.

This package is a part of the PKI Core used by the Certificate System.

%{overview}

%if %{with server}
################################################################################
%package -n       pki-server
################################################################################

Summary:          Certificate System - PKI Server Framework
BuildArch:        noarch

Provides:         pki-deploy = %{version}-%{release}
Provides:         pki-setup = %{version}-%{release}
Provides:         pki-silent = %{version}-%{release}

Obsoletes:        pki-deploy < %{version}-%{release}
Obsoletes:        pki-setup < %{version}-%{release}
Obsoletes:        pki-silent < %{version}-%{release}

Requires:         java-1.8.0-openjdk-headless
Requires:         hostname
Requires:         net-tools

%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:    nuxwdog-client-java >= 1.0.3-8
%else
Requires:    nuxwdog-client-java >= 1.0.3-14
%endif

Requires:         policycoreutils
Requires:         procps-ng
Requires:         openldap-clients
%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:         openssl >= 1.0.2k-11
%else
Requires:         openssl
%endif
Requires:         pki-base = %{version}-%{release}
Requires:         pki-base-java = %{version}-%{release}
Requires:         pki-tools = %{version}-%{release}
Requires:         python-ldap
Requires:         python-lxml
Requires:         libselinux-python
Requires:         policycoreutils-python
%if 0%{?fedora} || 0%{?rhel} > 7
Requires:         policycoreutils-python-utils
%endif

Requires:         selinux-policy-targeted >= 3.13.1-159
Obsoletes:        pki-selinux

%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:         tomcat >= 7.0.69
%else
Requires:         tomcat >= 7.0.68
Requires:         tomcat-el-3.0-api
Requires:         tomcat-jsp-2.3-api
Requires:         tomcat-servlet-3.1-api
%endif

Requires:         velocity
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units
Requires(pre):    shadow-utils
%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:         tomcatjss >= 7.2.1-8
%else
Requires:         tomcatjss >= 7.2.4-4
%endif

%if 0%{?rhel} && 0%{?rhel} <= 7
## Because RHCS 9.0 does not run on RHEL 7.3+, obsolete all
## RHCS 9.0 packages that can be replaced by RHCS 9.1 packages:
# pki-console
Obsoletes:        pki-console < 10.3.0
# pki-core
Obsoletes:        pki-core-debug = 10.2.6
Obsoletes:        pki-ocsp < 10.3.0
Obsoletes:        pki-tks < 10.3.0
Obsoletes:        pki-tps < 10.3.0
# redhat-pki
Obsoletes:        redhat-pki < 10.3.0
# redhat-pki-theme
Obsoletes:        redhat-pki-console-theme < 10.3.0
Obsoletes:        redhat-pki-server-theme < 10.3.0
%endif

%description -n   pki-server
The PKI Server Framework is required by the following four PKI subsystems:

    the Certificate Authority (CA),
    the Key Recovery Authority (KRA),
    the Online Certificate Status Protocol (OCSP) Manager,
    the Token Key Service (TKS), and
    the Token Processing Service (TPS).

This package is a part of the PKI Core used by the Certificate System.
The package contains scripts to create and remove PKI subsystems.

%{overview}

################################################################################
%package -n       pki-ca
################################################################################

Summary:          Certificate System - Certificate Authority
BuildArch:        noarch

Requires:         java-1.8.0-openjdk-headless
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

################################################################################
%package -n       pki-kra
################################################################################

Summary:          Certificate System - Key Recovery Authority
BuildArch:        noarch

Requires:         java-1.8.0-openjdk-headless
Requires:         pki-server = %{version}-%{release}
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units

%description -n   pki-kra
The Key Recovery Authority (KRA) is an optional PKI subsystem that can act
as a key archival facility.  When configured in conjunction with the
Certificate Authority (CA), the KRA stores private encryption keys as part of
the certificate enrollment process.  The key archival mechanism is triggered
when a user enrolls in the PKI and creates the certificate request.  Using the
Certificate Request Message Format (CRMF) request format, a request is
generated for the user's private encryption key.  This key is then stored in
the KRA which is configured to store keys in an encrypted format that can only
be decrypted by several agents requesting the key at one time, providing for
protection of the public encryption keys for the users in the PKI deployment.

Note that the KRA archives encryption keys; it does NOT archive signing keys,
since such archival would undermine non-repudiation properties of signing keys.

This package is one of the top-level java-based Tomcat PKI subsystems
provided by the PKI Core used by the Certificate System.

%{overview}

################################################################################
%package -n       pki-ocsp
################################################################################

Summary:          Certificate System - Online Certificate Status Protocol Manager
BuildArch:        noarch

Requires:         java-1.8.0-openjdk-headless
%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
Requires:         pki-server = %{version}-%{release}
%else
Requires:         pki-server >= %{pki_core_rhel_version}
%endif
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

################################################################################
%package -n       pki-tks
################################################################################

Summary:          Certificate System - Token Key Service
BuildArch:        noarch

Requires:         java-1.8.0-openjdk-headless
%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
Requires:         pki-server = %{version}-%{release}
Requires:         pki-symkey = %{version}-%{release}
%else
Requires:         pki-server >= %{pki_core_rhel_version}
Requires:         pki-symkey >= %{pki_core_rhel_version}
%endif
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

################################################################################
%package -n       pki-tps
################################################################################

Summary:          Certificate System - Token Processing Service

Provides:         pki-tps-tomcat
Provides:         pki-tps-client

Obsoletes:        pki-tps-tomcat
Obsoletes:        pki-tps-client

Requires:         java-1.8.0-openjdk-headless
%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
Requires:         pki-server = %{version}-%{release}
%else
Requires:         pki-server >= %{pki_core_rhel_version}
%endif
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units

# additional runtime requirements needed to run native 'tpsclient'
# REMINDER:  Revisit these once 'tpsclient' is rewritten as a Java app

Requires:         nss-tools >= 3.28.3
Requires:         openldap-clients
%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
Requires:         pki-symkey = %{version}-%{release}
%else
Requires:         pki-symkey >= %{pki_core_rhel_version}
%endif

%description -n   pki-tps
The Token Processing System (TPS) is an optional PKI subsystem that acts
as a Registration Authority (RA) for authenticating and processing
enrollment requests, PIN reset requests, and formatting requests from
the Enterprise Security Client (ESC).

TPS is designed to communicate with tokens that conform to
Global Platform's Open Platform Specification.

TPS communicates over SSL with various PKI backend subsystems (including
the Certificate Authority (CA), the Key Recovery Authority (KRA), and the
Token Key Service (TKS)) to fulfill the user's requests.

TPS also interacts with the token database, an LDAP server that stores
information about individual tokens.

The utility "tpsclient" is a test tool that interacts with TPS.  This
tool is useful to test TPS server configs without risking an actual
smart card.

%{overview}

################################################################################
%package -n       pki-javadoc
################################################################################

Summary:          Certificate System - PKI Framework Javadocs
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

%endif # %{with server}

################################################################################
%package -n       pki-console
################################################################################

Summary:          Certificate System - PKI Console
BuildArch:        noarch

BuildRequires:    idm-console-framework >= 1.1.17-4

Requires:         idm-console-framework >= 1.1.17-4
Requires:         java-1.8.0-openjdk
Requires:         ldapjdk >= 4.19-5
Requires:         pki-base-java >= %{version}
Requires:         pki-console-theme >= %{version}
Requires:         jpackage-utils >= 1.7.5-10
Requires:         jss >= 4.4.4-3

%description -n   pki-console
Certificate System (CS) is an enterprise software system designed
to manage enterprise Public Key Infrastructure (PKI) deployments.

The PKI Console is a java application used to administer CS.

For deployment purposes, a PKI Console requires ONE AND ONLY ONE of the
following "Mutually-Exclusive" PKI Theme packages:

  * dogtag-pki-console-theme (Dogtag Certificate System deployments)
  * redhat-pki-console-theme (Red Hat Certificate System deployments)

################################################################################
%prep
################################################################################

%autosetup -n %{name}-%{version}%{?prerel} -p 1 -S git
# With "autosetup" it's not necessary to specify the "patchX" macros.
# See http://rpm.org/user_doc/autosetup.html.

################################################################################
%build
################################################################################

%{__mkdir_p} build
cd build
%cmake \
    --no-warn-unused-cli \
    -DVERSION=%{version}-%{release} \
    -DVAR_INSTALL_DIR:PATH=/var \
    -DBUILD_PKI_CORE:BOOL=ON \
    -DBUILD_PKI_CONSOLE:BOOL=ON \
    -DJAVA_HOME=%{java_home} \
    -DJAVA_LIB_INSTALL_DIR=%{_jnidir} \
    -DSYSTEMD_LIB_INSTALL_DIR=%{_unitdir} \
%if %{version_phase}
    -DAPPLICATION_VERSION_PHASE="%{version_phase}" \
%endif
%if ! %{with_tomcat7}
    -DWITH_TOMCAT7:BOOL=OFF \
%endif
%if ! %{with_tomcat8}
    -DWITH_TOMCAT8:BOOL=OFF \
%endif
    -DJAXRS_API_JAR=%{jaxrs_api_jar} \
    -DRESTEASY_LIB=%{resteasy_lib} \
%if ! %{with server}
    -DWITH_SERVER:BOOL=OFF \
%endif
%if ! %{with server}
    -DWITH_SERVER:BOOL=OFF \
%endif
%if ! %{with javadoc}
    -DWITH_JAVADOC:BOOL=OFF \
%endif
    ..

################################################################################
%install
################################################################################

cd build

# Do not use _smp_mflags to preserve build order
%{__make} \
    VERBOSE=%{?_verbose} \
    CMAKE_NO_VERBOSE=1 \
    DESTDIR=%{buildroot} \
    INSTALL="install -p" \
    --no-print-directory \
     all unit-test install

# Create symlinks for admin console (TPS does not use admin console)
for subsystem in ca kra ocsp tks; do
    %{__mkdir_p} %{buildroot}%{_datadir}/pki/$subsystem/webapps/$subsystem/admin
    ln -s %{_datadir}/pki/server/webapps/pki/admin/console %{buildroot}%{_datadir}/pki/$subsystem/webapps/$subsystem/admin
done

# Create compatibility symlink for DRMTool -> KRATool
ln -s %{_bindir}/KRATool %{buildroot}%{_bindir}/DRMTool
# Create compatibility symlink for DRMTool.cfg -> KRATool.cfg
ln -s %{_datadir}/pki/java-tools/KRATool.cfg %{buildroot}%{_datadir}/pki/java-tools/DRMTool.cfg
# Create compatibility symlink for DRMTool.1.gz -> KRATool.1.gz
ln -s %{_mandir}/man1/KRATool.1.gz %{buildroot}%{_mandir}/man1/DRMTool.1.gz

# Customize client library links in /usr/share/pki/lib
%if 0%{?fedora} || 0%{?rhel} > 7
    rm -f %{buildroot}%{_datadir}/pki/lib/scannotation.jar
    rm -f %{buildroot}%{_datadir}/pki/lib/resteasy-jaxrs-api.jar
    rm -f %{buildroot}%{_datadir}/pki/lib/resteasy-jaxrs-jandex.jar
    ln -sf %{jaxrs_api_jar} %{buildroot}%{_datadir}/pki/lib/jboss-jaxrs-2.0-api.jar
    ln -sf /usr/share/java/jboss-logging/jboss-logging.jar %{buildroot}%{_datadir}/pki/lib/jboss-logging.jar
    ln -sf /usr/share/java/jboss-annotations-1.2-api/jboss-annotations-api_1.2_spec.jar %{buildroot}%{_datadir}/pki/lib/jboss-annotations-api_1.2_spec.jar
%else

if [ -f /etc/debian_version ]; then
    ln -sf /usr/share/java/httpclient.jar %{buildroot}%{_datadir}/pki/lib/httpclient.jar
    ln -sf /usr/share/java/httpcore.jar %{buildroot}%{_datadir}/pki/lib/httpcore.jar
    ln -sf /usr/share/java/jackson-core-asl.jar %{buildroot}%{_datadir}/pki/lib/jackson-core-asl.jar
    ln -sf /usr/share/java/jackson-jaxrs.jar %{buildroot}%{_datadir}/pki/lib/jackson-jaxrs.jar
    ln -sf /usr/share/java/jackson-mapper-asl.jar %{buildroot}%{_datadir}/pki/lib/jackson-mapper-asl.jar
    ln -sf /usr/share/java/jackson-mrbean.jar %{buildroot}%{_datadir}/pki/lib/jackson-mrbean.jar
    ln -sf /usr/share/java/jackson-smile.jar %{buildroot}%{_datadir}/pki/lib/jackson-smile.jar
    ln -sf /usr/share/java/jackson-xc.jar %{buildroot}%{_datadir}/pki/lib/jackson-xc.jar
    ln -sf /usr/share/java/jss4.jar %{buildroot}%{_datadir}/pki/lib/jss4.jar
fi

%endif

%if %{with server}

# Customize server upgrade scripts in /usr/share/pki/server/upgrade
%if 0%{?rhel} && 0%{?rhel} <= 7

# merge newer upgrade scripts into 10.3.3 for RHEL
mv %{buildroot}%{_datadir}/pki/server/upgrade/10.3.5/01-FixServerLibrary \
   %{buildroot}%{_datadir}/pki/server/upgrade/10.3.3/02-FixServerLibrary
mv %{buildroot}%{_datadir}/pki/server/upgrade/10.3.5/02-FixDeploymentDescriptor \
   %{buildroot}%{_datadir}/pki/server/upgrade/10.3.3/03-FixDeploymentDescriptor
/bin/rm -rf %{buildroot}%{_datadir}/pki/server/upgrade/10.3.5

# merge newer upgrade scripts into 10.4.1 for RHEL
%{__mkdir_p} %{buildroot}%{_datadir}/pki/server/upgrade/10.4.1
mv %{buildroot}%{_datadir}/pki/server/upgrade/10.4.2/01-AddSessionAuthenticationPlugin \
   %{buildroot}%{_datadir}/pki/server/upgrade/10.4.1/01-AddSessionAuthenticationPlugin
mv %{buildroot}%{_datadir}/pki/server/upgrade/10.4.2/02-AddKRAWrappingParams \
   %{buildroot}%{_datadir}/pki/server/upgrade/10.4.1/02-AddKRAWrappingParams
mv %{buildroot}%{_datadir}/pki/server/upgrade/10.4.6/01-UpdateKeepAliveTimeout \
   %{buildroot}%{_datadir}/pki/server/upgrade/10.4.1/03-UpdateKeepAliveTimeout
/bin/rm -rf %{buildroot}%{_datadir}/pki/server/upgrade/10.4.2
/bin/rm -rf %{buildroot}%{_datadir}/pki/server/upgrade/10.4.6

# merge newer upgrade scripts into 10.5.1 for RHEL 7.5
%{__mkdir_p} %{buildroot}%{_datadir}/pki/server/upgrade/10.5.1
mv %{buildroot}%{_datadir}/pki/server/upgrade/10.5.5/01-AddTPSExternalRegISEtokenParams \
   %{buildroot}%{_datadir}/pki/server/upgrade/10.5.1/01-AddTPSExternalRegISEtokenParams
/bin/rm -rf %{buildroot}%{_datadir}/pki/server/upgrade/10.5.5

# merge newer upgrade scripts into 10.5.9 for RHEL 7.6
%{__mkdir_p} %{buildroot}%{_datadir}/pki/server/upgrade/10.5.9
mv %{buildroot}%{_datadir}/pki/server/upgrade/10.5.14/01-UpdateAuditEvents \
   %{buildroot}%{_datadir}/pki/server/upgrade/10.5.9/01-UpdateAuditEvents
/bin/rm -rf %{buildroot}%{_datadir}/pki/server/upgrade/10.5.14

%endif

# Customize server library links in /usr/share/pki/server/common/lib
%if 0%{?fedora} || 0%{?rhel} > 7
    rm -f %{buildroot}%{_datadir}/pki/server/common/lib/scannotation.jar
    rm -f %{buildroot}%{_datadir}/pki/server/common/lib/resteasy-jaxrs-api.jar
    ln -sf %{jaxrs_api_jar} %{buildroot}%{_datadir}/pki/server/common/lib/jboss-jaxrs-2.0-api.jar
    ln -sf /usr/share/java/jboss-logging/jboss-logging.jar %{buildroot}%{_datadir}/pki/server/common/lib/jboss-logging.jar
    ln -sf /usr/share/java/jboss-annotations-1.2-api/jboss-annotations-api_1.2_spec.jar %{buildroot}%{_datadir}/pki/server/common/lib/jboss-annotations-api_1.2_spec.jar

%else

if [ -f /etc/debian_version ]; then
    ln -sf /usr/share/java/commons-collections3.jar %{buildroot}%{_datadir}/pki/server/common/lib/commons-collections.jar
    ln -sf /usr/share/java/httpclient.jar %{buildroot}%{_datadir}/pki/server/common/lib/httpclient.jar
    ln -sf /usr/share/java/httpcore.jar %{buildroot}%{_datadir}/pki/server/common/lib/httpcore.jar
    ln -sf /usr/share/java/jackson-core-asl.jar %{buildroot}%{_datadir}/pki/server/common/lib/jackson-core-asl.jar
    ln -sf /usr/share/java/jackson-jaxrs.jar %{buildroot}%{_datadir}/pki/server/common/lib/jackson-jaxrs.jar
    ln -sf /usr/share/java/jackson-mapper-asl.jar %{buildroot}%{_datadir}/pki/server/common/lib/jackson-mapper-asl.jar
    ln -sf /usr/share/java/jackson-mrbean.jar %{buildroot}%{_datadir}/pki/server/common/lib/jackson-mrbean.jar
    ln -sf /usr/share/java/jackson-smile.jar %{buildroot}%{_datadir}/pki/server/common/lib/jackson-smile.jar
    ln -sf /usr/share/java/jackson-xc.jar %{buildroot}%{_datadir}/pki/server/common/lib/jackson-xc.jar
    ln -sf /usr/share/java/jss4.jar %{buildroot}%{_datadir}/pki/server/common/lib/jss4.jar
    ln -sf /usr/share/java/symkey.jar %{buildroot}%{_datadir}/pki/server/common/lib/symkey.jar
    ln -sf /usr/share/java/xercesImpl.jar %{buildroot}%{_datadir}/pki/server/common/lib/xerces-j2.jar
    ln -sf /usr/share/java/xml-apis.jar %{buildroot}%{_datadir}/pki/server/common/lib/xml-commons-apis.jar
    ln -sf /usr/share/java/xml-resolver.jar %{buildroot}%{_datadir}/pki/server/common/lib/xml-commons-resolver.jar
fi

%endif

%if 0%{?rhel}
# no pylint
%else

################################################################################
echo "Scanning Python code with pylint"
################################################################################

%{__python2} ../pylint-build-scan.py rpm --prefix %{buildroot}
if [ $? -ne 0 ]; then
    echo "pylint failed. RC: $?"
    exit 1
fi

%{__python2} ../pylint-build-scan.py rpm --prefix %{buildroot} -- --py3k
if [ $? -ne 0 ]; then
    echo "pylint --py3k failed. RC: $?"
    exit 1
fi

################################################################################
echo "Scanning Python code with flake8"
################################################################################

flake8 --config ../tox.ini %{buildroot}
if [ $? -ne 0 ]; then
    echo "flake8 for Python 2 failed. RC: $?"
    exit 1
fi

python3-flake8 --config ../tox.ini %{buildroot}
if [ $? -ne 0 ]; then
    echo "flake8 for Python 3 failed. RC: $?"
    exit 1
fi

%endif

%{__rm} -rf %{buildroot}%{_datadir}/pki/server/lib

%endif # %{with server}

%{__mkdir_p} %{buildroot}%{_localstatedir}/log/pki
%{__mkdir_p} %{buildroot}%{_sharedstatedir}/pki

%if 0%{?fedora} || 0%{?rhel} > 7
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
   msg = "Unable to upgrade to Fedora 20.  There are PKI 9 instances\n" ..
         "that will no longer work since they require Tomcat 6, and \n" ..
         "Tomcat 6 is no longer available in Fedora 20.\n\n" ..
         "Please follow these instructions to migrate the instances to \n" ..
         "PKI 10:\n\n" ..
         "https://www.dogtagpki.org/wiki/Migrating_PKI_9_Instances_to_PKI_10"
   error(msg)
end
%endif

%if %{with server}

%pre -n pki-server
getent group %{pki_groupname} >/dev/null || groupadd -f -g %{pki_gid} -r %{pki_groupname}
if ! getent passwd %{pki_username} >/dev/null ; then
    if ! getent passwd %{pki_uid} >/dev/null ; then
      useradd -r -u %{pki_uid} -g %{pki_groupname} -d %{pki_homedir} -s /sbin/nologin -c "Certificate System" %{pki_username}
    else
      useradd -r -g %{pki_groupname} -d %{pki_homedir} -s /sbin/nologin -c "Certificate System" %{pki_username}
    fi
fi
exit 0

%endif # %{with server}

%post -n pki-base

if [ $1 -eq 1 ]
then
    # On RPM installation create system upgrade tracker
    echo "Configuration-Version: %{version}" > %{_sysconfdir}/pki/pki.version

else
    # On RPM upgrade run system upgrade
    echo "Upgrading PKI system configuration at `/bin/date`." >> /var/log/pki/pki-upgrade-%{version}.log 2>&1
    /sbin/pki-upgrade --silent >> /var/log/pki/pki-upgrade-%{version}.log 2>&1
    echo >> /var/log/pki/pki-upgrade-%{version}.log 2>&1
fi

%postun -n pki-base

if [ $1 -eq 0 ]
then
    # On RPM uninstallation remove system upgrade tracker
    rm -f %{_sysconfdir}/pki/pki.version
fi

%if %{with server}

%post -n pki-server
## NOTE:  At this time, NO attempt has been made to update ANY PKI subsystem
##        from EITHER 'sysVinit' OR previous 'systemd' processes to the new
##        PKI deployment process

echo "Upgrading PKI server configuration at `/bin/date`." >> /var/log/pki/pki-server-upgrade-%{version}.log 2>&1
/sbin/pki-server-upgrade --silent >> /var/log/pki/pki-server-upgrade-%{version}.log 2>&1
echo >> /var/log/pki/pki-server-upgrade-%{version}.log 2>&1

# Migrate Tomcat configuration
/sbin/pki-server migrate >> /var/log/pki/pki-server-upgrade-%{version}.log 2>&1
echo >> /var/log/pki/pki-server-upgrade-%{version}.log 2>&1

# Reload systemd daemons on upgrade only
if [ "$1" == "2" ]
then
    systemctl daemon-reload
fi

## %preun -n pki-server
## NOTE:  At this time, NO attempt has been made to update ANY PKI subsystem
##        from EITHER 'sysVinit' OR previous 'systemd' processes to the new
##        PKI deployment process


## %postun -n pki-server
## NOTE:  At this time, NO attempt has been made to update ANY PKI subsystem
##        from EITHER 'sysVinit' OR previous 'systemd' processes to the new
##        PKI deployment process

%endif # %{with server}

%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
################################################################################
%files -n pki-symkey
################################################################################

%doc base/symkey/LICENSE
%{_jnidir}/symkey.jar
%{_libdir}/symkey/
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
################################################################################
%files -n pki-base
################################################################################

%doc base/common/LICENSE
%doc base/common/LICENSE.LESSER
%doc %{_datadir}/doc/pki-base/html
%dir %{_datadir}/pki
%{_datadir}/pki/VERSION
%{_datadir}/pki/etc/
%{_datadir}/pki/upgrade/
%{_datadir}/pki/key/templates
%dir %{_sysconfdir}/pki
%config(noreplace) %{_sysconfdir}/pki/pki.conf
%exclude %{python2_sitelib}/pki/server
%{python2_sitelib}/pki
%dir %{_localstatedir}/log/pki
%{_sbindir}/pki-upgrade
%{_mandir}/man1/pki-python-client.1.gz
%{_mandir}/man5/pki-logging.5.gz
%{_mandir}/man8/pki-upgrade.8.gz
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
################################################################################
%files -n pki-base-java
################################################################################

%{_datadir}/pki/examples/java/
%{_datadir}/pki/lib/
%dir %{_javadir}/pki
%{_javadir}/pki/pki-cmsutil.jar
%{_javadir}/pki/pki-nsutil.jar
%{_javadir}/pki/pki-certsrv.jar
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
%if %{with_python3}
################################################################################
%files -n pki-base-python3
################################################################################

%doc base/common/LICENSE
%doc base/common/LICENSE.LESSER
%exclude %{python3_sitelib}/pki/server
%{python3_sitelib}/pki
%endif # with_python3
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
################################################################################
%files -n pki-tools
################################################################################

%doc base/native-tools/LICENSE base/native-tools/doc/README
%{_bindir}/p7tool
%{_bindir}/pistool
%{_bindir}/pki
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
%{_bindir}/CMCRequestLegacy
%{_bindir}/CMCResponse
%{_bindir}/CMCRevoke
%{_bindir}/CMCSharedToken
%{_bindir}/CRMFPopClient
%{_bindir}/DRMTool
%{_bindir}/ExtJoiner
%{_bindir}/GenExtKeyUsage
%{_bindir}/GenIssuerAltNameExt
%{_bindir}/GenSubjectAltNameExt
%{_bindir}/HttpClient
%{_bindir}/KRATool
%{_bindir}/OCSPClient
%{_bindir}/PKCS10Client
%{_bindir}/PKCS12Export
%{_bindir}/PKICertImport
%{_bindir}/PrettyPrintCert
%{_bindir}/PrettyPrintCrl
%{_bindir}/TokenInfo
%{_javadir}/pki/pki-tools.jar
%{_datadir}/pki/java-tools/
%{_mandir}/man1/AtoB.1.gz
%{_mandir}/man1/AuditVerify.1.gz
%{_mandir}/man1/BtoA.1.gz
%{_mandir}/man1/CMCEnroll.1.gz
%{_mandir}/man1/CMCRequest.1.gz
%{_mandir}/man1/CMCResponse.1.gz
%{_mandir}/man1/CMCSharedToken.1.gz
%{_mandir}/man1/DRMTool.1.gz
%{_mandir}/man1/KRATool.1.gz
%{_mandir}/man1/PrettyPrintCert.1.gz
%{_mandir}/man1/PrettyPrintCrl.1.gz
%{_mandir}/man1/pki.1.gz
%{_mandir}/man1/pki-audit.1.gz
%{_mandir}/man1/pki-ca-kraconnector.1.gz
%{_mandir}/man1/pki-ca-profile.1.gz
%{_mandir}/man1/pki-cert.1.gz
%{_mandir}/man1/pki-client.1.gz
%{_mandir}/man1/pki-group.1.gz
%{_mandir}/man1/pki-group-member.1.gz
%{_mandir}/man1/pki-key.1.gz
%{_mandir}/man1/pki-pkcs12-cert.1.gz
%{_mandir}/man1/pki-pkcs12-key.1.gz
%{_mandir}/man1/pki-pkcs12.1.gz
%{_mandir}/man1/pki-securitydomain.1.gz
%{_mandir}/man1/pki-tps-profile.1.gz
%{_mandir}/man1/pki-user.1.gz
%{_mandir}/man1/pki-user-cert.1.gz
%{_mandir}/man1/pki-user-membership.1.gz
%{_mandir}/man1/PKCS10Client.1.gz
%{_mandir}/man1/PKICertImport.1.gz
%endif

%if %{with server}
%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
################################################################################
%files -n pki-server
################################################################################

%doc base/common/THIRD_PARTY_LICENSES
%doc base/server/LICENSE
%doc base/server/README
%{_sysconfdir}/pki/default.cfg
%attr(755,-,-) %dir %{_sysconfdir}/sysconfig/pki
%attr(755,-,-) %dir %{_sysconfdir}/sysconfig/pki/tomcat
%{_sbindir}/pkispawn
%{_sbindir}/pkidestroy
%{_sbindir}/pki-server
%{_sbindir}/pki-server-nuxwdog
%{_sbindir}/pki-server-upgrade
%{python2_sitelib}/pki/server/
%dir %{_datadir}/pki/deployment
%{_datadir}/pki/deployment/config/
%dir %{_datadir}/pki/scripts
%{_datadir}/pki/scripts/operations
%{_bindir}/pkidaemon
%dir %{_sysconfdir}/systemd/system/pki-tomcatd.target.wants
%attr(644,-,-) %{_unitdir}/pki-tomcatd@.service
%attr(644,-,-) %{_unitdir}/pki-tomcatd.target
%dir %{_sysconfdir}/systemd/system/pki-tomcatd-nuxwdog.target.wants
%attr(644,-,-) %{_unitdir}/pki-tomcatd-nuxwdog@.service
%attr(644,-,-) %{_unitdir}/pki-tomcatd-nuxwdog.target
%{_javadir}/pki/pki-cms.jar
%{_javadir}/pki/pki-cmsbundle.jar
%{_javadir}/pki/pki-cmscore.jar
%{_javadir}/pki/pki-tomcat.jar
%dir %{_sharedstatedir}/pki
%{_mandir}/man1/pkidaemon.1.gz
%{_mandir}/man5/pki_default.cfg.5.gz
%{_mandir}/man5/pki-server-logging.5.gz
%{_mandir}/man8/pki-server-upgrade.8.gz
%{_mandir}/man8/pkidestroy.8.gz
%{_mandir}/man8/pkispawn.8.gz
%{_mandir}/man8/pki-server.8.gz
%{_mandir}/man8/pki-server-instance.8.gz
%{_mandir}/man8/pki-server-subsystem.8.gz
%{_mandir}/man8/pki-server-nuxwdog.8.gz
%{_mandir}/man8/pki-server-migrate.8.gz
%{_mandir}/man8/pki-server-cert.8.gz

%{_datadir}/pki/setup/
%{_datadir}/pki/server/
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
################################################################################
%files -n pki-ca
################################################################################

%doc base/ca/LICENSE
%{_javadir}/pki/pki-ca.jar
%dir %{_datadir}/pki/ca
%{_datadir}/pki/ca/conf/
%{_datadir}/pki/ca/emails/
%dir %{_datadir}/pki/ca/profiles
%{_datadir}/pki/ca/profiles/ca/
%{_datadir}/pki/ca/setup/
%{_datadir}/pki/ca/webapps/
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
################################################################################
%files -n pki-kra
################################################################################

%doc base/kra/LICENSE
%{_javadir}/pki/pki-kra.jar
%dir %{_datadir}/pki/kra
%{_datadir}/pki/kra/conf/
%{_datadir}/pki/kra/setup/
%{_datadir}/pki/kra/webapps/
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhcs_packages}
################################################################################
%files -n pki-ocsp
################################################################################

%doc base/ocsp/LICENSE
%{_javadir}/pki/pki-ocsp.jar
%dir %{_datadir}/pki/ocsp
%{_datadir}/pki/ocsp/conf/
%{_datadir}/pki/ocsp/setup/
%{_datadir}/pki/ocsp/webapps/
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhcs_packages}
################################################################################
%files -n pki-tks
################################################################################

%doc base/tks/LICENSE
%{_javadir}/pki/pki-tks.jar
%dir %{_datadir}/pki/tks
%{_datadir}/pki/tks/conf/
%{_datadir}/pki/tks/setup/
%{_datadir}/pki/tks/webapps/
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhcs_packages}
################################################################################
%files -n pki-tps
################################################################################

%doc base/tps/LICENSE
%{_javadir}/pki/pki-tps.jar
%dir %{_datadir}/pki/tps
%{_datadir}/pki/tps/applets/
%{_datadir}/pki/tps/conf/
%{_datadir}/pki/tps/setup/
%{_datadir}/pki/tps/webapps/
%{_mandir}/man5/pki-tps-connector.5.gz
%{_mandir}/man5/pki-tps-profile.5.gz
%{_mandir}/man1/tpsclient.1.gz

# files for native 'tpsclient'
# REMINDER:  Remove this comment once 'tpsclient' is rewritten as a Java app

%{_bindir}/tpsclient
%{_libdir}/tps/libtps.so
%{_libdir}/tps/libtokendb.so
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
%if %{with javadoc}
################################################################################
%files -n pki-javadoc
################################################################################

%{_javadocdir}/pki-%{version}/
%endif
%endif

%endif # %{with server}

################################################################################
%files -n pki-console
################################################################################

%doc base/console/LICENSE
%{_bindir}/pkiconsole
%{_javadir}/pki/pki-console.jar

################################################################################
%changelog
* Thu Oct 19 2017 Dogtag PKI Team <pki-devel@redhat.com> 10.5.0-1
- To list changes in <branch> since <tag>:
  $ git log --pretty=oneline --abbrev-commit --no-decorate <tag>..<branch>
