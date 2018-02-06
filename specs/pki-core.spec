# Python, keep every statement on a single line
%{!?__python2: %global __python2 /usr/bin/python2}
%{!?python2_sitelib: %global python2_sitelib %(%{__python2} -c "from distutils.sysconfig import get_python_lib; print(get_python_lib())")}

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
%define pki_core_rhel_version 10.5.1
%else
# 0%{?fedora}
# Fedora always packages all RPMS
%global package_fedora_packages 1
%endif

# Java
%define java_home /usr/lib/jvm/jre-1.8.0-openjdk

# Tomcat
%if 0%{?fedora} || 0%{?rhel} > 7
%define with_tomcat7 0
%define with_tomcat8 1
%else
%define with_tomcat7 1
%define with_tomcat8 0
%endif

# RESTEasy
%if 0%{?rhel} && 0%{?rhel} <= 7
%define jaxrs_api_jar /usr/share/java/resteasy-base/jaxrs-api.jar
%define resteasy_lib /usr/share/java/resteasy-base
%else
%define jaxrs_api_jar /usr/share/java/jboss-jaxrs-2.0-api.jar
%define resteasy_lib /usr/share/java/resteasy
%endif

# Dogtag
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

# Optionally fetch the release from the environment variable 'PKI_RELEASE'
%define use_pki_release %{getenv:USE_PKI_RELEASE}
%if 0%{?use_pki_release}
%define pki_release %{getenv:PKI_RELEASE}
%endif

Name:             pki-core
%if 0%{?rhel}
Version:                10.5.1
%define redhat_release  7
%define redhat_stage    0
%define default_release %{redhat_release}.%{redhat_stage}
#%define default_release %{redhat_release}
%else
Version:                10.5.5
%define fedora_release  1
%define fedora_stage    0
%define default_release %{fedora_release}.%{fedora_stage}
#%define default_release %{fedora_release}
%endif

%if 0%{?use_pki_release}
Release:          %{pki_release}%{?dist}
%else
Release:          %{default_release}%{?dist}
%endif

Summary:          Certificate System - PKI Core Components
URL:              http://pki.fedoraproject.org/
License:          GPLv2
Group:            System Environment/Daemons

BuildRoot:        %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

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
%if 0%{?fedora} || 0%{?rhel} > 7
BuildRequires:    slf4j-jdk14
%endif
BuildRequires:    nspr-devel
BuildRequires:    nss-devel >= 3.28.3

%if 0%{?rhel} && 0%{?rhel} <= 7
BuildRequires:    nuxwdog-client-java >= 1.0.3-7
%else
BuildRequires:    nuxwdog-client-java >= 1.0.3-13
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
BuildRequires:    jss >= 4.4.0-11
BuildRequires:    tomcatjss >= 7.2.1-4
%else
BuildRequires:    jss >= 4.4.2-9
BuildRequires:    tomcatjss >= 7.2.3
%endif
BuildRequires:    systemd-units

%if 0%{?with_python3}
BuildRequires:  python3-cryptography
BuildRequires:  python3-devel
BuildRequires:  python3-lxml
BuildRequires:  python3-nss
BuildRequires:  python3-pyldap
BuildRequires:  python3-requests >= 2.6.0
BuildRequires:  python3-six
%endif  # with_python3
BuildRequires:  python-devel

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

%if 0%{?rhel}
# NOTE:  In the future, as a part of its path, this URL will contain a release
#        directory which consists of the fixed number of the upstream release
#        upon which this tarball was originally based.
Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{version}/%{release}/rhel/%{name}-%{version}%{?prerel}.tar.gz
%else
Source0:          http://pki.fedoraproject.org/pki/sources/%{name}/%{version}/%{release}/%{name}-%{version}%{?prerel}.tar.gz
%endif

# Obtain version phase number (e. g. - used by "alpha", "beta", etc.)
#
#     NOTE:  For "alpha" releases, will be ".a1", ".a2", etc.
#            For "beta" releases, will be ".b1", ".b2", etc.
#
%define version_phase "%(echo `echo %{version} | awk -F. '{ print $4 }'`)"

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


%package -n       pki-symkey
Summary:          Symmetric Key JNI Package
Group:            System Environment/Libraries

Requires:         java-1.8.0-openjdk-headless
Requires:         jpackage-utils >= 0:1.7.5-10
%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:         jss >= 4.4.0-11
%else
Requires:         jss >= 4.4.2-9
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


%package -n       pki-base
Summary:          Certificate System - PKI Framework
Group:            System Environment/Base

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

%package -n       pki-base-java
Summary:          Certificate System - Java Framework
Group:            System Environment/Base
BuildArch:        noarch

Requires:         java-1.8.0-openjdk-headless
Requires:         apache-commons-cli
Requires:         apache-commons-codec
Requires:         apache-commons-io
Requires:         apache-commons-lang
Requires:         apache-commons-logging
Requires:         jakarta-commons-httpclient
Requires:         slf4j
%if 0%{?fedora} || 0%{?rhel} > 7
Requires:         slf4j-jdk14
%endif
Requires:         javassist
Requires:         jpackage-utils >= 0:1.7.5-10
%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:         jss >= 4.4.0-11
%else
Requires:         jss >= 4.4.2-9
%endif
Requires:         ldapjdk >= 4.19-5
Requires:         pki-base = %{version}-%{release}

%if 0%{?rhel} && 0%{?rhel} <= 7
# 'resteasy-base' is a subset of the complete set of
# 'resteasy' packages and consists of what is needed to
# support the PKI Restful interface on certain RHEL platforms
Requires:    resteasy-base-atom-provider >= 3.0.6-1
Requires:    resteasy-base-client >= 3.0.6-1
Requires:    resteasy-base-jaxb-provider >= 3.0.6-1
Requires:    resteasy-base-jaxrs >= 3.0.6-1
Requires:    resteasy-base-jaxrs-api >= 3.0.6-1
Requires:    resteasy-base-jackson-provider >= 3.0.6-1
%else
Requires:    resteasy-atom-provider >= 3.0.17-1
Requires:    resteasy-client >= 3.0.17-1
Requires:    resteasy-jaxb-provider >= 3.0.17-1
Requires:    resteasy-core >= 3.0.17-1
Requires:    resteasy-jackson-provider >= 3.0.17-1
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

%package -n       pki-base-python3
Summary:          Certificate System - PKI Framework
Group:            System Environment/Base

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

%package -n       pki-tools
Summary:          Certificate System - PKI Tools
Group:            System Environment/Base

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

Requires:         java-1.8.0-openjdk-headless
Requires:         hostname
Requires:         net-tools

%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:    nuxwdog-client-java >= 1.0.3-7
%else
Requires:    nuxwdog-client-java >= 1.0.3-13
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
Requires:         tomcatjss >= 7.2.1-4
%else
Requires:         tomcatjss >= 7.2.3
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

%package -n       pki-ca
Summary:          Certificate System - Certificate Authority
Group:            System Environment/Daemons

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


%package -n       pki-kra
Summary:          Certificate System - Key Recovery Authority
Group:            System Environment/Daemons

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


%package -n       pki-ocsp
Summary:          Certificate System - Online Certificate Status Protocol Manager
Group:            System Environment/Daemons

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


%package -n       pki-tks
Summary:          Certificate System - Token Key Service
Group:            System Environment/Daemons

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


%package -n       pki-tps
Summary:          Certificate System - Token Processing Service
Group:            System Environment/Daemons

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

%endif # %{with server}


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
%{__make} VERBOSE=1 %{?_smp_mflags} all
# %{__make} VERBOSE=1 %{?_smp_mflags} unit-test


%install
%{__rm} -rf %{buildroot}
cd build
%{__make} install DESTDIR=%{buildroot} INSTALL="install -p"

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

# Customize system upgrade scripts in /usr/share/pki/upgrade
%if 0%{?rhel} && 0%{?rhel} <= 7

# merge newer upgrade scripts into 10.3.3 for RHEL
/bin/rm -rf %{buildroot}%{_datadir}/pki/upgrade/10.3.4
/bin/rm -rf %{buildroot}%{_datadir}/pki/upgrade/10.3.5

# merge newer upgrade scripts into 10.4.1 for RHEL
/bin/rm -rf %{buildroot}%{_datadir}/pki/upgrade/10.4.2
/bin/rm -rf %{buildroot}%{_datadir}/pki/upgrade/10.4.3
/bin/rm -rf %{buildroot}%{_datadir}/pki/upgrade/10.4.4
/bin/rm -rf %{buildroot}%{_datadir}/pki/upgrade/10.4.5
/bin/rm -rf %{buildroot}%{_datadir}/pki/upgrade/10.4.6
%endif

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
/bin/rm -rf %{buildroot}%{_datadir}/pki/server/upgrade/10.3.4
/bin/rm -rf %{buildroot}%{_datadir}/pki/server/upgrade/10.3.5

# merge newer upgrade scripts into 10.4.1 for RHEL
mv %{buildroot}%{_datadir}/pki/server/upgrade/10.4.2/01-AddSessionAuthenticationPlugin \
   %{buildroot}%{_datadir}/pki/server/upgrade/10.4.1/01-AddSessionAuthenticationPlugin
mv %{buildroot}%{_datadir}/pki/server/upgrade/10.4.2/02-AddKRAWrappingParams \
   %{buildroot}%{_datadir}/pki/server/upgrade/10.4.1/02-AddKRAWrappingParams
mv %{buildroot}%{_datadir}/pki/server/upgrade/10.4.6/01-UpdateKeepAliveTimeout \
   %{buildroot}%{_datadir}/pki/server/upgrade/10.4.1/03-UpdateKeepAliveTimeout
/bin/rm -rf %{buildroot}%{_datadir}/pki/server/upgrade/10.4.2
/bin/rm -rf %{buildroot}%{_datadir}/pki/server/upgrade/10.4.3
/bin/rm -rf %{buildroot}%{_datadir}/pki/server/upgrade/10.4.4
/bin/rm -rf %{buildroot}%{_datadir}/pki/server/upgrade/10.4.5
/bin/rm -rf %{buildroot}%{_datadir}/pki/server/upgrade/10.4.6

# merge newer upgrade script into 10.5.1 for RHEL
mv %{buildroot}%{_datadir}/pki/server/upgrade/10.5.5/01-AddTPSExternalRegISEtokenParams \
   %{buildroot}%{_datadir}/pki/server/upgrade/10.5.1/01-AddTPSExternalRegISEtokenParams

/bin/rm -rf %{buildroot}%{_datadir}/pki/server/upgrade/10.5.5

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

%if 0%{?fedora} || 0%{?rhel} > 7
# Scanning the python code with pylint.
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
   msg = "Unable to upgrade to Fedora 20.  There are Dogtag 9 instances\n" ..
         "that will no longer work since they require Tomcat 6, and \n" ..
         "Tomcat 6 is no longer available in Fedora 20.\n\n" ..
         "Please follow these instructions to migrate the instances to \n" ..
         "Dogtag 10:\n\n" ..
         "http://pki.fedoraproject.org/wiki/Migrating_Dogtag_9_Instances_to_Dogtag_10"
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
%files -n pki-symkey
%defattr(-,root,root,-)
%doc base/symkey/LICENSE
%{_jnidir}/symkey.jar
%{_libdir}/symkey/
%endif


%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
%files -n pki-base
%defattr(-,root,root,-)
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
%files -n pki-base-java
%{_datadir}/pki/examples/java/
%{_datadir}/pki/lib/
%dir %{_javadir}/pki
%{_javadir}/pki/pki-cmsutil.jar
%{_javadir}/pki/pki-nsutil.jar
%{_javadir}/pki/pki-certsrv.jar
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
%if %{with_python3}
%files -n pki-base-python3
%defattr(-,root,root,-)
%doc base/common/LICENSE
%doc base/common/LICENSE.LESSER
%exclude %{python3_sitelib}/pki/server
%{python3_sitelib}/pki
%endif # with_python3
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
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
%{_bindir}/PrettyPrintCert
%{_bindir}/PrettyPrintCrl
%{_bindir}/TokenInfo
%{_javadir}/pki/pki-tools.jar
%{_datadir}/pki/java-tools/
%{_mandir}/man1/AtoB.1.gz
%{_mandir}/man1/AuditVerify.1.gz
%{_mandir}/man1/BtoA.1.gz
%{_mandir}/man1/CMCEnroll.1.gz
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
%endif

%if %{with server}

%if 0%{?package_fedora_packages} || 0%{?package_rhel_packages}
%files -n pki-server
%defattr(-,root,root,-)
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
%files -n pki-ca
%defattr(-,root,root,-)
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
%files -n pki-kra
%defattr(-,root,root,-)
%doc base/kra/LICENSE
%{_javadir}/pki/pki-kra.jar
%dir %{_datadir}/pki/kra
%{_datadir}/pki/kra/conf/
%{_datadir}/pki/kra/setup/
%{_datadir}/pki/kra/webapps/
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhcs_packages}
%files -n pki-ocsp
%defattr(-,root,root,-)
%doc base/ocsp/LICENSE
%{_javadir}/pki/pki-ocsp.jar
%dir %{_datadir}/pki/ocsp
%{_datadir}/pki/ocsp/conf/
%{_datadir}/pki/ocsp/setup/
%{_datadir}/pki/ocsp/webapps/
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhcs_packages}
%files -n pki-tks
%defattr(-,root,root,-)
%doc base/tks/LICENSE
%{_javadir}/pki/pki-tks.jar
%dir %{_datadir}/pki/tks
%{_datadir}/pki/tks/conf/
%{_datadir}/pki/tks/setup/
%{_datadir}/pki/tks/webapps/
%endif

%if 0%{?package_fedora_packages} || 0%{?package_rhcs_packages}
%files -n pki-tps
%defattr(-,root,root,-)
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
%files -n pki-javadoc
%defattr(-,root,root,-)
%{_javadocdir}/pki-%{version}/
%endif
%endif

%endif # %{with server}

%changelog
* Mon Feb  5 2018 Dogtag Team <pki-devel@redhat.com> 10.5.5-1
- dogtagpki Pagure Issue #2656 - Updating list of default audit events
  (edewata)
- dogtagpki Pagure Issue #2838 - Inconsistent  CERT_REQUEST_PROCESSED
  outcomes. (edewata)
- dogtagpki Pagure Issue #2844 - TPS CS.cfg should be reflected with the
  changes after an in-place upgrade (jmagne)
- dogtagpki Pagure Issue #2855 - restrict default cipher suite to those
  ciphers permitted in fips mode (mharmsen)
- dogtagpki Pagure Issue #2878 - Missing faillure resumption detection and
  audit event logging at startup (jmagne)
- dogtagpki Pagure Issue #2880 - Need to record CMC requests and responses
  (cfu)
- dogtagpki Pagure Issue #2889 - Unable to have non "pkiuser" owned CA
  instance (alee)
- dogtagpki Pagure Issue #2901 - Installing subsystems with external CMC
  certificates in HSM environment shows import error (edewata)
- dogtagpki Pagure Issue #2909 - ProfileService: config values with
  backslashes have backslashes removed (ftweedal)
- dogtagpki Pagure Issue #2916 - ExternalCA: Failures when installed with
  hsm (edewata)
- dogtagpki Pagure Issue #2920 - CMC: Audit Events needed for failures in
  SharedToken scenarios (cfu)
- dogtagpki Pagure Issue #2921 - CMC: Revocation works with an unknown
  revRequest.issuer (cfu)

* Tue Jan 23 2018 Dogtag Team <pki-devel@redhat.com> 10.5.4-1
- dogtagpki Pagure Issue #2557 -CA Cloning: Failed to update number range
  in few cases (ftweedal)
- dogtagpki Pagure Issue #2604 - RFE: shared token storage and retrieval
  mechanism (cfu)
- dogtagpki Pagure Issue #2661 -HAProxy rejects OCSP responses due to
  missing nextupdate field (ftweedal)
- dogtagpki Pagure Issue #2835 - pkidestroy does not work with nuxwdog
  (vakwetu)
- dogtagpki Pagure Issue #2870 - Adjust requirement for openssl to latest
  version to include latest openssl fixes for FIPS SSL (mharmsen)
- dogtagpki Pagure Issue #2872 -PR_FILE_NOT_FOUND_ERROR during
  pkispawn (vakwetu)
- dogtagpki Pagure Issue #2873 - p12 admin certificate is missing when
  certificate is signed Externally (edewata)
- dogtagpki Pagure Issue #2887 -Not able to setup CA with ECC (mharmsen)
- dogtagpki Pagure Issue #2889 - Unable to have non "pkiuser" owned CA
  instance (vakwetu)
- dogtagpki Pagure Issue #2904 - Adjust dependencies to require the latest
  nuxwdog (mharmsen)
- dogtagpki Pagure Issue #2910 - pkispawn fails to mask specified parameter
  values under the [DEFAULT] section (vakwetu)
- dogtagpki Pagure Issue #2911 -Adjust dependencies to require the latest
  JSS (mharmsen)

* Mon Dec 11 2017 Dogtag Team <pki-devel@redhat.com> 10.5.3-1
- Re-base Dogtag to 10.5.3
- dogtagpki Pagure Issue #2735 - Secure removal of secret data storage
  (jmagne)
- dogtagpki Pagure Issue #2856 - Pylint flags seobject failures
  (cheimes, mharmsen)
- dogtagpki Pagure Issue #2861 -ExternalCA: Failures in ExternalCA when
  tried to setup with CMC signed certificates (cfu)
- dogtagpki Pagure Issue #2862 - Create a mechanism to select the
  default NSS DB type (jmagne, mharmsen)
- dogtagpki Pagure Issue #2874 - nuxwdog won't start on Fedora
  (alee, mharmsen)

* Mon Nov 27 2017 Dogtag Team <pki-devel@redhat.com> 10.5.2-1
- Re-base Dogtag to 10.5.2

* Tue Nov 14 2017 Troy Dawson <tdawson@redhat.com> - 10.5.1-3
- dogtagpki Pagure Issue #2853 - Cleanup spec file conditionals

* Wed Nov  8 2017 Dogtag Team <pki-devel@redhat.com> 10.5.1-2
- Patch applying check-ins since 10.5.1-1

* Thu Nov  2 2017 Dogtag Team <pki-devel@redhat.com> 10.5.1-1
- Re-base Dogtag to 10.5.1

* Thu Oct 19 2017 Dogtag Team <pki-devel@redhat.com> 10.5.0-1
- Re-base Dogtag to 10.5.0

* Mon Sep 18 2017 Dogtag Team <pki-devel@redhat.com> 10.4.8-7
- dogtagpki Pagure Issue #2809 - PKCS #12 files incompatible with
  NSS >= 3.31 (ftweedal)

* Tue Sep 12 2017 Dogtag Team <pki-devel@redhat.com> 10.4.8-6
- Require "jss >= 4.4.2-5" as a build and runtime requirement
- dogtagpki Pagure Issue #2796 - lightweight CA replication fails with a
  NullPointerException (ftweedal)
- dogtagpki Pagure Issue #2788 - Missing CN in user signing cert would cause
  error in cmc user-signed (cfu)
- dogtagpki Pagure Issue #2789 - FixDeploymentDescriptor upgrade scriptlet can
  fail (ftweedal)
- dogtagpki Pagure Issue #2664 - PKCS12: upgrade to at least AES and SHA2
  (FIPS) (ftweedal)
- dogtagpki Pagure Issue #2764 - py3: pki.key.archive_encrypted_data:
  TypeError: ... is not JSON serializable (ftweedal)
- dogtagpki Pagure Issue #2772 - TPS incorrectly assigns "tokenOrigin" and
  "tokenType" certificate attribute for recovered certificates. (cfu)
- dogtagpki Pagure Issue #2793 - TPS UI: need to display tokenType and
  tokenOrigin for token certificates on TPS UI (edewata)

* Mon Aug 21 2017 Dogtag Team <pki-devel@redhat.com> 10.4.8-5
- dogtagpki Pagure Issue #2671 - Access Banner Validation (edewata)

* Thu Aug 03 2017 Fedora Release Engineering <releng@fedoraproject.org> - 10.4.8-4
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Binutils_Mass_Rebuild

* Thu Jul 27 2017 Fedora Release Engineering <releng@fedoraproject.org> - 10.4.8-3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_27_Mass_Rebuild

* Mon Jun 19 2017 Dogtag Team <pki-devel@redhat.com> 10.4.8-2
- dogtagpki Pagure Issue #2721 - Key recovery using externalReg fails
  with java null pointer exception on KRA (vakwetu)
- dogtagpki Pagure Issue #2737 - CMC: check HTTPS client
  authentication cert against CMC signer (cfu)
- dogtagpki Pagure Issue #2741 - Unable to find keys in the p12 file
  after deleting the any of the subsystem certs from it (ftweedal)
- dogtagpki Pagure Issue #2745 - Platform Dependent Python Import (cheimes)

* Mon Jun 12 2017 Dogtag Team <pki-devel@redhat.com> 10.4.8-1
- dogtagpki Pagure Issue #2540 - Creating symmetric key (sharedSecret)
  using tkstool is failing when operating system is in FIPS mode. (jmagne)
- dogtagpki Pagure Issue #2617 - Allow CA to process pre-signed CMC
  non-signing certificate requests (cfu)
- dogtagpki Pagure Issue #2619 - Allow CA to process pre-signed CMC
  revocation non-signing cert requests (cfu)
- dogtagpki Pagure Issue #2643 - Session timeout for PKI console
  (edewata)
- dogtagpki Pagure Issue #2719 - change the way aes clients refer to
  aes keysets (vakwetu)
- dogtagpki Pagure Issue #2722 - dont reuse IVs in the CMC code
  (vakwetu)
- dogtagpki Pagure Issue #2728 - In keywrap mode, key recovery on
  KRA with HSM causes KRA to crash (ftweedal)

* Mon Jun  5 2017 Dogtag Team <pki-devel@redhat.com> 10.4.7-1
- Require "selinux-policy-targeted >= 3.13.1-159" as a runtime requirement
- Require "tomcatjss >= 7.2.3" as a build and runtime requirement
- dogtagpki Pagure Issue #1663 - Add SCP03 support (jmagne)
- dogtagpki Pagure Issue #2556 - pkispawn fails to create PKI subsystem
  on FIPS enabled system (edewata)
- dogtagpki Pagure Issue #2674 - CA brought down during separate KRA
  instance creation (edewata)
- dogtagpki Pagure Issue #2676 - pkispawn fails occasionally with this
  failure ACCESS_SESSION_ESTABLISH_FAILURE (edewata)
- dogtagpki Pagure Issue #2687 - Upgrade script for keepAliveTimeout
  parameter (edewata)
- dogtagpki Pagure Issue #2707 - SubCA installation failure with 2 step
  installation in fips enabled mode (edewata)
- dogtagpki Pagure Issue #2713 - Build failure due to Pylint issues (cheimes)
- dogtagpki Pagure Issue #2714 - Classpath problem while trying to run pki
  CLI (edewata)
- dogtagpki Pagure Issue #2717 - Certificate import using pki
  client-cert-import is asking for password when already provided (edewata)
- dogtagpki Pagure Issue #2721 - Key recovery using externalReg fails with
  java null pointer exception on KRA (vakwetu)
- dogtagpki Pagure Issue #2726 - client-cert-import --ca-cert should import
  CA cert with trust bits "CT,C,C" (edewata)

* Tue May 30 2017 Dogtag Team <pki-devel@redhat.com> 10.4.6-1
- dogtagpki Pagure Issue #2540 - Creating symmetric key (sharedSecret)
   using tkstool is failing when operating system is in FIPS mode. (jmagne)
- dogtagpki Pagure Issue #2651 - Adding CRL_GENERATION audit event.
  (edewata)
- dogtagpki Pagure Issue #2660 - CA Server installation with HSM fails
  (jmagne)
- dogtagpki Pagure Issue #2699 - Enabling all subsystems on startup
  (edewata)
- dogtagpki Pagure Issue #2710 - Key recovery on token fails because
  key record is not marked encrypted (vakwetu)
- dogtagpki Pagure Issue #2711 - LWCA creation fails (ftweedal)

* Mon May 22 2017 Dogtag Team <pki-devel@redhat.com> 10.4.5-1
- dogtagpki Pagure Issue #2618 - Allow CA to process pre-signed CMC renewal
  non-signing cert requests (cfu)
- dogtagpki Pagure Issue #2641 - Ensuring common audit log correctness
  (edewata)
- dogtagpki Pagure Issue #2655 - Adding serial number into
  CERT_REQUEST_PROCESSED audit event. (edewata)
- dogtagpki Pagure Issue #2673 - allow enrollment key signed CMC with identity
  proof (cfu)
- dogtagpki Pagure Issue #2674 - CA brought down during separate KRA instance
  creation (mharmsen)
- dogtagpki Pagure Issue #2683 - exception Invalid module "--ignore-banner"
  when defined in ~/.dogtag/pki.conf and run pki pkcs12-import --help
  (edewata)
- dogtagpki Pagure Issue #2684 - CA installation with HSM in FIPS mode fails
  (jmagne)
- dogtagpki Pagure Issue #2685 - Add "is_fips_enabled()" method to Python
  pkispawn logic (mharmsen)
- dogtagpki Pagure Issue #2690 - Inconsistent CERT_REQUEST_PROCESSED event in
  ConnectorServlet. (edewata)
- dogtagpki Pagure Issue #2693 - Incorrect audit event outcome for
  agent-rejected cert request. (edewata)
- dogtagpki Pagure Issue #2694 -Incorrect audit event outcome for
  agent-canceled cert request. (edewata)
- dogtagpki Pagure Issue #2696 - CA CS.cfg shows default port (mharmsen)

* Tue May  9 2017 Dogtag Team <pki-devel@redhat.com> 10.4.4-1
- dogtagpki Pagure Issue #1663 - Add SCP03 support (jmagne)
- dogtagpki Pagure Issue #2522 - cannot extract generated private key from
  KRA when HSM is used. (vakwetu)
- dogtagpki Pagure Issue #2644 - pkispawn returns before tomcat is ready
  (cheimes)
- dogtagpki Pagure Issue #2665 - CAInfoService: retrieve KRA-related values
  from the KRA (ftweedal)
- dogtagpki Pagure Issue #2675 - CMC: cmc.popLinkWitnessRequired=false would
  cause error (cfu)
- dogtagpki Pagure Issue #2777 - pkispawn of clone install fails with
  InvalidBERException (ftweedal)
- dogtagpki Pagure Issue #2680 - kra unable to extract symmetric keys
  generated on thales hsm (vakwetu)
- Updated "jss" build and runtime requirements

* Mon May  1 2017 Dogtag Team <pki-devel@redhat.com> 10.4.3-1
- dogtagpki Pagure Issue #1359 - dogtag should support GSSAPI based auth in
  conjuction with FreeIPA (ftweedal)
- dogtagpki Pagure Issue #1408 - Key archival using AES (alee)
- dogtagpki Pagure Issue #2520 - CA certificate profiles: the startTime
  parameter is not working as expected. (jmagne)
- dogtagpki Pagure Issue #2588 - profile modification cannot remove existing
  config parameters (ftweedal)
- dogtagpki Pagure Issue #2610 - PKCS12: upgrade to at least AES and SHA2
  (ftweedal)
- dogtagpki Pagure Issue #2617 - Allow CA to process pre-signed CMC
  non-signing certificate requests (cfu)
- dogtagpki Pagure Issue #2642 - Missing ClientIP and ServerIP in audit log
  when pki CLI terminates SSL connection (edewata)
- dogtagpki Pagure Issue #2643 - Session timeout for PKI console (edewata)
- updated JSS dependencies

* Mon Apr 17 2017 Dogtag Team <pki-devel@redhat.com> 10.4.2-1
- dogtagpki Pagure Issue #1663 - Add SCP03 support for g&d sc 7 cards
  (jmagne)
- dogtagpki Pagure Issue #1722 - Installing pki-server in container reports
  scriptlet failed, exit status 1 (mharmsen)
- dogtagpki Pagure Issue #2556 - pkispawn fails to create PKI subsystem
  on FIPS enabled system (edewata)
- dogtagpki Pagure Issue #2602 -Audit logs for SSL/TLS session events
  (edewata)
- dogtagpki Pagure Issue #2614 - CMC: id-cmc-popLinkWitnessV2 feature
  implementation (cfu)
- dogtagpki Pagure Issue #2622 - Audit log search/review (edewata)
- dogtagpki Pagure Issue #2625 - cli authentication using expired cert
  throws an exception (edewata)
- dogtagpki Pagure Issue #2626 - non-CA cli looks for CA in the instance
  during a request (edewata)
- dogtagpki Pagure Issue #2633 - Missing python2-cryptography
  dependency (mharmsen)

* Fri Mar 31 2017 Dogtag Team <pki-devel@redhat.com> 10.4.1-2
- Fixed runtime typo on jss

* Mon Mar 27 2017 Dogtag Team <pki-devel@redhat.com> 10.4.1-1
- Require "nss >= 3.28.3" as a build and runtime requirement
- Require "jss >= 4.4.1" as a build and runtime requirement
- Require "tomcatjss >= 7.2.2" as a build and runtime requirement
- ############################################################################
- dogtagpki Pagure Issue #2541 - Re-base Dogtag pki packages to 10.4.x
- ############################################################################
- dogtagpki Pagure Issue #2602 - Audit logs for SSL/TLS session events
  implementation (edewata)
- dogtagpki Pagure Issue #2605 - CMC feature support: provided issuance
  protection cert mechanism (cfu)
- dogtagpki Pagure Issue #2612 - Unable to clone due to pki pkcs12-cert-find
  failure (edewata)
- dogtagpki Pagure Issue #2613 - CMC: id-cmc-identityProofV2 feature
  implementation (cfu)
- dogtagpki Pagure Issue #2615 - CMC: provide Proof of Possession for
  encryption cert requests (cfu)

* Tue Mar 14 2017 Dogtag Team <pki-devel@redhat.com> 10.4.0-1
- Require "jss >= 4.4.0-1" as a build and runtime requirement
- Require "tomcatjss >= 7.2.1-1" as a build and runtime requirement
- ############################################################################
- dogtagpki Pagure Issue #2541 - Re-base Dogtag pki packages to 10.4.x
- ############################################################################
- dogtagpki Pagure Issue #6 - Remove Policy Framework Deprecations (edewata)
- dogtagpki Pagure Issue #850 - JSS certificate validation function does not
  pass up exact errors from NSS (edewata)
- dogtagpki Pagure Issue #1114 - [MAN] Generting Symmetric key fails with
  key-generate when --usages verify is passed (vakwetu)
- dogtagpki Pagure Issue #1247 - Better error message when try to renew a
  certificate that expires outside renewal grace period (vakwetu)
- dogtagpki Pagure Issue #1309 - Recovering of a revoked cert erroneously
  reflects "active" in the token db cert entry (cfu)
- dogtagpki Pagure Issue #1490 - add option to bypass dnsdomainname check in
  pkispawn (vakwetu)
- dogtagpki Pagure Issue #1517 - user-cert-add --serial CLI request to secure
  port with remote CA shows authentication failure (edewata)
- dogtagpki Pagure Issue #1527 - TPS Enrollment always goes to "ca1" (cfu)
- dogtagpki Pagure Issue #1536 - CA EE: Submit caUserCert request without uid
  does not show proper error message (vakwetu)
- dogtagpki Pagure Issue #1663 - Add SCP03 support (jmagne)
- dogtagpki Pagure Issue #1664 - [BUG] Add ability to disallow TPS to enroll
  a single user on multiple tokens. (jmagne)
- dogtagpki Pagure Issue #1710 - Add profile component that copies CN to SAN
  (ftweedal)
- dogtagpki Pagure Issue #1741 - ECDSA Certificates Generated by Certificate
  System fail NIST validation test with parameter field. (cfu)
- dogtagpki Pagure Issue #1897 - [MAN] Man page for logging configuration.
  (edewata)
- dogtagpki Pagure Issue #1920 - [MAN] Man page for PKCS #12 utilities
  (edewata)
- dogtagpki Pagure Issue #2275 - add options to enable/disable cert or crl
  publishing. (vakwetu)
- dogtagpki Pagure Issue #2289 - [MAN] pki ca-cert-request-submit fails
  presumably because of missing authentication even if it should not require
  any (edewata)
- dogtagpki Pagure Issue #2450 - Unable to search certificate requests using
  the latest request ID (edewata)
- dogtagpki Pagure Issue #2453 - IPA replica-prepare failed with error
  "Profile caIPAserviceCert Not Found" (ftweedal)
- dogtagpki Pagure Issue #2457 - Misleading Logging for HSM (edewata)
- dogtagpki Pagure Issue #2460 - Typo in comment line of
  UserPwdDirAuthentication.java (edewata) 
- dogtagpki Pagure Issue #2463 - Troubleshooting improvements (edewata)
- dogtagpki Pagure Issue #2466 - two-step externally-signed CA installation
  fails due to missing AuthorityID (ftweedal)
- dogtagpki Pagure Issue #2475 - Multiple host authority entries created
  (ftweedal)
- dogtagpki Pagure Issue #2476 - Miscellaneous Minor Changes (edewata)
- dogtagpki Pagure Issue #2478 - pkispawn fails as it is not able to find
  openssl as a dependency package (mharmsen)
- dogtagpki Pagure Issue #2483 - Unable to read an encrypted email using
  renewed tokens (jmagne)
- dogtagpki Pagure Issue #2486 - Automatic recovery of encryption cert is not
  working when a token is physically damaged and a temporary token is issue
  (jmagne)
- dogtagpki Pagure Issue #2496 -Cert/Key recovery is successful when the cert
  serial number and key id on the ldap user mismatches (cfu)
- dogtagpki Pagure Issue #2497 - KRA installation failed against
  externally-signed CA with partial certificate chain (edewata)
- dogtagpki Pagure Issue #2498 -Token format with external reg fails when
  op.format.externalRegAddToToken.revokeCert=true (cfu)
- dogtagpki Pagure Issue #2500 - Problems with FIPS mode (edewata)
- dogtagpki Pagure Issue #2505 - Fix packaging duplicates of classes in
  multiple jar files (edewata)
- dogtagpki Pagure Issue #2510 - PIN_RESET policy is not giving expected
  results when set on a token (jmagne)
- dogtagpki Pagure Issue #2513 -TPS token enrollment fails to
  setupSecureChannel when TPS and TKS security db is on fips mode. (jmagne)
- dogtagpki Pagure Issue #2523 - Changes to target.agent.approve.list
  parameter is not reflected in the TPS Web UI (edewata)
- dogtagpki Pagure Issue #2524 - Remove xenroll.dll from pki-core (mharmsen)
- dogtagpki Pagure Issue #2525 - [RFE] FreeIPA to Dogtag permission mapping
  plugin (ftweedal)
- dogtagpki Pagure Issue #2532 - [RFE] add express archivals and retrievals
  from KRA (vakwetu)
- dogtagpki Pagure Issue #2534 - Automatic recovery of encryption cert - CA
  and TPS tokendb shows different certificate status (cfu)
- dogtagpki Pagure Issue #2543 - Unable to install subordinate CA with HSM in
  FIPS mode (edewata)
- dogtagpki Pagure Issue #2544 - TPS throws "err=6" when attempting to format
  and enroll G&D Cards (jmagne)
- dogtagpki Pagure Issue #2552 - pkispawn does not change default ecc key size
  from nistp256 when nistp384 is specified in spawn config (jmagne)
- dogtagpki Pagure Issue #2556 - pkispawn fails to create PKI subsystem on
  FIPS enabled system (edewata)
- dogtagpki Pagure Issue #2564 - pki-tomcat for 10+ minutes before generating
  cert (edewata)
- dogtagpki Pagure Issue #2569 - Token memory not wiped after key deletion
  (jmagne)
- dogtagpki Pagure Issue #2570 - Problem with default AJP hostname in IPv6
  environment. (edewata)
- dogtagpki Pagure Issue #2571 - Request ID undefined for CA signing
  certificate (vakwetu)
- dogtagpki Pagure Issue #2573 - CA Certificate Issuance Date displayed on CA
  website incorrect (vakwetu)
- dogtagpki Pagure Issue #2579 - NumberFormatException in
  LDAPProfileSubsystem (ftweedal)
- dogtagpki Pagure Issue #2582 - Access banner (edewata)
- dogtagpki Pagure Issue #2601 - Return revocation reason in GET
  /ca/rest/certs/{id} response. (ftweedal)
- ############################################################################

* Mon Mar  6 2017 Dogtag Team <pki-devel@redhat.com> 10.4.0-0.1
- Updated version number to 10.4.0-0.1
- NOTE: Original date was Mon Aug 8 2016

* Mon Mar  6 2017 Dogtag Team <pki-devel@redhat.com> 10.3.5-13
- PKI TRAC Ticket #1710 - Add profile component that copies CN to SAN (ftweedal)

* Sat Feb 11 2017 Fedora Release Engineering <releng@fedoraproject.org> - 10.3.5-12
- Rebuilt for https://fedoraproject.org/wiki/Fedora_26_Mass_Rebuild

* Tue Jan 31 2017 Dogtag Team <pki-devel@redhat.com> 10.3.5-11

* Thu Dec 22 2016 Miro Hrončok <mhroncok@redhat.com> - 10.3.5-10
- Rebuild for Python 3.6 (Fedora 26)

* Tue Dec 13 2016 Dogtag Team <pki-devel@redhat.com> 10.3.5-9
- PKI TRAC Ticket #1517 - user-cert-add --serial CLI request to secure port
  with remote CA shows authentication failure (edewata)
- PKI TRAC Ticket #1897 - [MAN] Man page for logging configuration. (edewata)
- PKI TRAC Ticket #1920 - [MAN] Man page for PKCS #12 utilities (edewata)
- PKI TRAC Ticket #2226 - KRA installation: NullPointerException in
  ProxyRealm.findSecurityConstraints (edewata)
- PKI TRAC Ticket #2289 -  [MAN] pki ca-cert-request-submit fails presumably
  because of missing authentication even if it should not require any (edewata)
- PKI TRAC Ticket #2523 - Changes to target.agent.approve.list parameter is
  not reflected in the TPS Web UI [pki-base] (edewata)
- PKI TRAC Ticket #2534 - Automatic recovery of encryption cert - CA and TPS
  tokendb shows different certificate status (cfu)
- PKI TRAC Ticket #2543 - Unable to install subordinate CA with HSM in FIPS
  mode (edewata)
- PKI TRAC Ticket #2544 -  TPS throws "err=6" when attempting to format and
  enroll G&D Cards (jmagne)
- PKI TRAC Ticket #2552 - pkispawn does not change default ecc key size from
  nistp256 when nistp384 is specified in spawn config (jmagne)

* Fri Nov  4 2016 Dogtag Team <pki-devel@redhat.com> 10.3.5-8
- PKI TRAC Ticket #850 - JSS certificate validation function does not pass up
  exact errors from NSS (edewata)
  (Failed to start pki-tomcatd Service - "ipa-cacert-manage renew" failed?)
- PKI TRAC Ticket #1247 - Better error message when try to renew a certificate
  that expires outside renewal grace period (alee)
- PKI TRAC Ticket #1536 - CA EE: Submit caUserCert request without uid does
  not show proper error message (alee)
- PKI TRAC Ticket #2460 - Typo in comment line of UserPwdDirAuthentication.java
  (edewata)
- PKI TRAC Ticket #2486 - Automatic recovery of encryption cert is not working
  when a token is physically damaged and a temporary token is issued (jmagne)
- PKI TRAC Ticket #2498 - Token format with external reg fails when
  op.format.externalRegAddToToken.revokeCert=true (cfu)
- PKI TRAC Ticket #2500 - Problems with FIPS mode (edewata)
- PKI TRAC Ticket #2500 - Problems with FIPS mode (edewata)
  (added KRA key recovery via CLI in FIPS mode)
- PKI TRAC Ticket #2510 - PIN_RESET policy is not giving expected results when
  set on a token (jmagne)
- PKI TRAC Ticket #2513 - TPS token enrollment fails to setupSecureChannel
  when TPS and TKS security db is on fips mode. (jmagne)
- Reverted patches associated with
  PKI TRAC Ticket #2523 - Changes to target.agent.approve.list parameter is
  not reflected in the TPS Web UI

* Mon Oct 10 2016 Dogtag Team <pki-devel@redhat.com> 10.3.5-7
- PKI TRAC Ticket #1527 - TPS Enrollment always goes to "ca1" (cfu)
- PKI TRAC Ticket #1664 - [BUG] Add ability to disallow TPS to enroll a single
  user on multiple tokens. (jmagne)
- PKI TRAC Ticket #2463 - Troubleshooting improvements (edewata)
- PKI TRAC Ticket #2466 - two-step externally-signed CA installation fails due
  to missing AuthorityID (ftweedal)
- PKI TRAC Ticket #2475 - Multiple host authority entries created (ftweedal)
- PKI TRAC Ticket #2476 - Dogtag 10.4.0 Miscellaneous Minor Changes
  (edewata)
- PKI TRAC Ticket #2478 - pkispawn fails as it is not able to find openssl as a
  dependency package (mharmsen)
- PKI TRAC Ticket #2483 - Unable to read an encrypted email using renewed
  tokens (jmagne)
- PKI TRAC Ticket #2496 - Cert/Key recovery is successful when the cert serial
  number and key id on the ldap user mismatches (cfu)
- PKI TRAC Ticket #2497 - KRA installation failed against externally-signed CA
  with partial certificate chain (edewata)
- PKI TRAC Ticket #2505 - Fix packaging duplicates of classes in multiple jar
  files (edewata)
- Fix for flake8 errors on Fedora 26 (cheimes)

* Fri Sep  9 2016 Dogtag Team <pki-devel@redhat.com> 10.3.5-6
- Revert Patch:  PKI TRAC Ticket #2449 - Unable to create system certificates
  in different tokens (edewata)

* Tue Sep  6 2016 Dogtag Team <pki-devel@redhat.com> 10.3.5-5
- PKI TRAC Ticket #1638 - Lightweight CAs: revoke certificate on CA deletion
  (ftweedal)
- PKI TRAC Ticket #2436 - Dogtag 10.3.6: Miscellaneous Enhancements
  (edewata)
- PKI TRAC Ticket #2443 - Prevent deletion of host CA's keys if LWCA entry
  deleted (ftweedal)
- PKI TRAC Ticket #2444 - Authority entry without entryUSN is skipped even if
  USN plugin enabled (ftweedal)
- PKI TRAC Ticket #2446 - pkispawn: make subject_dn defaults unique per
  instance name (for shared HSM) (cfu)
- PKI TRAC Ticket #2447 - CertRequestInfo has incorrect URLs (vakwetu)
- PKI TRAC Ticket #2449 - Unable to create system certificates in different
  tokens (edewata)

* Mon Aug 29 2016 Dogtag Team <pki-devel@redhat.com> 10.3.5-4
- PKI TRAC Ticket #1578 - Authentication Instance Id PinDirEnrollment with authType value as SslclientAuth is not working (jmagne)
- PKI TRAC TIcket #2414 - pki pkcs12-cert-del shows a successfully deleted message when a wrong nickname is provided (gkapoor)
- PKI TRAC Ticket #2423 - pki_ca_signing_token when not specified does not fallback to pki_token_name value (edewata)
- PKI TRAC Ticket #2436 - Dogtag 10.3.6: Miscellaneous Enhancements (akasurde) - ticket remains open
- PKI TRAC Ticket #2439 - Outdated deployment descriptors in upgraded server(edewata)

* Mon Aug 22 2016 Dogtag Team <pki-devel@redhat.com> 10.3.5-3
- spec file changes

* Mon Aug 22 2016 Dogtag Team <pki-devel@redhat.com> 10.3.5-2
- PKI TRAC Ticket #690 - [MAN] pki-tools man pages (mharmsen)
  - CMCEnroll
- PKI TRAC Ticket #833 - pki user-mod fullName="" gives an error message
  "PKIException: LDAP error (21): error result" (edewata)
- PKI TRAC Ticket #2431 - Errors noticed during ipa server upgrade.
  (cheimes, edewata, mharmsen)
- PKI TRAC Ticket #2432 - Kra-selftest behavior is not as expected (edewata)
- PKI TRAC Ticket #2436 - Dogtag 10.3.6: Miscellaneous Enhancements
  (edewata, mharmsen)
- PKI TRAC Ticket #2437 - TPS UI: while adding certs for users from TPSUI pem
  format with/without header works while pkcs7 with header is not allowed
  (edewata)
- PKI TRAC Ticket #2440 - Optional CA signing CSR for migration (edewata)

* Mon Aug  8 2016 Dogtag Team <pki-devel@redhat.com> 10.3.5-1
- Updated version number to 10.3.5-1

* Tue Jul 19 2016 Dogtag Team <pki-devel@redhat.com> 10.3.5-0.1
- Updated version number to 10.3.5-0.1
- NOTE: Original date was Tue Jul  5 2016

* Tue Jul 19 2016 Dogtag Team <pki-devel@redhat.com> 10.3.4-0.1
- Updated version number to 10.3.4-0.1
- NOTE: Original date was Tue Jun 21 2016

* Tue Jul 19 2016 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 10.3.3-4
- https://fedoraproject.org/wiki/Changes/Automatic_Provides_for_Python_RPM_Packages

* Tue Jul  5 2016 Dogtag Team <pki-devel@redhat.com> 10.3.3-3
- PKI TRAC Ticket #691  - [MAN] pki-server man pages (mharmsen)
- PKI TRAC Ticket #1114 - [MAN] Generting Symmetric key fails with
  key-generate when --usages verify is passed (jmagne)
- PKI TRAC Ticket #1306 - [RFE] Add granularity to token termination in TPS
  (cfu)
- PKI TRAC Ticket #1308 - [RFE] Provide ability to perform off-card key
  generation for non-encryption token keys (cfu)
- PKI TRAC Ticket #1405 - [MAN] Add additional HSM details to
  'pki_default.cfg' & 'pkispawn' man pages (mharmsen)
- PKI TRAC Ticket #1607 - [MAN] man pkispawn has inadequate description for
  shared vs non shared tomcat instance installation (mharmsen)
- PKI TRAC Ticket #1664 - [BUG] Add ability to disallow TPS to enroll a single
  user on multiple tokens. (jmagne)
- PKI TRAC Ticket #1711 - CLI :: pki-server ca-cert-request-find throws
  IOError (edewata, ftweedal)
- PKI TRAC Ticket #2285 - freeipa fails to start correctly after pki-core
  update on upgraded system (ftweedal)
- PKI TRAC Ticket #2311 - When pki_token_name=Internal, consider normalizing
  it to "internal" (mharmsen)
- PKI TRAC Ticket #2349 - Separated TPS does not automatically receive shared
  secret from remote TKS (jmagne)
- PKI TRAC Ticket #2364 - CLI :: pki-server ca-cert-request-show throws
  attribute error (ftweedal)
- PKI TRAC Ticket #2368 - pki-server subsystem subcommands throws error with
  --help option (edewata)
- PKI TRAC Ticket #2374 - KRA cloning overwrites CA signing certificate trust
  flags (edewata)
- PKI TRAC Ticket #2380 - Pki-server instance commands throws exception while
  specifying invalid parameters. (edewata)
- PKI TRAC Ticket #2384 - CA installation with HSM prompts for HSM password
  during silent installation (edewata)
- PKI TRAC Ticket #2385 - Upgraded CA lacks ca.sslserver.certreq in CS.cfg
  (ftweedal)
- PKI TRAC Ticket #2387 - Add config for default OCSP URI if none given
  (ftweedal)
- PKI TRAC Ticket #2388 - CA creation responds 500 if certificate issuance
  fails (ftweedal)
- PKI TRAC Ticket #2389 - Installation: subsystem certs could have notAfter
  beyond CA signing cert in case of external or existing CA (cfu)
- PKI TRAC Ticket #2390 - Dogtag 10.3.4: Miscellaneous Enhancements
  (akasurde, edewata)

* Thu Jun 30 2016 Dogtag Team <pki-devel@redhat.com> 10.3.3-2
- PKI TRAC Ticket #2373 - Fedora 25: RestEasy 3.0.6 ==> 3.0.17 breaks
  pki-core (ftweedal)

* Mon Jun 20 2016 Dogtag Team <pki-devel@redhat.com> 10.3.3-1
- Updated release number to 10.3.3-1

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.3-0.1
- Updated version number to 10.3.3-0.1

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-5
- Provided cleaner runtime dependency separation

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-4
- Updated tomcatjss version dependencies

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-3
- Updated 'java', 'java-headless', and 'java-devel' dependencies to 1:1.8.0.

* Tue Jun  7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.2-2
- Updated tomcat version dependencies

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

* Fri Apr 8 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0.a2-2
- PKI TRAC Ticket #2255 - PKCS #12 backup does not contain trust attributes.

* Thu Apr 7 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0.a2-1
- Updated build for F24 alpha

* Wed Mar 23 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0.a1-2
- PKI TRAC Ticket #1625 - Allow multiple ACLs of same name
  (union of rules) [ftweedal]
- PKI TRAC Ticket #2237 - Add CRL dist points extension to OIDMap
  unconditionally [edewata]
- PKI TRAC Ticket #1803 - Removed unnecessary URL encoding for admin cert
  request. [edewata]
- PKI TRAC Ticket #1742 - Added support for cloning 3rd-party CA
  certificates. [edewata]
- PKI TRAC Ticket #1482 - Added TPS token filter dialog. [edewata]
- PKI TRAC Ticket #1808 - Fixed illegal token state transition
  via TEMP_LOST. [edewata]

* Fri Mar  4 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0.a1-1
- Build for F24 alpha

* Tue Mar 1 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0-0.5
- PKI Trac Ticket #1399 - Move java components out of pki-base

* Thu Feb 11 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0-0.4
- PKI TRAC Ticket #1850 - Rename DRMTool --> KRATool

* Thu Feb  4 2016 Dogtag Team <pki-devel@redhat.com> 10.3.0-0.3
- PKI TRAC Ticket #1714 - mod_revocator and mod_nss dependency for tps
  should be removed

* Sat Oct  3 2015 Dogtag Team <pki-devel@redhat.com> 10.3.0-0.2
- PKI TRAC Ticket #1623 - Runtime dependency on python-nss is missing

* Sat Aug  8 2015 Dogtag Team <pki-devel@redhat.com> 10.3.0-0.1
- Updated version number to 10.3.0-0.1

* Fri Aug  7 2015 Dogtag Team <pki-devel@redhat.com> 10.2.7-0.3
- Added dep on tomcat-servlet-3.1-api [Fedora 23 and later] or dep on
  tomcat-servlet-3.0-api [Fedora 22 and later] to pki-tools
- Updated dep on tomcatjss [Fedora 23 and later]

* Fri Jul 24 2015 Tomas Radej <tradej@redhat.com> - 10.2.7-0.2
- Updated dep on policycoreutils-python-utils [Fedora 23 and later]

* Sat Jul 18 2015 Dogtag Team <pki-devel@redhat.com> 10.2.7-0.1
- Updated version number to 10.2.7-0.1

* Sat Jul 18 2015 Dogtag Team <pki-devel@redhat.com> 10.2.6-1
- Update release number for release build

* Fri Jul 17 2015 Dogtag Team <pki-devel@redhat.com> 10.2.6-0.3
- Remove setup directory and remaining Perl dependencies

* Sat Jun 20 2015 Dogtag Team <pki-devel@redhat.com> 10.2.6-0.2
- Remove ExcludeArch directive

* Fri Jun 19 2015 Dogtag Team <pki-devel@redhat.com> 10.2.6-0.1
- Updated version number to 10.2.6-0.1

* Fri Jun 19 2015 Dogtag Team <pki-devel@redhat.com> 10.2.5-1
- Update release number for release build

* Wed Jun 17 2015 Dogtag Team <pki-devel@redhat.com> 10.2.5-0.2
- Resolves rhbz #1230970 - Errata TPS tests for rpm verification failed

* Tue May 26 2015 Dogtag Team <pki-devel@redhat.com> 10.2.5-0.1
- Updated version number to 10.2.5-0.1

* Tue May 26 2015 Dogtag Team <pki-devel@redhat.com> 10.2.4-1
- Update release number for release build

* Tue May 12 2015 Dogtag Team <pki-devel@redhat.com> 10.2.4-0.2
- Updated nuxwdog and tomcatjss requirements (alee)

* Thu Apr 23 2015 Dogtag Team <pki-devel@redhat.com> 10.2.4-0.1
- Updated version number to 10.2.4-0.1
- Added nuxwdog systemd files

* Thu Apr 23 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-1
- Update release number for release build

* Thu Apr  9 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-0.1
- Reverted version number back to 10.2.3-0.1
- Added support for Tomcat 8.

* Mon Apr  6 2015 Dogtag Team <pki-devel@redhat.com> 10.3.0-0.1
- Updated version number to 10.3.0-0.1

* Wed Mar 18 2015 Dogtag Team <pki-devel@redhat.com> 10.2.3-0.1
- Updated version number to 10.2.3-0.1

* Tue Mar 17 2015 Dogtag Team <pki-devel@redhat.com> 10.2.2-1
- Update release number for release build

* Thu Jan  8 2015 Dogtag Team <pki-devel@redhat.com> 10.2.2-0.1
- Updated version number to 10.2.2-0.1
- Moved web application deployment locations.
- Updated Resteasy and Jackson dependencies.
- Added missing python-lxml build dependency.

* Thu Jan  8 2015 Dogtag Team <pki-devel@redhat.com> 10.2.1-1
- Update release number for release build

* Tue Dec 16 2014 Matthew Harmsen <mharmsen@redhat.com> - 10.2.1-0.4
- PKI TRAC Ticket #1187 - mod_perl should be removed from requirements for 10.2
- PKI TRAC Ticket #1205 - Outdated selinux-policy dependency.
- Removed perl(XML::LibXML), perl-Crypt-SSLeay, and perl-Mozilla-LDAP runtime
  dependencies

* Fri Dec 12 2014 Ade Lee <alee@redhat.com> 10.2.1-0.3
- Change resteasy dependencies for F22+

* Mon Nov 24 2014 Christina Fu <cfu@redhat.com> 10.2.1-0.2
- Ticket 1198 Bugzilla 1158410 add TLS range support to server.xml by
  default and upgrade (cfu)
- PKI Trac Ticket #1211 - New release overwrites old source tarball (mharmsen)
- up the release number to 0.2

* Fri Oct 24 2014 Dogtag Team <pki-devel@redhat.com> 10.2.1-0.1
- Updated version number to 10.2.1-0.1.
- Added CLIs to simplify generating user certificates
- Added enhancements to KRA Python API
- Added a man page for pki ca-profile commands.
- Added python api docs

* Wed Oct 1 2014 Ade Lee <alee@redhat.com> 10.2.0-3
- Disable pylint dependency for RHEL builds
- Added jakarta-commons-httpclient requirements
- Added tomcat version for RHEL build
- Added resteasy-base-client for RHEL build

* Wed Sep 24 2014 Matthew Harmsen <mharmsen@redhat.com> - 10.2.0-2
- PKI TRAC Ticket #1130 - Add RHEL/CentOS conditionals to spec

* Wed Sep  3 2014 Dogtag Team <pki-devel@redhat.com> 10.2.0-1
- Update release number for release build

* Wed Sep  3 2014 Matthew Harmsen <mharmsen@redhat.com> - 10.2.0-0.10
- PKI TRAC Ticket #1017 - Rename pki-tps-tomcat to pki-tps

* Fri Aug 29 2014 Matthew Harmsen <mharmsen@redhat.com> - 10.2.0-0.9
- Merged jmagne@redhat.com's spec file changes from the stand-alone
  'pki-tps-client' package needed to build/run the native 'tpsclient'
  command line utility into this 'pki-core' spec file under the 'tps' package.
- Original tps libararies must be built to support this native utility.
- Modifies tps package from 'noarch' into 'architecture-specific' package

* Wed Aug 27 2014 Matthew Harmsen <mharmsen@redhat.com> - 10.2.0-0.8
- PKI TRAC Ticket #1127 - Remove 'pki-ra', 'pki-setup', and 'pki-silent'
  packages . . .

* Sun Aug 17 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 10.2.0-0.5
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_22_Mass_Rebuild

* Wed Aug 13 2014 Jack Magne <jmagne@redhat.com> - 10.2.0-0.7
- Respin to include the applet files with the rpm install. No change
  to spec file needed.

* Tue Jul 15 2014 Matthew Harmsen <mharmsen@redhat.com> - 10.2.0-0.6
- Bugzilla Bug #1120045 - pki-core: Switch to java-headless (build)requires --
  drop dependency on java-atk-wrapper
- Removed 'java-atk-wrapper' dependency from 'pki-server'

* Wed Jul 2 2014 Matthew Harmsen <mharmsen@redhat.com> - 10.2.0-0.5
- PKI TRAC Ticket #832 - Remove legacy 'systemctl' files . . .

* Tue Jul 1 2014 Ade Lee <alee@redhat.com> - 10.2.0-0.4
- Update rawhide build

* Sat Jun 07 2014 Fedora Release Engineering <rel-eng@lists.fedoraproject.org> - 10.2.0-0.3
- Rebuilt for https://fedoraproject.org/wiki/Fedora_21_Mass_Rebuild

* Fri Mar 28 2014 Michael Simacek <msimacek@redhat.com> - 10.2.0-0.2
- Use Requires: java-headless rebuild (#1067528)

* Fri Nov 22 2013 Dogtag Team <pki-devel@redhat.com> 10.2.0-0.1
- Added option to build without server packages.
- Replaced Jettison with Jackson.
- Added python-nss build requirement
- Bugzilla Bug #1057959 - pkispawn requires policycoreutils-python
- TRAC Ticket #840 - pkispawn requires policycoreutils-python
- Updated requirements for resteasy
- Added template files for archive, retrieve and generate key
  requests to the client package.

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

