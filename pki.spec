################################################################################
Name:             pki
################################################################################

Summary:          PKI Package
URL:              http://www.dogtagpki.org/
# The entire source code is GPLv2 except for 'pki-tps' which is LGPLv2
License:          GPLv2 and LGPLv2

Version:          10.6.8
Release:          1%{?_timestamp}%{?_commit_id}%{?dist}
# global           _phase -a1

# To create a tarball from a version tag:
# $ git archive \
#     --format=tar.gz \
#     --prefix pki-<version>/ \
#     -o pki-<version>.tar.gz \
#     <version tag>
Source: https://github.com/dogtagpki/pki/archive/v%{version}%{?_phase}/pki-%{version}%{?_phase}.tar.gz

# To create a patch for all changes since a version tag:
# $ git format-patch \
#     --stdout \
#     <version tag> \
#     > pki-VERSION-RELEASE.patch
# Patch: pki-VERSION-RELEASE.patch

################################################################################
# NSS
################################################################################

%if 0%{?rhel} && 0%{?rhel} <= 7 || 0%{?fedora} && 0%{?fedora} <= 27
%global nss_default_db_type dbm
%else
%global nss_default_db_type sql
%endif

################################################################################
# Python
################################################################################

# Python 2 packages
%if 0%{!?with_python2:1}
%if 0%{?rhel} && 0%{?rhel} <= 7 || 0%{?fedora} && 0%{?fedora} <= 28
%global with_python2 1
%else
# no python2
%endif
%endif

# Python 3 packages
%if 0%{!?with_python3:1}
%if 0%{?rhel} && 0%{?rhel} <= 7
# no python3
%else
%global with_python3 1
%endif
%endif

# Use Python 3 for all commands?
%if 0%{!?with_python3_default:1}
%if 0%{?rhel} && 0%{?rhel} <= 7 || 0%{?fedora} && 0%{?fedora} <= 27
%global with_python3_default 0
%else
%global with_python3_default 1
%endif
%endif

################################################################################
# Java
################################################################################

%define java_home %{_usr}/lib/jvm/jre-1.8.0-openjdk

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

# By default the build will execute unit tests unless --without test
# option is specified.

%bcond_without test

# By default all packages will be built except the ones specified with
# --without <package> option (exclusion method).

# If --with pkgs option is specified, only packages specified with
# --with <package> will be built (inclusion method).

%bcond_with pkgs

# Define package_option macro to wrap bcond_with or bcond_without macro
# depending on package selection method.

%if %{with pkgs}
%define package_option() %bcond_with %1
%else
%define package_option() %bcond_without %1
%endif # with pkgs

# Define --with <package> or --without <package> options depending on
# package selection method.

%package_option base
%package_option server
%package_option ca
%package_option kra
%package_option ocsp
%package_option tks
%package_option tps
%package_option javadoc
%package_option console
%package_option theme
%package_option meta
%package_option debug

%if ! %{with debug}
%define debug_package %{nil}
%endif # with debug

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

%global brand dogtag

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

################################################################################
# Build Dependencies
################################################################################

# autosetup
BuildRequires:    git
BuildRequires:    make

BuildRequires:    cmake >= 2.8.9-1
BuildRequires:    gcc-c++
BuildRequires:    zip
BuildRequires:    java-1.8.0-openjdk-devel
BuildRequires:    redhat-rpm-config
BuildRequires:    ldapjdk >= 4.20
BuildRequires:    apache-commons-cli
BuildRequires:    apache-commons-codec
BuildRequires:    apache-commons-io
BuildRequires:    apache-commons-lang
BuildRequires:    jakarta-commons-httpclient
BuildRequires:    glassfish-jaxb-api
BuildRequires:    slf4j
%if 0%{?rhel} && 0%{?rhel} <= 7
# no slf4j-jdk14
%else
BuildRequires:    slf4j-jdk14
%endif
BuildRequires:    nspr-devel
BuildRequires:    nss-devel >= 3.36.1

BuildRequires:    openldap-devel
BuildRequires:    pkgconfig
BuildRequires:    policycoreutils

%if 0%{?rhel} && 0%{?rhel} <= 7
BuildRequires:    python-lxml
BuildRequires:    python-sphinx
%else
%if 0%{?fedora} && 0%{?fedora} <= 28
BuildRequires:    python2-lxml
BuildRequires:    python2-sphinx
%else
BuildRequires:    python3-lxml
BuildRequires:    python3-sphinx
%endif
%endif

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
BuildRequires:    resteasy-jackson2-provider >= 3.0.17-1
%endif

%if 0%{?with_python2}
%if 0%{?rhel}
# no pylint
%else
BuildRequires:    pylint
%if 0%{?fedora} && 0%{?fedora} <= 27
BuildRequires:    python-flake8 >= 2.5.4
BuildRequires:    pyflakes >= 1.2.3
%else
BuildRequires:    python2-flake8 >= 2.5.4
BuildRequires:    python2-pyflakes >= 1.2.3
%endif
%endif
%endif  # with_python2

%if 0%{?with_python3}
%if 0%{?rhel}
# no pylint
%else
BuildRequires:    python3-pylint
BuildRequires:    python3-flake8 >= 2.5.4
BuildRequires:    python3-pyflakes >= 1.2.3
%endif
%endif  # with_python3

%if 0%{?with_python2}
BuildRequires:    python2
BuildRequires:    python2-devel
BuildRequires:    python2-cryptography
%if 0%{?rhel} && 0%{?rhel} <= 7 || 0%{?fedora} && 0%{?fedora} <= 27
BuildRequires:    python-nss
BuildRequires:    python-requests >= 2.6.0
BuildRequires:    python-six
BuildRequires:    libselinux-python
BuildRequires:    policycoreutils-python
BuildRequires:    python-ldap
%else
BuildRequires:    python2-nss
BuildRequires:    python2-requests >= 2.6.0
BuildRequires:    python2-six
BuildRequires:    python2-libselinux
BuildRequires:    python2-policycoreutils
BuildRequires:    python2-ldap
%endif
%if 0%{?rhel} && 0%{?rhel} <= 7
# no policycoreutils-python-utils
%else
BuildRequires:    policycoreutils-python-utils
%endif
%endif  # with_python2

%if 0%{?with_python3}
BuildRequires:    python3
BuildRequires:    python3-devel
BuildRequires:    python3-cryptography
BuildRequires:    python3-lxml
%if 0%{?rhel} && 0%{?rhel} <= 7 || 0%{?fedora} && 0%{?fedora} <= 27
BuildRequires:    python3-pyldap
# no python3-libselinux
%else
BuildRequires:    python3-ldap
BuildRequires:    python3-libselinux
%endif
BuildRequires:    python3-nss
BuildRequires:    python3-requests >= 2.6.0
BuildRequires:    python3-six
%endif  # with_python3

BuildRequires:    junit
BuildRequires:    jpackage-utils >= 0:1.7.5-10
%if 0%{?rhel} && 0%{?rhel} <= 7
BuildRequires:    jss >= 4.4.0-11
BuildRequires:    tomcatjss >= 7.2.1-4
%else
BuildRequires:    jss >= 4.5.0-1
BuildRequires:    tomcatjss >= 7.3.6
%endif
BuildRequires:    systemd-units

%if 0%{?rhel} && 0%{?rhel} <= 7
BuildRequires:    tomcat >= 7.0.69
%else
%if 0%{?fedora} && 0%{?fedora} <= 27
BuildRequires:    tomcat >= 8.0.49
%else
%if 0%{?fedora} && 0%{?fedora} <= 28
BuildRequires:    tomcat >= 1:8.5.23
%else
BuildRequires:    tomcat >= 1:9.0.7
%endif
%endif
%endif

# additional build requirements needed to build native 'tpsclient'
# REMINDER:  Revisit these once 'tpsclient' is rewritten as a Java app
BuildRequires:    apr-devel
BuildRequires:    apr-util-devel
BuildRequires:    cyrus-sasl-devel
BuildRequires:    httpd-devel >= 2.4.2
BuildRequires:    pcre-devel
BuildRequires:    systemd
BuildRequires:    zlib
BuildRequires:    zlib-devel

# description for top-level package (if there is a separate meta package)
%if "%{name}" != "%{brand}-pki"
%description

Dogtag PKI is an enterprise software system designed
to manage enterprise Public Key Infrastructure deployments.

PKI consists of the following components:

  * Certificate Authority (CA)
  * Key Recovery Authority (KRA)
  * Online Certificate Status Protocol (OCSP) Manager
  * Token Key Service (TKS)
  * Token Processing Service (TPS)

%endif

%if %{with meta}
%if "%{name}" != "%{brand}-pki"
################################################################################
%package -n       %{brand}-pki
################################################################################

Summary:          Dogtag PKI Package
%endif

# Make certain that this 'meta' package requires the latest version(s)
# of ALL PKI theme packages
Requires:         %{brand}-pki-server-theme >= %{version}
Requires:         %{brand}-pki-console-theme >= %{version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL PKI core packages
Requires:         pki-base-java >= %{version}
%if 0%{?with_python3}
Requires:         pki-base-python3 >= %{version}
%endif
Requires:         pki-tools >= %{version}
Requires:         pki-server >= %{version}
Requires:         pki-ca >= %{version}
Requires:         pki-kra >= %{version}
Requires:         pki-ocsp >= %{version}
Requires:         pki-tks >= %{version}
Requires:         pki-tps >= %{version}

# Make certain that this 'meta' package requires the latest version(s)
# of PKI console
Requires:         pki-console >= %{version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL PKI clients
%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:         esc >= 1.1.0
%else
Requires:         esc >= 1.1.1
%endif

# description for top-level package (unless there is a separate meta package)
%if "%{name}" == "%{brand}-pki"
%description
%else
%description -n   %{brand}-pki
%endif

Dogtag PKI is an enterprise software system designed
to manage enterprise Public Key Infrastructure deployments.

PKI consists of the following components:

  * Certificate Authority (CA)
  * Key Recovery Authority (KRA)
  * Online Certificate Status Protocol (OCSP) Manager
  * Token Key Service (TKS)
  * Token Processing Service (TPS)

%endif # with meta

%if %{with base}
################################################################################
%package -n       pki-symkey
################################################################################

Summary:          PKI Symmetric Key Package

Requires:         java-1.8.0-openjdk-headless
Requires:         jpackage-utils >= 0:1.7.5-10
%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:         jss >= 4.4.0-11
%else
Requires:         jss >= 4.5.0-1
%endif
Requires:         nss >= 3.38.0

%description -n   pki-symkey
The PKI Symmetric Key Java Package supplies various native
symmetric key operations to Java programs.

################################################################################
%package -n       pki-base
################################################################################

Summary:          PKI Base Package
BuildArch:        noarch

Requires:         nss >= 3.36.1
%if 0%{?with_python3_default}
Requires:         python3-pki = %{version}-%{release}
Requires(post):   python3-pki = %{version}-%{release}
%else
Requires:         python2-pki = %{version}-%{release}
Requires(post):   python2-pki = %{version}-%{release}
%endif  # with_python3_default

%description -n   pki-base
The PKI Base Package contains the common and client libraries and utilities
written in Python.

%if 0%{?with_python2}
################################################################################
%package -n       python2-pki
################################################################################

Summary:          PKI Python 2 Package
BuildArch:        noarch

Obsoletes:        pki-base-python2 < %{version}
Provides:         pki-base-python2 = %{version}-%{release}
%if 0%{?fedora}
%{?python_provide:%python_provide python2-pki}
%endif

Requires:         pki-base >= %{version}-%{release}
Requires:         python2-cryptography
%if 0%{?rhel} && 0%{?rhel} <= 7 || 0%{?fedora} && 0%{?fedora} <= 27
Requires:         python-nss
Requires:         python-requests >= 2.6.0
Requires:         python-six
%else
Requires:         python2-nss
Requires:         python2-requests >= 2.6.0
Requires:         python2-six
%endif

%description -n   python2-pki
This package contains PKI client library for Python 2.

%endif  # with_python2

%if 0%{?with_python3}
################################################################################
%package -n       python3-pki
################################################################################

Summary:          PKI Python 3 Package
BuildArch:        noarch

Obsoletes:        pki-base-python3 < %{version}
Provides:         pki-base-python3 = %{version}-%{release}
%if 0%{?fedora}
%{?python_provide:%python_provide python3-pki}
%endif

Requires:         pki-base >= %{version}-%{release}
Requires:         python3-cryptography
Requires:         python3-lxml
Requires:         python3-nss
Requires:         python3-requests >= 2.6.0
Requires:         python3-six

%description -n   python3-pki
This package contains PKI client library for Python 3.

%endif  # with_python3 for python3-pki

################################################################################
%package -n       pki-base-java
################################################################################

Summary:          PKI Base Java Package
BuildArch:        noarch

Requires:         java-1.8.0-openjdk-headless
Requires:         apache-commons-cli
Requires:         apache-commons-codec
Requires:         apache-commons-io
Requires:         apache-commons-lang
Requires:         apache-commons-logging
Requires:         jakarta-commons-httpclient
Requires:         glassfish-jaxb-api
Requires:         slf4j
%if 0%{?rhel} && 0%{?rhel} <= 7
# no slf4j-jdk14
%else
Requires:         slf4j-jdk14
%endif
Requires:         javassist
Requires:         jpackage-utils >= 0:1.7.5-10
%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:         jss >= 4.4.0-11
%else
Requires:         jss >= 4.5.0-1
%endif
Requires:         ldapjdk >= 4.20
Requires:         pki-base >= %{version}-%{release}

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
Requires:         resteasy-jackson2-provider >= 3.0.17-1
%endif

Requires:         xalan-j2
Requires:         xerces-j2
Requires:         xml-commons-apis
Requires:         xml-commons-resolver

%description -n   pki-base-java
The PKI Base Java Package contains the common and client libraries and utilities
written in Java.

################################################################################
%package -n       pki-tools
################################################################################

Summary:          PKI Tools Package

Requires:         openldap-clients
Requires:         nss-tools >= 3.36.1
Requires:         pki-base-java >= %{version}-%{release}

%description -n   pki-tools
This package contains PKI executables that can be used to help make
Certificate System into a more complete and robust PKI solution.

%endif # with base

%if %{with server}
################################################################################
%package -n       pki-server
################################################################################

Summary:          PKI Server Package
BuildArch:        noarch

Requires:         hostname
Requires:         net-tools

Requires:         policycoreutils
Requires:         procps-ng
Requires:         openldap-clients
%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:         openssl >= 1.0.2k-11
%else
Requires:         openssl
%endif
Requires:         pki-symkey >= %{version}-%{release}
Requires:         pki-base-java >= %{version}-%{release}
Requires:         pki-tools >= %{version}-%{release}

%if 0%{?rhel} && 0%{?rhel} <= 7
# no policycoreutils-python-utils
%else
Requires:         policycoreutils-python-utils
%endif

%if 0%{?with_python3_default}
%if 0%{?fedora} && 0%{?fedora} <= 27
Requires:         python3-pyldap
%else
Requires:         python3-ldap
%endif
Requires:         python3-lxml
Requires:         python3-libselinux
Requires:         python3-policycoreutils
%else
%if 0%{?rhel} && 0%{?rhel} <= 7 || 0%{?fedora} && 0%{?fedora} <= 27
Requires:         python-ldap
Requires:         python-lxml
Requires:         libselinux-python
Requires:         policycoreutils-python
%else
Requires:         python2-ldap
Requires:         python2-lxml
Requires:         python2-libselinux
Requires:         python2-policycoreutils
%endif
%endif  # with_python3_default

Requires:         selinux-policy-targeted >= 3.13.1-159

%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:         tomcat >= 7.0.69
%else
%if 0%{?fedora} && 0%{?fedora} <= 27
Requires:         tomcat >= 8.0.49
%else
%if 0%{?fedora} && 0%{?fedora} <= 28
Requires:         tomcat >= 1:8.5.23
%else
Requires:         tomcat >= 1:9.0.7
%endif
%endif
%endif

Requires:         velocity
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units
Requires(pre):    shadow-utils
%if 0%{?rhel} && 0%{?rhel} <= 7
Requires:         tomcatjss >= 7.2.1-4
%else
Requires:         tomcatjss >= 7.3.6
%endif

# https://pagure.io/freeipa/issue/7742
Conflicts:        freeipa-server < 4.7.1

%description -n   pki-server
The PKI Server Package contains libraries and utilities needed by the
following PKI subsystems:

    the Certificate Authority (CA),
    the Key Recovery Authority (KRA),
    the Online Certificate Status Protocol (OCSP) Manager,
    the Token Key Service (TKS), and
    the Token Processing Service (TPS).

%endif # with server

%if %{with ca}
################################################################################
%package -n       pki-ca
################################################################################

Summary:          PKI CA Package
BuildArch:        noarch

Requires:         pki-server >= %{version}-%{release}
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

%endif # with ca

%if %{with kra}
################################################################################
%package -n       pki-kra
################################################################################

Summary:          PKI KRA Package
BuildArch:        noarch

Requires:         pki-server >= %{version}-%{release}
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

%endif # with kra

%if %{with ocsp}
################################################################################
%package -n       pki-ocsp
################################################################################

Summary:          PKI OCSP Package
BuildArch:        noarch

Requires:         pki-server >= %{version}-%{release}
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

%endif # with ocsp

%if %{with tks}
################################################################################
%package -n       pki-tks
################################################################################

Summary:          PKI TKS Package
BuildArch:        noarch

Requires:         pki-server >= %{version}-%{release}
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

%endif # with tks

%if %{with tps}
################################################################################
%package -n       pki-tps
################################################################################

Summary:          PKI TPS Package

Requires:         pki-server >= %{version}-%{release}
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units

# additional runtime requirements needed to run native 'tpsclient'
# REMINDER:  Revisit these once 'tpsclient' is rewritten as a Java app

Requires:         nss-tools >= 3.36.1
Requires:         openldap-clients

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

%endif # with tps

%if %{with javadoc}
################################################################################
%package -n       pki-javadoc
################################################################################

Summary:          PKI Javadoc Package
BuildArch:        noarch

%description -n   pki-javadoc
This package contains PKI API documentation.

%endif # with javadoc

%if %{with console}
################################################################################
%package -n       pki-console
################################################################################

Summary:          PKI Console Package
BuildArch:        noarch

BuildRequires:    idm-console-framework >= 1.2.0

Requires:         idm-console-framework >= 1.2.0
Requires:         pki-base-java >= %{version}
Requires:         pki-console-theme >= %{version}

%description -n   pki-console
The PKI Console is a Java application used to administer PKI server.

%endif # with console

%if %{with theme}
################################################################################
%package -n       %{brand}-pki-server-theme
################################################################################

Summary:          Dogtag PKI Server Theme Package
BuildArch:        noarch

Provides:         pki-server-theme = %{version}-%{release}

%description -n   %{brand}-pki-server-theme
This PKI Server Theme Package contains
Dogtag textual and graphical user interface for PKI Server.

################################################################################
%package -n       %{brand}-pki-console-theme
################################################################################

Summary:          Dogtag PKI Console Theme Package
BuildArch:        noarch

Provides:         pki-console-theme = %{version}-%{release}

%description -n   %{brand}-pki-console-theme
This PKI Console Theme Package contains
Dogtag textual and graphical user interface for PKI Console.

%endif # with theme

################################################################################
%prep
################################################################################

%autosetup -n pki-%{version}%{?_phase} -p 1 -S git

################################################################################
%build
################################################################################

# get Tomcat <major>.<minor> version number
tomcat_version=`/usr/sbin/tomcat version | sed -n 's/Server number: *\([0-9]\+\.[0-9]\+\).*/\1/p'`

if [ $tomcat_version == "9.0" ]; then
    app_server=tomcat-8.5
else
    app_server=tomcat-$tomcat_version
fi

%{__mkdir_p} build
cd build
%cmake \
    --no-warn-unused-cli \
    -DVERSION=%{version}-%{release} \
    -DVAR_INSTALL_DIR:PATH=/var \
    -DJAVA_HOME=%{java_home} \
    -DJAVA_LIB_INSTALL_DIR=%{_jnidir} \
    -DSYSTEMD_LIB_INSTALL_DIR=%{_unitdir} \
    -DAPP_SERVER=$app_server \
    -DJAXRS_API_JAR=%{jaxrs_api_jar} \
    -DRESTEASY_LIB=%{resteasy_lib} \
    -DNSS_DEFAULT_DB_TYPE=%{nss_default_db_type} \
    -DBUILD_PKI_CORE:BOOL=ON \
    -DWITH_PYTHON2:BOOL=%{?with_python2:ON}%{!?with_python2:OFF} \
    -DWITH_PYTHON3:BOOL=%{?with_python3:ON}%{!?with_python3:OFF} \
%if 0%{?with_python3_default}
    -DWITH_PYTHON3_DEFAULT:BOOL=ON \
%endif
    -DPYTHON_EXECUTABLE=%{__python3} \
    -DWITH_TEST:BOOL=%{?with_test:ON}%{!?with_test:OFF} \
%if ! %{with server} && ! %{with ca} && ! %{with kra} && ! %{with ocsp} && ! %{with tks} && ! %{with tps}
    -DWITH_SERVER:BOOL=OFF \
%endif
    -DWITH_JAVADOC:BOOL=%{?with_javadoc:ON}%{!?with_javadoc:OFF} \
    -DBUILD_PKI_CONSOLE:BOOL=%{?with_console:ON}%{!?with_console:OFF} \
    -DTHEME=%{?with_theme:%{brand}} \
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
    all install

%if %{with meta}
%{__mkdir_p} %{buildroot}%{_datadir}/doc/pki

cat > %{buildroot}%{_datadir}/doc/pki/README << EOF
This package is a "meta-package" whose dependencies pull in all of the
packages comprising the Dogtag Public Key Infrastructure (PKI) Suite.
EOF
%endif # with meta

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
%if 0%{?rhel} && 0%{?rhel} <= 7
# no link customization
%else
    rm -f %{buildroot}%{_datadir}/pki/lib/scannotation.jar
    ln -sf /usr/share/java/jboss-logging/jboss-logging.jar %{buildroot}%{_datadir}/pki/lib/jboss-logging.jar
    ln -sf /usr/share/java/jboss-annotations-1.2-api/jboss-annotations-api_1.2_spec.jar %{buildroot}%{_datadir}/pki/lib/jboss-annotations-api_1.2_spec.jar
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

# Customize server common library links in /usr/share/pki/server/common/lib
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

# Customize server library links in /usr/share/pki/server/lib
%if 0%{?rhel} && 0%{?rhel} <= 7
    rm -f %{buildroot}%{_datadir}/pki/server/lib/slf4j-jdk14.jar
%endif

%if 0%{?rhel}
# no pylint
%else

################################################################################
echo "Scanning Python code with pylint"
################################################################################

%if 0%{?with_python3_default}
%{__python3} ../tools/pylint-build-scan.py rpm --prefix %{buildroot}
if [ $? -ne 0 ]; then
    echo "pylint for Python 3 failed. RC: $?"
    exit 1
fi
%else
%{__python2} ../tools/pylint-build-scan.py rpm --prefix %{buildroot}
if [ $? -ne 0 ]; then
    echo "pylint for Python 2 failed. RC: $?"
    exit 1
fi

%{__python2} ../tools/pylint-build-scan.py rpm --prefix %{buildroot} -- --py3k
if [ $? -ne 0 ]; then
    echo "pylint for Python 2 with --py3k failed. RC: $?"
    exit 1
fi
%endif  # with_python3_default

################################################################################
echo "Scanning Python code with flake8"
################################################################################

%if 0%{?with_python2}
flake8 --config ../tox.ini %{buildroot}
if [ $? -ne 0 ]; then
    echo "flake8 for Python 2 failed. RC: $?"
    exit 1
fi
%endif  # with_python2

%if 0%{?with_python3}
python3-flake8 --config ../tox.ini %{buildroot}
if [ $? -ne 0 ]; then
    echo "flake8 for Python 3 failed. RC: $?"
    exit 1
fi
%endif  # with_python3

%endif

%endif # with server

%if %{with base}

%if 0%{?rhel} && 0%{?rhel} <= 7
# no upgrade check
%else
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
         "http://www.dogtagpki.org/wiki/Migrating_PKI_9_Instances_to_PKI_10"
   error(msg)
end
%endif

%endif # with base

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

%endif # with server

%if %{with base}

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

%endif # with base

%if %{with server}

%post -n pki-server
## NOTE:  At this time, NO attempt has been made to update ANY PKI subsystem
##        from EITHER 'sysVinit' OR previous 'systemd' processes to the new
##        PKI deployment process

echo "Upgrading PKI server configuration at `/bin/date`." >> /var/log/pki/pki-server-upgrade-%{version}.log 2>&1
/sbin/pki-server-upgrade --silent >> /var/log/pki/pki-server-upgrade-%{version}.log 2>&1
echo >> /var/log/pki/pki-server-upgrade-%{version}.log 2>&1

# Reload systemd daemons on upgrade only
if [ "$1" == "2" ]
then
    systemctl daemon-reload
fi

## preun -n pki-server
## NOTE:  At this time, NO attempt has been made to update ANY PKI subsystem
##        from EITHER 'sysVinit' OR previous 'systemd' processes to the new
##        PKI deployment process


## postun -n pki-server
## NOTE:  At this time, NO attempt has been made to update ANY PKI subsystem
##        from EITHER 'sysVinit' OR previous 'systemd' processes to the new
##        PKI deployment process

%endif # with server

%if %{with meta}
%if "%{name}" != "%{brand}-pki"
################################################################################
%files -n %{brand}-pki
################################################################################
%else
%files
%endif

%doc %{_datadir}/doc/pki/README

%endif # with meta

%if %{with base}
################################################################################
%files -n pki-symkey
################################################################################

%doc base/symkey/LICENSE
%{_jnidir}/symkey.jar
%{_libdir}/symkey/

################################################################################
%files -n pki-base
################################################################################

%doc base/common/LICENSE
%doc base/common/LICENSE.LESSER
%doc %{_datadir}/doc/pki-base/html
%dir %{_datadir}/pki
%{_datadir}/pki/VERSION
%dir %{_datadir}/pki/etc
%{_datadir}/pki/etc/pki.conf
%{_datadir}/pki/etc/logging.properties
%dir %{_datadir}/pki/scripts
%{_datadir}/pki/scripts/config
%{_datadir}/pki/upgrade/
%{_datadir}/pki/key/templates
%dir %{_sysconfdir}/pki
%config(noreplace) %{_sysconfdir}/pki/pki.conf
%dir %{_localstatedir}/log/pki
%{_sbindir}/pki-upgrade
%{_mandir}/man1/pki-python-client.1.gz
%{_mandir}/man5/pki-logging.5.gz
%{_mandir}/man8/pki-upgrade.8.gz

%if 0%{?with_python2}
################################################################################
%files -n python2-pki
################################################################################

%doc base/common/LICENSE
%doc base/common/LICENSE.LESSER
%if %{with server} && ! %{?with_python3_default}
%exclude %{python2_sitelib}/pki/server
%endif
%{python2_sitelib}/pki
%endif # with_python2

################################################################################
%files -n pki-base-java
################################################################################

%doc base/common/LICENSE
%doc base/common/LICENSE.LESSER
%{_datadir}/pki/examples/java/
%{_datadir}/pki/lib/
%dir %{_javadir}/pki
%{_javadir}/pki/pki-cmsutil.jar
%{_javadir}/pki/pki-nsutil.jar
%{_javadir}/pki/pki-certsrv.jar

%if 0%{?with_python3}
################################################################################
%files -n python3-pki
################################################################################

%doc base/common/LICENSE
%doc base/common/LICENSE.LESSER
%if %{with server} && %{?with_python3_default}
%exclude %{python3_sitelib}/pki/server
%endif
%{python3_sitelib}/pki
%endif # with_python3

################################################################################
%files -n pki-tools
################################################################################

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
%{_mandir}/man1/CMCRequest.1.gz
%{_mandir}/man1/CMCSharedToken.1.gz
%{_mandir}/man1/CMCResponse.1.gz
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

%endif # with base

%if %{with server}
################################################################################
%files -n pki-server
################################################################################

%doc base/common/THIRD_PARTY_LICENSES
%doc base/server/LICENSE
%doc base/server/README
%attr(755,-,-) %dir %{_sysconfdir}/sysconfig/pki
%attr(755,-,-) %dir %{_sysconfdir}/sysconfig/pki/tomcat
%{_sbindir}/pkispawn
%{_sbindir}/pkidestroy
%{_sbindir}/pki-server
%{_sbindir}/pki-server-upgrade
%if 0%{?with_python3_default}
%{python3_sitelib}/pki/server/
%else
%{python2_sitelib}/pki/server/
%endif  # with_python3_default

%{_datadir}/pki/etc/tomcat.conf
%dir %{_datadir}/pki/deployment
%{_datadir}/pki/deployment/config/
%{_datadir}/pki/scripts/operations
%{_bindir}/pkidaemon
%{_bindir}/pki-server-nuxwdog
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
%{_mandir}/man8/pki-server-ca.8.gz
%{_mandir}/man8/pki-server-kra.8.gz
%{_mandir}/man8/pki-server-ocsp.8.gz
%{_mandir}/man8/pki-server-tks.8.gz
%{_mandir}/man8/pki-server-tps.8.gz
%{_datadir}/pki/setup/
%{_datadir}/pki/server/

%endif # with server

%if %{with ca}
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

%endif # with ca

%if %{with kra}
################################################################################
%files -n pki-kra
################################################################################

%doc base/kra/LICENSE
%{_javadir}/pki/pki-kra.jar
%dir %{_datadir}/pki/kra
%{_datadir}/pki/kra/conf/
%{_datadir}/pki/kra/setup/
%{_datadir}/pki/kra/webapps/

%endif # with kra

%if %{with ocsp}
################################################################################
%files -n pki-ocsp
################################################################################

%doc base/ocsp/LICENSE
%{_javadir}/pki/pki-ocsp.jar
%dir %{_datadir}/pki/ocsp
%{_datadir}/pki/ocsp/conf/
%{_datadir}/pki/ocsp/setup/
%{_datadir}/pki/ocsp/webapps/

%endif # with ocsp

%if %{with tks}
################################################################################
%files -n pki-tks
################################################################################

%doc base/tks/LICENSE
%{_javadir}/pki/pki-tks.jar
%dir %{_datadir}/pki/tks
%{_datadir}/pki/tks/conf/
%{_datadir}/pki/tks/setup/
%{_datadir}/pki/tks/webapps/

%endif # with tks

%if %{with tps}
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

%endif # with tps

%if %{with javadoc}
################################################################################
%files -n pki-javadoc
################################################################################

%{_javadocdir}/pki-%{version}/

%endif # with javadoc

%if %{with console}
################################################################################
%files -n pki-console
################################################################################

%doc base/console/LICENSE
%{_bindir}/pkiconsole
%{_javadir}/pki/pki-console.jar

%endif # with console

%if %{with theme}
################################################################################
%files -n %{brand}-pki-server-theme
################################################################################

%doc themes/%{brand}/common-ui/LICENSE
%dir %{_datadir}/pki
%{_datadir}/pki/CS_SERVER_VERSION
%{_datadir}/pki/common-ui/
%{_datadir}/pki/server/webapps/pki/ca
%{_datadir}/pki/server/webapps/pki/css
%{_datadir}/pki/server/webapps/pki/esc
%{_datadir}/pki/server/webapps/pki/fonts
%{_datadir}/pki/server/webapps/pki/images
%{_datadir}/pki/server/webapps/pki/kra
%{_datadir}/pki/server/webapps/pki/ocsp
%{_datadir}/pki/server/webapps/pki/pki.properties
%{_datadir}/pki/server/webapps/pki/tks

################################################################################
%files -n %{brand}-pki-console-theme
################################################################################

%doc themes/%{brand}/console-ui/LICENSE
%{_javadir}/pki/pki-console-theme.jar

%endif # with theme

################################################################################
%changelog
* Tue Mar 6 2018 Dogtag PKI Team <pki-devel@redhat.com> 10.6.0-0
- To list changes in <branch> since <tag>:
  $ git log --pretty=oneline --abbrev-commit --no-decorate <tag>..<branch>
