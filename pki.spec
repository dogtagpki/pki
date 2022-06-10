################################################################################
Name:             pki
################################################################################

%global           product_name Dogtag PKI
%global           product_id dogtag-pki
%global           theme dogtag

# Upstream version number:
%global           major_version 11
%global           minor_version 3
%global           update_version 0

# Downstream release number:
# - development/stabilization (unsupported): 0.<n> where n >= 1
# - GA/update (supported): <n> where n >= 1
%global           release_number 0.1

# Development phase:
# - development (unsupported): alpha<n> where n >= 1
# - stabilization (unsupported): beta<n> where n >= 1
# - GA/update (supported): <none>
%global           phase alpha1

%undefine         timestamp
%undefine         commit_id

Summary:          %{product_name} Package
URL:              https://www.dogtagpki.org
# The entire source code is GPLv2 except for 'pki-tps' which is LGPLv2
License:          GPLv2 and LGPLv2
Version:          %{major_version}.%{minor_version}.%{update_version}
Release:          %{release_number}%{?phase:.}%{?phase}%{?timestamp:.}%{?timestamp}%{?commit_id:.}%{?commit_id}%{?dist}

# To create a tarball from a version tag:
# $ git archive \
#     --format=tar.gz \
#     --prefix pki-<version>/ \
#     -o pki-<version>.tar.gz \
#     <version tag>
Source: https://github.com/dogtagpki/pki/archive/v%{version}%{?phase:-}%{?phase}/pki-%{version}%{?phase:-}%{?phase}.tar.gz

# To create a patch for all changes since a version tag:
# $ git format-patch \
#     --stdout \
#     <version tag> \
#     > pki-VERSION-RELEASE.patch
# Patch: pki-VERSION-RELEASE.patch

# Java 17 and md2man are not available on i686
ExcludeArch: i686

################################################################################
# Python
################################################################################

%global python_executable /usr/bin/python3

################################################################################
# Java
################################################################################

%define java_devel java-17-openjdk-devel
%define java_headless java-17-openjdk-headless
%define java_home %{_jvmdir}/jre-17-openjdk

################################################################################
# PKI
################################################################################

# Execute unit tests unless --without test is specified.
%bcond_without test

# Build the package unless --without <package> is specified.

%bcond_without base
%bcond_without server
%bcond_without acme
%bcond_without ca
%bcond_without kra
%bcond_without ocsp
%bcond_without tks
%bcond_without tps
%bcond_without javadoc
%bcond_without theme
%bcond_without meta
%bcond_without tests
%bcond_without debug

# Don't build console unless --with console is specified.
%bcond_with console

%if ! %{with debug}
%define debug_package %{nil}
%endif

# ignore unpackaged files from native 'tpsclient'
# REMINDER:  Remove this '%%define' once 'tpsclient' is rewritten as a Java app
%define _unpackaged_files_terminate_build 0

# The PKI UID and GID are preallocated, see:
# https://bugzilla.redhat.com/show_bug.cgi?id=476316
# https://bugzilla.redhat.com/show_bug.cgi?id=476782
# https://pagure.io/setup/blob/master/f/uidgid
# /usr/share/doc/setup/uidgid
%define pki_username pkiuser
%define pki_uid 17
%define pki_groupname pkiuser
%define pki_gid 17
%define pki_homedir /usr/share/pki

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

BuildRequires:    make
BuildRequires:    cmake >= 3.0.2
BuildRequires:    gcc-c++
BuildRequires:    zip
BuildRequires:    %{java_devel}
BuildRequires:    javapackages-tools
BuildRequires:    redhat-rpm-config
BuildRequires:    apache-commons-cli
BuildRequires:    apache-commons-codec
BuildRequires:    apache-commons-io
BuildRequires:    apache-commons-lang3 >= 3.2
BuildRequires:    apache-commons-logging
BuildRequires:    apache-commons-net
BuildRequires:    slf4j
BuildRequires:    slf4j-jdk14
BuildRequires:    nspr-devel
BuildRequires:    nss-devel >= 3.36.1

BuildRequires:    openldap-devel
BuildRequires:    pkgconfig
BuildRequires:    policycoreutils

BuildRequires:    python3-lxml
BuildRequires:    python3-sphinx

BuildRequires:    resteasy >= 3.0.26

BuildRequires:    python3 >= 3.9
BuildRequires:    python3-devel
BuildRequires:    python3-setuptools
BuildRequires:    python3-cryptography
BuildRequires:    python3-lxml
BuildRequires:    python3-ldap
BuildRequires:    python3-libselinux
BuildRequires:    python3-requests >= 2.6.0
BuildRequires:    python3-six

BuildRequires:    junit
BuildRequires:    jpackage-utils >= 0:1.7.5-10
BuildRequires:    jss >= 5.2
BuildRequires:    tomcatjss >= 8.2
BuildRequires:    ldapjdk >= 5.2

BuildRequires:    systemd-units

%if 0%{?rhel} && ! 0%{?eln}
BuildRequires:    pki-servlet-engine >= 9.0.31
%else
BuildRequires:    tomcat >= 1:9.0.31
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

# build dependency to build man pages
BuildRequires:    golang-github-cpuguy83-md2man

# pki-healthcheck depends on the following library
%if 0%{?rhel}
BuildRequires:    ipa-healthcheck-core
%else
BuildRequires:    freeipa-healthcheck-core
%endif

# PKICertImport depends on certutil and openssl
BuildRequires:    nss-tools
BuildRequires:    openssl

# description for top-level package (if there is a separate meta package)
%if "%{name}" != "%{product_id}"
%description

%{product_name} is an enterprise software system designed
to manage enterprise Public Key Infrastructure deployments.

%{product_name} consists of the following components:

  * Automatic Certificate Management Environment (ACME) Responder
  * Certificate Authority (CA)
  * Key Recovery Authority (KRA)
  * Online Certificate Status Protocol (OCSP) Manager
  * Token Key Service (TKS)
  * Token Processing Service (TPS)

%endif

%if %{with meta}
%if "%{name}" != "%{product_id}"
################################################################################
%package -n       %{product_id}
################################################################################

Summary:          %{product_name} Package
%endif

Obsoletes:        pki-symkey < %{version}
Obsoletes:        %{product_id}-symkey < %{version}
Obsoletes:        pki-console < %{version}
Obsoletes:        pki-console-theme < %{version}
Obsoletes:        idm-console-framework < 2.0

# Make certain that this 'meta' package requires the latest version(s)
# of ALL PKI theme packages
Requires:         %{product_id}-theme = %{version}-%{release}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL PKI core packages
Requires:         %{product_id}-acme = %{version}-%{release}
Requires:         %{product_id}-ca = %{version}-%{release}
Requires:         %{product_id}-kra = %{version}-%{release}
Requires:         %{product_id}-ocsp = %{version}-%{release}
Requires:         %{product_id}-tks = %{version}-%{release}
Requires:         %{product_id}-tps = %{version}-%{release}

Requires:         %{product_id}-javadoc = %{version}-%{release}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL PKI clients -- except for s390/s390x where 'esc' is not built
%ifnarch s390 s390x
Requires:         esc >= 1.1.1
%endif

# description for top-level package (unless there is a separate meta package)
%if "%{name}" == "%{product_id}"
%description
%else
%description -n   %{product_id}
%endif

%{product_name} is an enterprise software system designed
to manage enterprise Public Key Infrastructure deployments.

%{product_name} consists of the following components:

  * Automatic Certificate Management Environment (ACME) Responder
  * Certificate Authority (CA)
  * Key Recovery Authority (KRA)
  * Online Certificate Status Protocol (OCSP) Manager
  * Token Key Service (TKS)
  * Token Processing Service (TPS)

# with meta
%endif

%if %{with base}
################################################################################
%package -n       %{product_id}-base
################################################################################

Summary:          %{product_name} Base Package
BuildArch:        noarch

Obsoletes:        pki-base < %{version}-%{release}
Provides:         pki-base = %{version}-%{release}

Requires:         nss >= 3.36.1

Requires:         python3-pki = %{version}-%{release}
Requires(post):   python3-pki = %{version}-%{release}

# Ensure we end up with a useful installation
Conflicts:        pki-javadoc < %{version}
Conflicts:        pki-server-theme < %{version}
Conflicts:        %{product_id}-theme < %{version}

%description -n   %{product_id}-base
This package provides default configuration files for %{product_name} client.

################################################################################
%package -n       python3-%{product_id}
################################################################################

Summary:          %{product_name} Python 3 Package
BuildArch:        noarch

Obsoletes:        python3-pki < %{version}-%{release}
Provides:         python3-pki = %{version}-%{release}

Obsoletes:        pki-base-python3 < %{version}-%{release}
Provides:         pki-base-python3 = %{version}-%{release}

%{?python_provide:%python_provide python3-pki}

Requires:         %{product_id}-base = %{version}-%{release}
Requires:         python3 >= 3.9
Requires:         python3-cryptography
Requires:         python3-ldap
Requires:         python3-lxml
Requires:         python3-requests >= 2.6.0
Requires:         python3-six

%description -n   python3-%{product_id}
This package provides common and client library for Python 3.

################################################################################
%package -n       %{product_id}-java
################################################################################

Summary:          %{product_name} Base Java Package
BuildArch:        noarch

Obsoletes:        pki-base-java < %{version}-%{release}
Provides:         pki-base-java = %{version}-%{release}

Obsoletes:        %{product_id}-base-java < %{version}-%{release}
Provides:         %{product_id}-base-java = %{version}-%{release}

Requires:         %{java_headless}
Requires:         apache-commons-cli
Requires:         apache-commons-codec
Requires:         apache-commons-io
Requires:         apache-commons-lang3 >= 3.2
Requires:         apache-commons-logging
Requires:         apache-commons-net
Requires:         slf4j
Requires:         slf4j-jdk14
Requires:         jpackage-utils >= 0:1.7.5-10
Requires:         jss >= 5.2
Requires:         ldapjdk >= 5.2
Requires:         %{product_id}-base = %{version}-%{release}
Requires:         resteasy-client >= 3.0.17-1
Requires:         resteasy-core >= 3.0.17-1
Requires:         resteasy-jackson2-provider >= 3.0.17-1

%description -n   %{product_id}-java
This package provides common and client libraries for Java.

################################################################################
%package -n       %{product_id}-tools
################################################################################

Summary:          %{product_name} Tools Package

Obsoletes:        pki-tools < %{version}-%{release}
Provides:         pki-tools = %{version}-%{release}

Requires:         openldap-clients
Requires:         nss-tools >= 3.36.1
Requires:         %{product_id}-java = %{version}-%{release}
Requires:         p11-kit-trust

# PKICertImport depends on certutil and openssl
Requires:         nss-tools
Requires:         openssl

%description -n   %{product_id}-tools
This package provides tools that can be used to help make
%{product_name} into a more complete and robust PKI solution.

The utility "tpsclient" is a test tool that interacts with TPS.
This tool is useful to test TPS server without risking an actual smart card.

# with base
%endif

%if %{with server}
################################################################################
%package -n       %{product_id}-server
################################################################################

Summary:          %{product_name} Server Package
BuildArch:        noarch

Obsoletes:        pki-server < %{version}-%{release}
Provides:         pki-server = %{version}-%{release}

Requires:         hostname

Requires:         policycoreutils
Requires:         procps-ng
Requires:         openldap-clients
Requires:         openssl
Requires:         %{product_id}-tools = %{version}-%{release}

Requires:         keyutils

Requires:         policycoreutils-python-utils

Requires:         python3-lxml
Requires:         python3-libselinux
Requires:         python3-policycoreutils

Requires:         selinux-policy-targeted >= 3.13.1-159

%if 0%{?rhel} && ! 0%{?eln}
Requires:         pki-servlet-engine >= 9.0.31
%else
Requires:         tomcat >= 1:9.0.31
%endif

Requires:         systemd
Requires(post):   systemd-units
Requires(postun): systemd-units
Requires(pre):    shadow-utils
Requires:         tomcatjss >= 8.2

# pki-healthcheck depends on the following library
%if 0%{?rhel}
Requires:         ipa-healthcheck-core
%else
Requires:         freeipa-healthcheck-core
%endif

# https://pagure.io/freeipa/issue/7742
%if 0%{?rhel}
Conflicts:        ipa-server < 4.7.1
%else
Conflicts:        freeipa-server < 4.7.1
%endif

Provides:         bundled(js-backbone) = 1.4.0
Provides:         bundled(js-bootstrap) = 3.4.1
Provides:         bundled(js-jquery) = 3.5.1
Provides:         bundled(js-jquery-i18n-properties) = 1.2.7
Provides:         bundled(js-patternfly) = 3.59.2
Provides:         bundled(js-underscore) = 1.9.2

%description -n   %{product_id}-server
This package provides libraries and utilities needed by %{product_name} services.

# with server
%endif

%if %{with acme}
################################################################################
%package -n       %{product_id}-acme
################################################################################

Summary:          %{product_name} ACME Package
BuildArch:        noarch

Obsoletes:        pki-acme < %{version}-%{release}
Provides:         pki-acme = %{version}-%{release}

Requires:         %{product_id}-server = %{version}-%{release}

%description -n   %{product_id}-acme
%{product_name} ACME responder is a service that provides an automatic certificate
management via ACME v2 protocol defined in RFC 8555.

# with acme
%endif

%if %{with ca}
################################################################################
%package -n       %{product_id}-ca
################################################################################

Summary:          %{product_name} CA Package
BuildArch:        noarch

Obsoletes:        pki-ca < %{version}-%{release}
Provides:         pki-ca = %{version}-%{release}

Requires:         %{product_id}-server = %{version}-%{release}
Requires(post):   systemd-units
Requires(postun): systemd-units

%description -n   %{product_id}-ca
%{product_name} Certificate Authority (CA) is a required subsystem which issues,
renews, revokes, and publishes certificates as well as compiling and
publishing Certificate Revocation Lists (CRLs).

The Certificate Authority can be configured as a self-signing Certificate
Authority, where it is the root CA, or it can act as a subordinate CA,
where it obtains its own signing certificate from a public CA.

# with ca
%endif

%if %{with kra}
################################################################################
%package -n       %{product_id}-kra
################################################################################

Summary:          %{product_name} KRA Package
BuildArch:        noarch

Obsoletes:        pki-kra < %{version}-%{release}
Provides:         pki-kra = %{version}-%{release}

Requires:         %{product_id}-server = %{version}-%{release}
Requires(post):   systemd-units
Requires(postun): systemd-units

%description -n   %{product_id}-kra
%{product_name} Key Recovery Authority (KRA) is an optional subsystem that can act
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

# with kra
%endif

%if %{with ocsp}
################################################################################
%package -n       %{product_id}-ocsp
################################################################################

Summary:          %{product_name} OCSP Package
BuildArch:        noarch

Obsoletes:        pki-ocsp < %{version}-%{release}
Provides:         pki-ocsp = %{version}-%{release}

Requires:         %{product_id}-server = %{version}-%{release}
Requires(post):   systemd-units
Requires(postun): systemd-units

%description -n   %{product_id}-ocsp
%{product_name} Online Certificate Status Protocol (OCSP) Manager is an optional
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

# with ocsp
%endif

%if %{with tks}
################################################################################
%package -n       %{product_id}-tks
################################################################################

Summary:          %{product_name} TKS Package
BuildArch:        noarch

Obsoletes:        pki-tks < %{version}-%{release}
Provides:         pki-tks = %{version}-%{release}

Requires:         %{product_id}-server = %{version}-%{release}
Requires(post):   systemd-units
Requires(postun): systemd-units

%description -n   %{product_id}-tks
%{product_name} Token Key Service (TKS) is an optional subsystem that manages the
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

# with tks
%endif

%if %{with tps}
################################################################################
%package -n       %{product_id}-tps
################################################################################

Summary:          %{product_name} TPS Package
BuildArch:        noarch

Obsoletes:        pki-tps < %{version}-%{release}
Provides:         pki-tps = %{version}-%{release}

Requires:         %{product_id}-server = %{version}-%{release}
Requires(post):   systemd-units
Requires(postun): systemd-units

# additional runtime requirements needed to run native 'tpsclient'
# REMINDER:  Revisit these once 'tpsclient' is rewritten as a Java app

Requires:         nss-tools >= 3.36.1
Requires:         openldap-clients

%description -n   %{product_id}-tps
%{product_name} Token Processing System (TPS) is an optional subsystem that acts
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

# with tps
%endif

%if %{with javadoc}
################################################################################
%package -n       %{product_id}-javadoc
################################################################################

Summary:          %{product_name} Javadoc Package
BuildArch:        noarch

Obsoletes:        pki-javadoc < %{version}-%{release}
Provides:         pki-javadoc = %{version}-%{release}

# Ensure we end up with a useful installation
Conflicts:        pki-base < %{version}
Conflicts:        pki-server-theme < %{version}
Conflicts:        %{product_id}-theme < %{version}

%description -n   %{product_id}-javadoc
This package provides %{product_name} API documentation.

# with javadoc
%endif

%if %{with console}
################################################################################
%package -n       %{product_id}-console
################################################################################

Summary:          %{product_name} Console Package
BuildArch:        noarch

BuildRequires:    idm-console-framework >= 2.0

Obsoletes:        pki-console < %{version}-%{release}
Provides:         pki-console = %{version}-%{release}

Requires:         idm-console-framework >= 2.0
Requires:         %{product_id}-java = %{version}-%{release}
Requires:         %{product_id}-console-theme = %{version}-%{release}

%description -n   %{product_id}-console
%{product_name} Console is a Java application used to administer %{product_name} Server.

# with console
%endif

%if %{with theme}
################################################################################
%package -n       %{product_id}-theme
################################################################################

Summary:          %{product_name} Server Theme Package
BuildArch:        noarch

Obsoletes:        pki-server-theme < %{version}-%{release}
Provides:         pki-server-theme = %{version}-%{release}

Obsoletes:        %{product_id}-server-theme < %{version}-%{release}
Provides:         %{product_id}-server-theme = %{version}-%{release}

# Ensure we end up with a useful installation
Conflicts:        pki-base < %{version}
Conflicts:        pki-javadoc < %{version}

%description -n   %{product_id}-theme
This package provides theme files for %{product_name}.

%if %{with console}
################################################################################
%package -n       %{product_id}-console-theme
################################################################################

Summary:          %{product_name} Console Theme Package
BuildArch:        noarch

Obsoletes:        pki-console-theme < %{version}-%{release}
Provides:         pki-console-theme = %{version}-%{release}

# Ensure we end up with a useful installation
Conflicts:        pki-base < %{version}
Conflicts:        pki-server-theme < %{version}
Conflicts:        pki-javadoc < %{version}
Conflicts:        %{product_id}-theme < %{version}

%description -n   %{product_id}-console-theme
This package provides theme files for %{product_name} Console.

# with console
%endif

# with theme
%endif

%if %{with tests}
################################################################################
%package -n       %{product_id}-tests
################################################################################

Summary:          %{product_name} Tests
BuildArch:        noarch

Obsoletes:        pki-tests < %{version}-%{release}
Provides:         pki-tests = %{version}-%{release}

Requires:         python3-pylint
Requires:         python3-flake8

%description -n   %{product_id}-tests
This package provides test suite for %{product_name}.

# with tests
%endif

################################################################################
%prep
################################################################################

%autosetup -n pki-%{version}%{?phase:-}%{?phase} -p 1

################################################################################
%build
################################################################################

# assume tomcat app_server
app_server=tomcat-9.0

%cmake \
    --no-warn-unused-cli \
    -DPRODUCT_NAME="%{product_name}" \
    -DVERSION=%{version} \
    -DRELEASE=%{release} \
    -DVAR_INSTALL_DIR:PATH=/var \
    -DP11_KIT_TRUST=/etc/alternatives/libnssckbi.so.%{_arch} \
    -DJAVA_HOME=%{java_home} \
    -DJAVA_LIB_INSTALL_DIR=%{_jnidir} \
    -DSYSTEMD_LIB_INSTALL_DIR=%{_unitdir} \
    -DAPP_SERVER=$app_server \
    -DPYTHON_EXECUTABLE=%{python_executable} \
    -DWITH_SERVER:BOOL=%{?with_server:ON}%{!?with_server:OFF} \
    -DWITH_CA:BOOL=%{?with_ca:ON}%{!?with_ca:OFF} \
    -DWITH_KRA:BOOL=%{?with_kra:ON}%{!?with_kra:OFF} \
    -DWITH_OCSP:BOOL=%{?with_ocsp:ON}%{!?with_ocsp:OFF} \
    -DWITH_TKS:BOOL=%{?with_tks:ON}%{!?with_tks:OFF} \
    -DWITH_TPS:BOOL=%{?with_tps:ON}%{!?with_tps:OFF} \
    -DWITH_ACME:BOOL=%{?with_acme:ON}%{!?with_acme:OFF} \
    -DWITH_JAVADOC:BOOL=%{?with_javadoc:ON}%{!?with_javadoc:OFF} \
    -DWITH_CONSOLE:BOOL=%{?with_console:ON}%{!?with_console:OFF} \
    -DWITH_TESTS:BOOL=%{?with_tests:ON}%{!?with_tests:OFF} \
    -DWITH_META:BOOL=%{?with_meta:ON}%{!?with_meta:OFF} \
    -DTHEME=%{?with_theme:%{theme}} \
    -DRUN_TESTS:BOOL=%{?with_test:ON}%{!?with_test:OFF} \
    -B %{_vpath_builddir}

cd %{_vpath_builddir}

# Do not use _smp_mflags to preserve build order
%{__make} \
    VERBOSE=%{?_verbose} \
    CMAKE_NO_VERBOSE=1 \
    DESTDIR=%{buildroot} \
    INSTALL="install -p" \
    --no-print-directory \
    all

%if %{with tests}
ctest --output-on-failure
%endif

################################################################################
%install
################################################################################

cd %{_vpath_builddir}

%{__make} \
    VERBOSE=%{?_verbose} \
    CMAKE_NO_VERBOSE=1 \
    DESTDIR=%{buildroot} \
    INSTALL="install -p" \
    --no-print-directory \
    install

%if %{with server}

%pre -n %{product_id}-server
getent group %{pki_groupname} >/dev/null || groupadd -f -g %{pki_gid} -r %{pki_groupname}
if ! getent passwd %{pki_username} >/dev/null ; then
    useradd -r -u %{pki_uid} -g %{pki_groupname} -d %{pki_homedir} -s /sbin/nologin -c "Certificate System" %{pki_username}
fi
exit 0

# with server
%endif

%if %{with base}

%post -n %{product_id}-base

if [ $1 -eq 1 ]
then
    # On RPM installation create system upgrade tracker
    echo "Configuration-Version: %{version}" > %{_sysconfdir}/pki/pki.version

else
    # On RPM upgrade run system upgrade
    echo "Upgrading PKI system configuration at `/bin/date`." >> /var/log/pki/pki-upgrade-%{version}.log
    /sbin/pki-upgrade 2>&1 | tee -a /var/log/pki/pki-upgrade-%{version}.log
    echo >> /var/log/pki/pki-upgrade-%{version}.log
fi

%postun -n %{product_id}-base

if [ $1 -eq 0 ]
then
    # On RPM uninstallation remove system upgrade tracker
    rm -f %{_sysconfdir}/pki/pki.version
fi

# with base
%endif

%if %{with server}

%post -n %{product_id}-server
# CVE-2021-3551
# Remove world access from existing installation logs
find /var/log/pki -maxdepth 1 -type f -exec chmod o-rwx {} \;

# Reload systemd daemons on upgrade only
if [ "$1" == "2" ]
then
    systemctl daemon-reload
fi

# with server
%endif

%if %{with meta}
%if "%{name}" != "%{product_id}"
################################################################################
%files -n %{product_id}
################################################################################
%else
%files
%endif

%doc %{_datadir}/doc/pki/README

# with meta
%endif

%if %{with base}
################################################################################
%files -n %{product_id}-base
################################################################################

%license base/common/LICENSE
%license base/common/LICENSE.LESSER
%doc %{_datadir}/doc/pki-base/html
%dir %{_datadir}/pki
%{_datadir}/pki/VERSION
%{_datadir}/pki/pom.xml
%dir %{_datadir}/pki/etc
%{_datadir}/pki/etc/pki.conf
%{_datadir}/pki/etc/logging.properties
%dir %{_datadir}/pki/lib
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

################################################################################
%files -n %{product_id}-java
################################################################################

%license base/common/LICENSE
%license base/common/LICENSE.LESSER
%{_datadir}/pki/examples/java/
%{_datadir}/pki/lib/*.jar
%dir %{_javadir}/pki
%{_javadir}/pki/pki-cmsutil.jar
%{_javadir}/pki/pki-certsrv.jar

################################################################################
%files -n python3-%{product_id}
################################################################################

%license base/common/LICENSE
%license base/common/LICENSE.LESSER
%if %{with server}
%exclude %{python3_sitelib}/pki/server
%endif
%{python3_sitelib}/pki

################################################################################
%files -n %{product_id}-tools
################################################################################

%license base/tools/LICENSE
%doc base/tools/doc/README
%{_bindir}/p12tool
%{_bindir}/p7tool
%{_bindir}/pistool
%{_bindir}/pki
%{_bindir}/revoker
%{_bindir}/setpin
%{_bindir}/sslget
%{_bindir}/tkstool
%{_bindir}/tpsclient
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
%{_bindir}/PKICertImport
%{_bindir}/PrettyPrintCert
%{_bindir}/PrettyPrintCrl
%{_bindir}/TokenInfo
%{_javadir}/pki/pki-tools.jar
%{_datadir}/pki/tools/
%{_datadir}/pki/lib/p11-kit-trust.so
%{_libdir}/tps/libtps.so
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
%{_mandir}/man1/pki-ca-cert.1.gz
%{_mandir}/man1/pki-ca-kraconnector.1.gz
%{_mandir}/man1/pki-ca-profile.1.gz
%{_mandir}/man1/pki-client.1.gz
%{_mandir}/man1/pki-group.1.gz
%{_mandir}/man1/pki-group-member.1.gz
%{_mandir}/man1/pki-kra-key.1.gz
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
%{_mandir}/man1/tpsclient.1.gz

# with base
%endif

%if %{with server}
################################################################################
%files -n %{product_id}-server
################################################################################

%license base/common/THIRD_PARTY_LICENSES
%license base/server/LICENSE
%doc base/server/README
%attr(755,-,-) %dir %{_sysconfdir}/sysconfig/pki
%attr(755,-,-) %dir %{_sysconfdir}/sysconfig/pki/tomcat
%{_sbindir}/pkispawn
%{_sbindir}/pkidestroy
%{_sbindir}/pki-server
%{_sbindir}/pki-server-upgrade
%{_sbindir}/pki-healthcheck
%{python3_sitelib}/pki/server/
%{python3_sitelib}/pkihealthcheck-*.egg-info/
%config(noreplace) %{_sysconfdir}/pki/healthcheck.conf

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
%{_javadir}/pki/pki-tomcat.jar
%dir %{_sharedstatedir}/pki
%{_mandir}/man1/pkidaemon.1.gz
%{_mandir}/man5/pki_default.cfg.5.gz
%{_mandir}/man5/pki_healthcheck.conf.5.gz
%{_mandir}/man5/pki-server-logging.5.gz
%{_mandir}/man8/pki-server-upgrade.8.gz
%{_mandir}/man8/pkidestroy.8.gz
%{_mandir}/man8/pkispawn.8.gz
%{_mandir}/man8/pki-server.8.gz
%{_mandir}/man8/pki-server-acme.8.gz
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
%{_mandir}/man8/pki-healthcheck.8.gz
%{_datadir}/pki/setup/
%{_datadir}/pki/server/

# with server
%endif

%if %{with acme}
################################################################################
%files -n %{product_id}-acme
################################################################################

%{_javadir}/pki/pki-acme.jar
%{_datadir}/pki/acme/

# with acme
%endif

%if %{with ca}
################################################################################
%files -n %{product_id}-ca
################################################################################

%license base/ca/LICENSE
%{_javadir}/pki/pki-ca.jar
%{_datadir}/pki/ca/

# with ca
%endif

%if %{with kra}
################################################################################
%files -n %{product_id}-kra
################################################################################

%license base/kra/LICENSE
%{_javadir}/pki/pki-kra.jar
%{_datadir}/pki/kra/

# with kra
%endif

%if %{with ocsp}
################################################################################
%files -n %{product_id}-ocsp
################################################################################

%license base/ocsp/LICENSE
%{_javadir}/pki/pki-ocsp.jar
%{_datadir}/pki/ocsp/

# with ocsp
%endif

%if %{with tks}
################################################################################
%files -n %{product_id}-tks
################################################################################

%license base/tks/LICENSE
%{_javadir}/pki/pki-tks.jar
%{_datadir}/pki/tks/

# with tks
%endif

%if %{with tps}
################################################################################
%files -n %{product_id}-tps
################################################################################

%license base/tps/LICENSE
%{_javadir}/pki/pki-tps.jar
%{_datadir}/pki/tps/
%{_mandir}/man5/pki-tps-connector.5.gz
%{_mandir}/man5/pki-tps-profile.5.gz

# with tps
%endif

%if %{with javadoc}
################################################################################
%files -n %{product_id}-javadoc
################################################################################

%{_javadocdir}/pki/

# with javadoc
%endif

%if %{with console}
################################################################################
%files -n %{product_id}-console
################################################################################

%license base/console/LICENSE
%{_bindir}/pkiconsole
%{_javadir}/pki/pki-console.jar

# with console
%endif

%if %{with theme}
################################################################################
%files -n %{product_id}-theme
################################################################################

%license themes/%{theme}/common-ui/LICENSE
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

%if %{with console}
################################################################################
%files -n %{product_id}-console-theme
################################################################################

%license themes/%{theme}/console-ui/LICENSE
%{_javadir}/pki/pki-console-theme.jar

# with console
%endif

# with theme
%endif

%if %{with tests}
################################################################################
%files -n %{product_id}-tests
################################################################################

%{_datadir}/pki/tests/

# with tests
%endif

################################################################################
%changelog
* Tue Mar 6 2018 Dogtag PKI Team <devel@lists.dogtagpki.org> 10.6.0-0
- To list changes in <branch> since <tag>:
  $ git log --pretty=oneline --abbrev-commit --no-decorate <tag>..<branch>
