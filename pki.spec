################################################################################
Name:             pki
################################################################################

%global           product_name Dogtag PKI
%global           product_id dogtag-pki
%global           theme dogtag

# Upstream version number:
%global           major_version 11
%global           minor_version 5
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

%if 0%{?java_arches:1}
ExclusiveArch: %{java_arches}
%else
ExcludeArch: i686
%endif

################################################################################
# PKCS #11 Kit Trust
################################################################################

%global p11_kit_trust /usr/lib64/pkcs11/p11-kit-trust.so

################################################################################
# Java
################################################################################

%global java_devel java-17-openjdk-devel
%global java_headless java-17-openjdk-headless
%global java_home %{_jvmdir}/jre-17-openjdk

################################################################################
# Application Server
################################################################################

%global app_server tomcat-9.0

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
%bcond_without est
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

BuildRequires:    nspr-devel
BuildRequires:    nss-devel >= 3.36.1

BuildRequires:    openldap-devel
BuildRequires:    pkgconfig
BuildRequires:    policycoreutils

# Java build dependencies
BuildRequires:    %{java_devel}
BuildRequires:    maven-local
%if 0%{?fedora}
BuildRequires:    xmvn-tools
%endif
BuildRequires:    javapackages-tools
BuildRequires:    mvn(commons-cli:commons-cli)
BuildRequires:    mvn(commons-codec:commons-codec)
BuildRequires:    mvn(commons-io:commons-io)
BuildRequires:    mvn(org.apache.commons:commons-lang3)
BuildRequires:    mvn(commons-logging:commons-logging)
BuildRequires:    mvn(commons-net:commons-net)
BuildRequires:    mvn(org.slf4j:slf4j-api)
BuildRequires:    mvn(xml-apis:xml-apis)
BuildRequires:    mvn(xml-resolver:xml-resolver)
BuildRequires:    mvn(org.junit.jupiter:junit-jupiter-api)
BuildRequires:    mvn(org.jboss.resteasy:resteasy-client)
BuildRequires:    mvn(org.jboss.resteasy:resteasy-jackson2-provider)
BuildRequires:    mvn(org.jboss.resteasy:resteasy-jaxrs)
BuildRequires:    mvn(org.jboss.resteasy:resteasy-servlet-initializer)
BuildRequires:    mvn(org.apache.tomcat:tomcat-catalina)
BuildRequires:    mvn(org.apache.tomcat:tomcat-servlet-api)
BuildRequires:    mvn(org.apache.tomcat:tomcat-jaspic-api)
BuildRequires:    mvn(org.apache.tomcat:tomcat-util-scan)
BuildRequires:    mvn(org.dogtagpki.jss:jss-base) >= 5.5.0
BuildRequires:    mvn(org.dogtagpki.jss:jss-tomcat) >= 5.5.0
BuildRequires:    mvn(org.dogtagpki.ldap-sdk:ldapjdk) >= 5.5.0

# Python build dependencies
BuildRequires:    python3 >= 3.9
BuildRequires:    python3-devel
BuildRequires:    python3-setuptools
BuildRequires:    python3-cryptography
BuildRequires:    python3-lxml
BuildRequires:    python3-ldap
BuildRequires:    python3-libselinux
BuildRequires:    python3-requests >= 2.6.0
BuildRequires:    python3-six
BuildRequires:    python3-sphinx

BuildRequires:    systemd-units

# additional build requirements needed to build native 'tpsclient'
# REMINDER:  Revisit these once 'tpsclient' is rewritten as a Java app
BuildRequires:    apr-devel
BuildRequires:    apr-util-devel
BuildRequires:    cyrus-sasl-devel
BuildRequires:    httpd-devel >= 2.4.2
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

  * Certificate Authority (CA)
  * Key Recovery Authority (KRA)
  * Online Certificate Status Protocol (OCSP) Manager
  * Token Key Service (TKS)
  * Token Processing Service (TPS)
  * Automatic Certificate Management Environment (ACME) Responder
  * Enrollment over Secure Transport (EST) Responder

%endif

%if %{with meta}
%if "%{name}" != "%{product_id}"
################################################################################
%package -n       %{product_id}
################################################################################

Summary:          %{product_name} Package
%endif
BuildArch:        noarch

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
Requires:         %{product_id}-est = %{version}-%{release}
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

  * Certificate Authority (CA)
  * Key Recovery Authority (KRA)
  * Online Certificate Status Protocol (OCSP) Manager
  * Token Key Service (TKS)
  * Token Processing Service (TPS)
  * Automatic Certificate Management Environment (ACME) Responder
  * Enrollment over Secure Transport (EST) Responder

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
Requires:         mvn(commons-cli:commons-cli)
Requires:         mvn(commons-codec:commons-codec)
Requires:         mvn(commons-io:commons-io)
Requires:         mvn(org.apache.commons:commons-lang3)
Requires:         mvn(commons-logging:commons-logging)
Requires:         mvn(commons-net:commons-net)
Requires:         mvn(org.slf4j:slf4j-api)
Requires:         mvn(org.slf4j:slf4j-jdk14)
Requires:         mvn(org.jboss.resteasy:resteasy-client)
Requires:         mvn(org.jboss.resteasy:resteasy-jackson2-provider)
Requires:         mvn(org.jboss.resteasy:resteasy-jaxrs)
Requires:         mvn(org.dogtagpki.jss:jss-base) >= 5.5.0
Requires:         mvn(org.dogtagpki.ldap-sdk:ldapjdk) >= 5.5.0
Requires:         %{product_id}-base = %{version}-%{release}

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

Requires:         mvn(org.jboss.resteasy:resteasy-servlet-initializer)
Requires:         tomcat >= 1:9.0.50
Requires:         mvn(org.dogtagpki.jss:jss-tomcat) >= 5.5.0

Requires:         systemd
Requires(post):   systemd-units
Requires(postun): systemd-units
Requires(pre):    shadow-utils

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

%if %{with est}
################################################################################
%package -n       %{product_id}-est
################################################################################

Summary:          %{product_name} EST Package
BuildArch:        noarch

Obsoletes:        pki-est < %{version}-%{release}
Provides:         pki-est = %{version}-%{release}

Requires:         %{product_id}-server = %{version}-%{release}

%description -n   %{product_id}-est
%{product_name} EST subsystem provides an Enrollment over
Secure Transport (RFC 7030) service.

# with est
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

BuildRequires:    mvn(org.dogtagpki.console-framework:console-framework) >= 2.1.0

Obsoletes:        pki-console < %{version}-%{release}
Provides:         pki-console = %{version}-%{release}

Requires:         mvn(org.dogtagpki.console-framework:console-framework) >= 2.1.0
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

# Set build flags for CMake
# (see /usr/lib/rpm/macros.d/macros.cmake)
%set_build_flags

export JAVA_HOME=%{java_home}

# flatten-maven-plugin is not available in RPM
%pom_remove_plugin org.codehaus.mojo:flatten-maven-plugin

%if ! %{with console}
%pom_disable_module console base
%endif

# build Java binaries and run unit tests with Maven
%mvn_build %{!?with_test:-f} -j

# create links to Maven-built JAR files for CMake
mkdir -p %{_vpath_builddir}/dist
pushd %{_vpath_builddir}/dist
ln -sf ../../base/common/target/pki-common.jar
ln -sf ../../base/tools/target/pki-tools.jar
ln -sf ../../base/tomcat/target/pki-tomcat.jar
ln -sf ../../base/tomcat-9.0/target/pki-tomcat-9.0.jar
ln -sf ../../base/server/target/pki-server.jar
ln -sf ../../base/server-webapp/target/pki-server-webapp.jar
ln -sf ../../base/ca/target/pki-ca.jar
ln -sf ../../base/kra/target/pki-kra.jar
ln -sf ../../base/ocsp/target/pki-ocsp.jar
ln -sf ../../base/tks/target/pki-tks.jar
ln -sf ../../base/tps/target/pki-tps.jar
ln -sf ../../base/acme/target/pki-acme.jar
ln -sf ../../base/est/target/pki-est.jar

%if %{with console}
ln -sf ../../base/console/target/pki-console.jar
%endif

popd

# Remove all symbol table and relocation information from the executable.
C_FLAGS="-s"

%if 0%{?fedora}
# https://sourceware.org/annobin/annobin.html/Test-gaps.html
C_FLAGS="$C_FLAGS -fplugin=annobin"

# https://sourceware.org/annobin/annobin.html/Test-cf-protection.html
C_FLAGS="$C_FLAGS -fcf-protection=full"

# https://sourceware.org/annobin/annobin.html/Test-optimization.html
C_FLAGS="$C_FLAGS -O2"

# https://sourceware.org/annobin/annobin.html/Test-glibcxx-assertions.html
C_FLAGS="$C_FLAGS -D_GLIBCXX_ASSERTIONS"

# https://sourceware.org/annobin/annobin.html/Test-lto.html
C_FLAGS="$C_FLAGS -fno-lto"
%endif

pkgs=base\
%{?with_server:,server}\
%{?with_ca:,ca}\
%{?with_est:,est}\
%{?with_kra:,kra}\
%{?with_ocsp:,ocsp}\
%{?with_tks:,tks}\
%{?with_tps:,tps}\
%{?with_acme:,acme}\
%{?with_javadoc:,javadoc}\
%{?with_theme:,theme}\
%{?with_meta:,meta}\
%{?with_tests:,tests}\
%{?with_debug:,debug}

# build PKI console, Javadoc, and native binaries with CMake
./build.sh \
    %{?_verbose:-v} \
    --product-name="%{product_name}" \
    --product-id=%{product_id} \
%if %{with theme}
    --theme=%{theme} \
%endif
    --work-dir=%{_vpath_builddir} \
    --prefix-dir=%{_prefix} \
    --include-dir=%{_includedir} \
    --lib-dir=%{_libdir} \
    --sysconf-dir=%{_sysconfdir} \
    --share-dir=%{_datadir} \
    --cmake=%{__cmake} \
    --c-flags="$C_FLAGS" \
    --java-home=%{java_home} \
    --jni-dir=%{_jnidir} \
    --unit-dir=%{_unitdir} \
    --python=%{python3} \
    --python-dir=%{python3_sitelib} \
    --without-java \
    --with-pkgs=$pkgs \
    %{?with_console:--with-console} \
    --without-test \
    dist

################################################################################
%install
################################################################################

# install Java binaries
%mvn_install

# install PKI console, Javadoc, and native binaries
./build.sh \
    %{?_verbose:-v} \
    --work-dir=%{_vpath_builddir} \
    --install-dir=%{buildroot} \
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

# Update the fapolicy rules for each PKI server instance
for instance in $(ls /var/lib/pki)
do
    target="/etc/fapolicyd/rules.d/61-pki-$instance.rules"

    sed -e "s/\[WORK_DIR\]/\/var\/lib\/pki\/$instance\/work/g" \
        /usr/share/pki/server/etc/fapolicy.rules \
        > $target

    chown root:fapolicyd $target
    chmod 644 $target
done

# Restart fapolicy daemon if it's active
status=$(systemctl is-active fapolicyd)
if [ "$status" = "active" ]
then
    systemctl restart fapolicyd
fi

# with server
%endif

%if %{with meta}
%if "%{name}" != "%{product_id}"
################################################################################
%files -n %{product_id} -f .mfiles
################################################################################
%else
%files -f .mfiles
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
%{_javadir}/pki/pki-common.jar

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
%{_mandir}/man1/AtoB.1.gz
%{_mandir}/man1/AuditVerify.1.gz
%{_mandir}/man1/BtoA.1.gz
%{_mandir}/man1/CMCEnroll.1.gz
%{_mandir}/man1/CMCRequest.1.gz
%{_mandir}/man1/CMCSharedToken.1.gz
%{_mandir}/man1/CMCResponse.1.gz
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
%{_javadir}/pki/pki-server.jar
%{_javadir}/pki/pki-server-webapp.jar
%{_javadir}/pki/pki-tomcat.jar
%{_javadir}/pki/pki-tomcat-9.0.jar
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
%{_mandir}/man8/pki-server-est.8.gz
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

%if %{with est}
################################################################################
%files -n %{product_id}-est
################################################################################

%{_javadir}/pki/pki-est.jar
%{_datadir}/pki/est/

# with est
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

%if %{with server}
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

# with server
%endif

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
