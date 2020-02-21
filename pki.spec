################################################################################
Name:             pki
################################################################################

%global           vendor_id dogtag
%global           brand Dogtag

Summary:          %{brand} PKI Package
URL:              http://www.dogtagpki.org/
# The entire source code is GPLv2 except for 'pki-tps' which is LGPLv2
License:          GPLv2 and LGPLv2

Version:          10.8.2
Release:          1%{?_timestamp}%{?_commit_id}%{?dist}
# global          _phase -a1

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

%global nss_default_db_type sql

################################################################################
# Python
################################################################################

%if 0%{?rhel}
%global python_executable /usr/libexec/platform-python
%else
%global python_executable /usr/bin/python3
%endif

################################################################################
# Java
################################################################################

%define java_home %{_usr}/lib/jvm/jre-1.8.0-openjdk

################################################################################
# RESTEasy
################################################################################

%define jaxrs_api_jar /usr/share/java/jboss-jaxrs-2.0-api.jar
%define resteasy_lib /usr/share/java/resteasy

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

# with pkgs
%endif

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

# with debug
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

# autosetup
BuildRequires:    git
BuildRequires:    make

BuildRequires:    cmake >= 2.8.9-1
BuildRequires:    gcc-c++
BuildRequires:    zip
BuildRequires:    java-1.8.0-openjdk-devel
BuildRequires:    redhat-rpm-config
BuildRequires:    ldapjdk >= 4.21.0
BuildRequires:    apache-commons-cli
BuildRequires:    apache-commons-codec
BuildRequires:    apache-commons-io
BuildRequires:    apache-commons-lang
BuildRequires:    apache-commons-net
BuildRequires:    jakarta-commons-httpclient
BuildRequires:    glassfish-jaxb-api
BuildRequires:    slf4j
BuildRequires:    slf4j-jdk14
BuildRequires:    nspr-devel
BuildRequires:    nss-devel >= 3.36.1

BuildRequires:    openldap-devel
BuildRequires:    pkgconfig
BuildRequires:    policycoreutils

BuildRequires:    python3-lxml
BuildRequires:    python3-sphinx

BuildRequires:    velocity
BuildRequires:    xalan-j2
BuildRequires:    xerces-j2

%if 0%{?rhel}
BuildRequires:    resteasy >= 3.0.26
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

%if 0%{?rhel}
# no pylint
%else
BuildRequires:    python3-pylint
BuildRequires:    python3-flake8 >= 2.5.4
BuildRequires:    python3-pyflakes >= 1.2.3
%endif

BuildRequires:    python3 >= 3.5
BuildRequires:    python3-devel
BuildRequires:    python3-cryptography
BuildRequires:    python3-lxml
BuildRequires:    python3-ldap
BuildRequires:    python3-libselinux
BuildRequires:    python3-nss
BuildRequires:    python3-requests >= 2.6.0
BuildRequires:    python3-six

%if 0%{?rhel}
# no python3-pytest-runner
%else
# BuildRequires:  python3-pytest-runner
%endif

BuildRequires:    junit
BuildRequires:    jpackage-utils >= 0:1.7.5-10
BuildRequires:    jss >= 4.6.0
BuildRequires:    tomcatjss >= 7.4.1
BuildRequires:    systemd-units

%if 0%{?rhel}
BuildRequires:    pki-servlet-engine
%else
BuildRequires:    tomcat >= 1:9.0.7
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
%if 0%{?fedora} && 0%{?fedora} <= 30 || 0%{?rhel}
BuildRequires:    go-md2man
%else
BuildRequires:    golang-github-cpuguy83-md2man
%endif

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
%if "%{name}" != "%{vendor_id}-pki"
%description

%{brand} PKI is an enterprise software system designed
to manage enterprise Public Key Infrastructure deployments.

PKI consists of the following components:

  * Certificate Authority (CA)
  * Key Recovery Authority (KRA)
  * Online Certificate Status Protocol (OCSP) Manager
  * Token Key Service (TKS)
  * Token Processing Service (TPS)

%endif

%if %{with meta}
%if "%{name}" != "%{vendor_id}-pki"
################################################################################
%package -n       %{vendor_id}-pki
################################################################################

Summary:          %{brand} PKI Package
%endif

# Make certain that this 'meta' package requires the latest version(s)
# of ALL PKI theme packages
Requires:         %{vendor_id}-pki-server-theme = %{version}
Requires:         %{vendor_id}-pki-console-theme = %{version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL PKI core packages
Requires:         pki-ca = %{version}
Requires:         pki-kra = %{version}
Requires:         pki-ocsp = %{version}
Requires:         pki-tks = %{version}
Requires:         pki-tps = %{version}

# Make certain that this 'meta' package requires the latest version(s)
# of PKI console
Requires:         pki-console = %{version}
Requires:         pki-javadoc = %{version}

# Make certain that this 'meta' package requires the latest version(s)
# of ALL PKI clients
Requires:         esc >= 1.1.1

# description for top-level package (unless there is a separate meta package)
%if "%{name}" == "%{vendor_id}-pki"
%description
%else
%description -n   %{vendor_id}-pki
%endif

%{brand} PKI is an enterprise software system designed
to manage enterprise Public Key Infrastructure deployments.

PKI consists of the following components:

  * Certificate Authority (CA)
  * Key Recovery Authority (KRA)
  * Online Certificate Status Protocol (OCSP) Manager
  * Token Key Service (TKS)
  * Token Processing Service (TPS)

# with meta
%endif

%if %{with base}
################################################################################
%package -n       pki-symkey
################################################################################

Summary:          PKI Symmetric Key Package

Requires:         java-1.8.0-openjdk-headless
Requires:         jpackage-utils >= 0:1.7.5-10
Requires:         jss >= 4.6.0
Requires:         nss >= 3.38.0

# Ensure we end up with a useful installation
Conflicts:        pki-symkey < %{version}
Conflicts:        pki-javadoc < %{version}
Conflicts:        pki-server-theme < %{version}
Conflicts:        pki-console-theme < %{version}

%description -n   pki-symkey
The PKI Symmetric Key Java Package supplies various native
symmetric key operations to Java programs.

################################################################################
%package -n       pki-base
################################################################################

Summary:          PKI Base Package
BuildArch:        noarch

Requires:         nss >= 3.36.1

Requires:         python3-pki = %{version}
Requires(post):   python3-pki = %{version}

# Ensure we end up with a useful installation
Conflicts:        pki-symkey < %{version}
Conflicts:        pki-javadoc < %{version}
Conflicts:        pki-server-theme < %{version}
Conflicts:        pki-console-theme < %{version}

%description -n   pki-base
The PKI Base Package contains the common and client libraries and utilities
written in Python.

################################################################################
%package -n       python3-pki
################################################################################

Summary:          PKI Python 3 Package
BuildArch:        noarch

Obsoletes:        pki-base-python3 < %{version}
Provides:         pki-base-python3 = %{version}
%if 0%{?fedora}
%{?python_provide:%python_provide python3-pki}
%endif

Requires:         pki-base = %{version}
Requires:         python3 >= 3.5
Requires:         python3-cryptography
Requires:         python3-lxml
Requires:         python3-nss
Requires:         python3-requests >= 2.6.0
Requires:         python3-six

%description -n   python3-pki
This package contains PKI client library for Python 3.

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
Requires:         apache-commons-net
Requires:         jakarta-commons-httpclient
Requires:         glassfish-jaxb-api
Requires:         slf4j
Requires:         slf4j-jdk14
Requires:         jpackage-utils >= 0:1.7.5-10
Requires:         jss >= 4.6.0
Requires:         ldapjdk >= 4.21.0
Requires:         pki-base = %{version}

%if 0%{?rhel}
Requires:         resteasy >= 3.0.26
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
Requires:         pki-base-java = %{version}
Requires:         p11-kit-trust

# PKICertImport depends on certutil and openssl
Requires:         nss-tools
Requires:         openssl

%description -n   pki-tools
This package contains PKI executables that can be used to help make
Certificate System into a more complete and robust PKI solution.

# with base
%endif

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
Requires:         openssl
Requires:         pki-symkey = %{version}
Requires:         pki-tools = %{version}

Requires:         keyutils

Requires:         policycoreutils-python-utils

Requires:         python3-ldap
Requires:         python3-lxml
Requires:         python3-libselinux
Requires:         python3-policycoreutils

Requires:         selinux-policy-targeted >= 3.13.1-159

%if 0%{?rhel}
Requires:         pki-servlet-engine >= 1:9.0.7
%else
Requires:         tomcat >= 1:9.0.7
%endif

Requires:         velocity
Requires(post):   systemd-units
Requires(preun):  systemd-units
Requires(postun): systemd-units
Requires(pre):    shadow-utils
Requires:         tomcatjss >= 7.4.1

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

%description -n   pki-server
The PKI Server Package contains libraries and utilities needed by the
following PKI subsystems:

    the Certificate Authority (CA),
    the Key Recovery Authority (KRA),
    the Online Certificate Status Protocol (OCSP) Manager,
    the Token Key Service (TKS), and
    the Token Processing Service (TPS).

# with server
%endif

%if %{with ca}
################################################################################
%package -n       pki-ca
################################################################################

Summary:          PKI CA Package
BuildArch:        noarch

Requires:         pki-server = %{version}
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

# with ca
%endif

%if %{with kra}
################################################################################
%package -n       pki-kra
################################################################################

Summary:          PKI KRA Package
BuildArch:        noarch

Requires:         pki-server = %{version}
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

# with kra
%endif

%if %{with ocsp}
################################################################################
%package -n       pki-ocsp
################################################################################

Summary:          PKI OCSP Package
BuildArch:        noarch

Requires:         pki-server = %{version}
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

# with ocsp
%endif

%if %{with tks}
################################################################################
%package -n       pki-tks
################################################################################

Summary:          PKI TKS Package
BuildArch:        noarch

Requires:         pki-server = %{version}
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

# with tks
%endif

%if %{with tps}
################################################################################
%package -n       pki-tps
################################################################################

Summary:          PKI TPS Package

Requires:         pki-server = %{version}
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

# with tps
%endif

%if %{with javadoc}
################################################################################
%package -n       pki-javadoc
################################################################################

Summary:          PKI Javadoc Package
BuildArch:        noarch

# Ensure we end up with a useful installation
Conflicts:        pki-base < %{version}
Conflicts:        pki-symkey < %{version}
Conflicts:        pki-server-theme < %{version}
Conflicts:        pki-console-theme < %{version}

%description -n   pki-javadoc
This package contains PKI API documentation.

# with javadoc
%endif

%if %{with console}
################################################################################
%package -n       pki-console
################################################################################

Summary:          PKI Console Package
BuildArch:        noarch

BuildRequires:    idm-console-framework >= 1.2.0

Requires:         idm-console-framework >= 1.2.0
Requires:         pki-base-java = %{version}
Requires:         pki-console-theme = %{version}

%description -n   pki-console
The PKI Console is a Java application used to administer PKI server.

# with console
%endif

%if %{with theme}
################################################################################
%package -n       %{vendor_id}-pki-server-theme
################################################################################

Summary:          %{brand} PKI Server Theme Package
BuildArch:        noarch

Provides:         pki-server-theme = %{version}

# Ensure we end up with a useful installation
Conflicts:        pki-base < %{version}
Conflicts:        pki-symkey < %{version}
Conflicts:        pki-console-theme < %{version}
Conflicts:        pki-javadoc < %{version}

%description -n   %{vendor_id}-pki-server-theme
This PKI Server Theme Package contains
%{brand} textual and graphical user interface for PKI Server.

################################################################################
%package -n       %{vendor_id}-pki-console-theme
################################################################################

Summary:          %{brand} PKI Console Theme Package
BuildArch:        noarch

Provides:         pki-console-theme = %{version}

# Ensure we end up with a useful installation
Conflicts:        pki-base < %{version}
Conflicts:        pki-symkey < %{version}
Conflicts:        pki-server-theme < %{version}
Conflicts:        pki-javadoc < %{version}

%description -n   %{vendor_id}-pki-console-theme
This PKI Console Theme Package contains
%{brand} textual and graphical user interface for PKI Console.

# with theme
%endif

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
    -DP11_KIT_TRUST=/etc/alternatives/libnssckbi.so.%{_arch} \
    -DJAVA_HOME=%{java_home} \
    -DJAVA_LIB_INSTALL_DIR=%{_jnidir} \
    -DSYSTEMD_LIB_INSTALL_DIR=%{_unitdir} \
    -DAPP_SERVER=$app_server \
    -DJAXRS_API_JAR=%{jaxrs_api_jar} \
    -DRESTEASY_LIB=%{resteasy_lib} \
    -DNSS_DEFAULT_DB_TYPE=%{nss_default_db_type} \
    -DBUILD_PKI_CORE:BOOL=ON \
    -DPYTHON_EXECUTABLE=%{python_executable} \
    -DWITH_TEST:BOOL=%{?with_test:ON}%{!?with_test:OFF} \
%if ! %{with server} && ! %{with ca} && ! %{with kra} && ! %{with ocsp} && ! %{with tks} && ! %{with tps}
    -DWITH_SERVER:BOOL=OFF \
%endif
    -DWITH_JAVADOC:BOOL=%{?with_javadoc:ON}%{!?with_javadoc:OFF} \
    -DBUILD_PKI_CONSOLE:BOOL=%{?with_console:ON}%{!?with_console:OFF} \
    -DTHEME=%{?with_theme:%{vendor_id}} \
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

%if %{with_test}
ctest --output-on-failure
%endif

%if %{with meta}
%{__mkdir_p} %{buildroot}%{_datadir}/doc/pki

cat > %{buildroot}%{_datadir}/doc/pki/README << EOF
This package is a "meta-package" whose dependencies pull in all of the
packages comprising the %{brand} Public Key Infrastructure (PKI) Suite.
EOF

# with meta
%endif

# Customize client library links in /usr/share/pki/lib
ln -sf /usr/share/java/jboss-logging/jboss-logging.jar %{buildroot}%{_datadir}/pki/lib/jboss-logging.jar
ln -sf /usr/share/java/jboss-annotations-1.2-api/jboss-annotations-api_1.2_spec.jar %{buildroot}%{_datadir}/pki/lib/jboss-annotations-api_1.2_spec.jar

%if %{with server}

# Customize server common library links in /usr/share/pki/server/common/lib
ln -sf %{jaxrs_api_jar} %{buildroot}%{_datadir}/pki/server/common/lib/jboss-jaxrs-2.0-api.jar
ln -sf /usr/share/java/jboss-logging/jboss-logging.jar %{buildroot}%{_datadir}/pki/server/common/lib/jboss-logging.jar
ln -sf /usr/share/java/jboss-annotations-1.2-api/jboss-annotations-api_1.2_spec.jar %{buildroot}%{_datadir}/pki/server/common/lib/jboss-annotations-api_1.2_spec.jar

%if 0%{?rhel}
# no pylint
%else

################################################################################
echo "Scanning Python code with pylint"
################################################################################

%{python_executable} -I ../tools/pylint-build-scan.py rpm --prefix %{buildroot}
if [ $? -ne 0 ]; then
    echo "pylint for Python 3 failed. RC: $?"
    exit 1
fi

################################################################################
echo "Scanning Python code with flake8"
################################################################################

python3-flake8 --config ../tox.ini %{buildroot}
if [ $? -ne 0 ]; then
    echo "flake8 for Python 3 failed. RC: $?"
    exit 1
fi

%endif

# with server
%endif

%if %{with server}

%pre -n pki-server
getent group %{pki_groupname} >/dev/null || groupadd -f -g %{pki_gid} -r %{pki_groupname}
if ! getent passwd %{pki_username} >/dev/null ; then
    useradd -r -u %{pki_uid} -g %{pki_groupname} -d %{pki_homedir} -s /sbin/nologin -c "Certificate System" %{pki_username}
fi
exit 0

# with server
%endif

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

# with base
%endif

%if %{with server}

%post -n pki-server
## NOTE:  At this time, NO attempt has been made to update ANY PKI subsystem
##        from EITHER 'sysVinit' OR previous 'systemd' processes to the new
##        PKI deployment process

echo "Upgrading PKI server configuration on `/bin/date`." >> /var/log/pki/pki-server-upgrade-%{version}.log 2>&1
/sbin/pki-server upgrade --silent >> /var/log/pki/pki-server-upgrade-%{version}.log 2>&1
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

# with server
%endif

%if %{with meta}
%if "%{name}" != "%{vendor_id}-pki"
################################################################################
%files -n %{vendor_id}-pki
################################################################################
%else
%files
%endif

%doc %{_datadir}/doc/pki/README

# with meta
%endif

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
%files -n pki-base-java
################################################################################

%doc base/common/LICENSE
%doc base/common/LICENSE.LESSER
%{_datadir}/pki/examples/java/
%{_datadir}/pki/lib/*.jar
%dir %{_javadir}/pki
%{_javadir}/pki/pki-cmsutil.jar
%{_javadir}/pki/pki-nsutil.jar
%{_javadir}/pki/pki-certsrv.jar

################################################################################
%files -n python3-pki
################################################################################

%doc base/common/LICENSE
%doc base/common/LICENSE.LESSER
%if %{with server}
%exclude %{python3_sitelib}/pki/server
%endif
%{python3_sitelib}/pki

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
%{_datadir}/pki/lib/p11-kit-trust.so
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

# with base
%endif

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
%{python3_sitelib}/pki/server/
%{_sbindir}/pki-healthcheck
%{python3_sitelib}/pki/server/healthcheck/
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
%{_mandir}/man8/pki-healthcheck.8.gz
%{_datadir}/pki/setup/
%{_datadir}/pki/server/
%{_datadir}/pki/acme/
%{_javadir}/pki/pki-acme.jar

# with server
%endif

%if %{with ca}
################################################################################
%files -n pki-ca
################################################################################

%doc base/ca/LICENSE
%{_javadir}/pki/pki-ca.jar
%dir %{_datadir}/pki/ca
%{_datadir}/pki/ca/conf/
%{_datadir}/pki/ca/emails/
%{_datadir}/pki/ca/profiles/
%{_datadir}/pki/ca/setup/
%{_datadir}/pki/ca/webapps/

# with ca
%endif

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

# with kra
%endif

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

# with ocsp
%endif

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

# with tks
%endif

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

# with tps
%endif

%if %{with javadoc}
################################################################################
%files -n pki-javadoc
################################################################################

%{_javadocdir}/pki-%{version}/

# with javadoc
%endif

%if %{with console}
################################################################################
%files -n pki-console
################################################################################

%doc base/console/LICENSE
%{_bindir}/pkiconsole
%{_javadir}/pki/pki-console.jar

# with console
%endif

%if %{with theme}
################################################################################
%files -n %{vendor_id}-pki-server-theme
################################################################################

%doc themes/%{vendor_id}/common-ui/LICENSE
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
%files -n %{vendor_id}-pki-console-theme
################################################################################

%doc themes/%{vendor_id}/console-ui/LICENSE
%{_javadir}/pki/pki-console-theme.jar

# with theme
%endif

################################################################################
%changelog
* Tue Mar 6 2018 Dogtag PKI Team <pki-devel@redhat.com> 10.6.0-0
- To list changes in <branch> since <tag>:
  $ git log --pretty=oneline --abbrev-commit --no-decorate <tag>..<branch>
