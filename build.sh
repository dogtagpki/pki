#!/bin/bash -e

# BEGIN COPYRIGHT BLOCK
# (C) 2018 Red Hat, Inc.
# All rights reserved.
# END COPYRIGHT BLOCK

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_NAME=$(basename "$SCRIPT_PATH")
SRC_DIR=$(dirname "$SCRIPT_PATH")

NAME=pki
PRODUCT_NAME=
PRODUCT_ID=
THEME=

WORK_DIR=

PREFIX_DIR="/usr"
INCLUDE_DIR="/usr/include"

if [ "$HOSTTYPE" = "x86_64" ]; then
   LIB_DIR="/usr/lib64"
else
   LIB_DIR="/usr/lib"
fi

SYSCONF_DIR="/etc"
SHARE_DIR="/usr/share"

CMAKE="cmake"
C_FLAGS=

JNI_DIR="/usr/lib/java"
UNIT_DIR="/usr/lib/systemd/system"

PYTHON=
PYTHON_DIR=

INSTALL_DIR=

SOURCE_TAG=
SPEC_TEMPLATE="$SRC_DIR/pki.spec"
SPEC_FILE=

WITH_TIMESTAMP=
WITH_COMMIT_ID=
DIST=

WITH_JAVA=true
WITH_CONSOLE=
RUN_TESTS=true

PKG_LIST="base, server, ca, kra, ocsp, tks, tps, acme, est, javadoc, theme, meta, tests, debug"
ALL_PKGS=( $(echo "$PKG_LIST" | sed 's/ *, */ /g') )

WITH_PKGS=
WITHOUT_PKGS=

VERBOSE=
DEBUG=

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] <target>"
    echo
    echo "Options:"
    echo "    --name=<name>          Package name (default: $NAME)."
    echo "    --product-name=<name>  Use the specified product name."
    echo "    --product-id=<ID>      Use the specified product ID."
    echo "    --theme=<name>         Use the specified theme."
    echo "    --work-dir=<path>      Working directory (default: ~/build/$NAME)."
    echo "    --prefix-dir=<path>    Prefix directory (default: $PREFIX_DIR)"
    echo "    --include-dir=<path>   Include directory (default: $INCLUDE_DIR)"
    echo "    --lib-dir=<path>       Library directory (default: $LIB_DIR)"
    echo "    --sysconf-dir=<path>   System configuration directory (default: $SYSCONF_DIR)"
    echo "    --share-dir=<path>     Share directory (default: $SHARE_DIR)"
    echo "    --cmake=<path>         Path to CMake executable"
    echo "    --c-flags=<flags>      C compiler flags"
    echo "    --java-home=<path>     Java home directory"
    echo "    --jni-dir=<path>       JNI directory (default: $JNI_DIR)"
    echo "    --unit-dir=<path>      Systemd unit directory (default: $UNIT_DIR)"
    echo "    --python=<path>        Path to Python executable (default: $PYTHON)"
    echo "    --python-dir=<path>    Path to Python modules"
    echo "    --install-dir=<path>   Installation directory"
    echo "    --source-tag=<tag>     Generate RPM sources from a source tag."
    echo "    --spec=<file>          Use the specified RPM spec (default: $SPEC_TEMPLATE)."
    echo "    --with-timestamp       Append timestamp to release number."
    echo "    --with-commit-id       Append commit ID to release number."
    echo "    --dist=<name>          Distribution name (e.g. fc28)."
    echo "    --without-java         Do not build Java binaries."
    echo "    --with-console         Build console package."
    echo "    --with-pkgs=<list>     Build packages specified in comma-separated list only."
    echo "    --without-pkgs=<list>  Build everything except packages specified in comma-separated list."
    echo "    --without-test         Do not run unit tests."
    echo " -v,--verbose              Run in verbose mode."
    echo "    --debug                Run in debug mode."
    echo "    --help                 Show help message."
    echo
    echo "Packages:"
    echo "    $PKG_LIST"
    echo
    echo "Target:"
    echo "    dist     Build PKI binaries (default)."
    echo "    install  Install PKI binaries."
    echo "    src      Generate RPM sources."
    echo "    spec     Generate RPM spec."
    echo "    srpm     Build SRPM package."
    echo "    rpm      Build RPM packages."
}

generate_rpm_sources() {

    PREFIX="pki-$FULL_VERSION"
    TARBALL="$PREFIX.tar.gz"

    if [ "$SOURCE_TAG" != "" ] ; then

        if [ "$VERBOSE" = true ] ; then
            echo "Generating $TARBALL from $SOURCE_TAG tag"
        fi

        git -C "$SRC_DIR" \
            archive \
            --format=tar.gz \
            --prefix "$PREFIX/" \
            -o "$WORK_DIR/SOURCES/$TARBALL" \
            "$SOURCE_TAG"

        if [ "$SOURCE_TAG" != "HEAD" ] ; then

            TAG_ID="$(git -C "$SRC_DIR" rev-parse "$SOURCE_TAG")"
            HEAD_ID="$(git -C "$SRC_DIR" rev-parse HEAD)"

            if [ "$TAG_ID" != "$HEAD_ID" ] ; then
                generate_patch
            fi
        fi

        return
    fi

    if [ "$VERBOSE" = true ] ; then
        echo "Generating $TARBALL"
    fi

    tar czf "$WORK_DIR/SOURCES/$TARBALL" \
        --transform "s,^./,$PREFIX/," \
        --exclude .git \
        --exclude .svn \
        --exclude .swp \
        --exclude .metadata \
        --exclude .tox \
        --exclude build \
        --exclude dist \
        --exclude target \
        --exclude MANIFEST \
        --exclude *.pyc \
        --exclude __pycache__ \
        -C "$SRC_DIR" \
        .
}

generate_patch() {

    PATCH="pki-$VERSION-$RELEASE.patch"

    if [ "$VERBOSE" = true ] ; then
        echo "Generating $PATCH for all changes since $SOURCE_TAG tag"
    fi

    git -C "$SRC_DIR" \
        format-patch \
        --stdout \
        "$SOURCE_TAG" \
        > "$WORK_DIR/SOURCES/$PATCH"
}

generate_rpm_spec() {

    if [ "$VERBOSE" = true ] ; then
        echo "Creating $SPEC_FILE"
    fi

    cp "$SPEC_TEMPLATE" "$SPEC_FILE"

    # hard-code package name
    sed -i "s/^\(Name: *\).*\$/\1${NAME}/g" "$SPEC_FILE"

    # hard-code product name
    sed -i "s/^\(%global *product_name *\).*\$/\1$PRODUCT_NAME/g" "$SPEC_FILE"

    # hard-code product ID
    sed -i "s/^\(%global *product_id *\).*\$/\1$PRODUCT_ID/g" "$SPEC_FILE"

    # hard-code theme
    sed -i "s/^\(%global *theme *\).*\$/\1$THEME/g" "$SPEC_FILE"

    # hard-code timestamp
    if [ "$TIMESTAMP" != "" ] ; then
        sed -i "s/%undefine *timestamp/%global timestamp $TIMESTAMP/g" "$SPEC_FILE"
    fi

    # hard-code commit ID
    if [ "$COMMIT_ID" != "" ] ; then
        sed -i "s/%undefine *commit_id/%global commit_id $COMMIT_ID/g" "$SPEC_FILE"
    fi

    # hard-code patch
    if [ "$PATCH" != "" ] ; then
        sed -i "s/# Patch: pki-VERSION-RELEASE.patch/Patch: $PATCH/g" "$SPEC_FILE"
    fi

    if [ "$WITH_CONSOLE" = true ] ; then
        # convert bcond_with into bcond_without to build console by default
        sed -i "s/%bcond_with *console\$/%bcond_without console/g" "$SPEC_FILE"
    fi

    # hard-code packages to build
    for package in "${PKGS_TO_SKIP[@]}"
    do
        # convert bcond_without into bcond_with to skip the package by default
        sed -i "s/^%bcond_without *\($package\)\$/%bcond_with \1/g" "$SPEC_FILE"
    done

    if [ "$RUN_TESTS" = false ] ; then
        # convert bcond_without into bcond_with to skip unit tests by default
        sed -i "s/%bcond_without *test\$/%bcond_with test/g" "$SPEC_FILE"
    fi

    # rpmlint "$SPEC_FILE"
}

while getopts v-: arg ; do
    case $arg in
    v)
        VERBOSE=true
        ;;
    -)
        LONG_OPTARG="${OPTARG#*=}"

        case $OPTARG in
        name=?*)
            NAME="$LONG_OPTARG"
            ;;
        product-name=?*)
            PRODUCT_NAME="$LONG_OPTARG"
            ;;
        product-id=?*)
            PRODUCT_ID="$LONG_OPTARG"
            ;;
        theme=?*)
            THEME="$LONG_OPTARG"
            ;;
        work-dir=?*)
            WORK_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        prefix-dir=?*)
            PREFIX_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        include-dir=?*)
            INCLUDE_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        lib-dir=?*)
            LIB_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        sysconf-dir=?*)
            SYSCONF_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        share-dir=?*)
            SHARE_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        cmake=?*)
            CMAKE=$(readlink -f "$LONG_OPTARG")
            ;;
        c-flags=?*)
            C_FLAGS="$LONG_OPTARG"
            ;;
        java-home=?*)
            # Don't convert Java home into an absolute path since that
            # will prevent PKI from running with other OpenJDK releases.
            JAVA_HOME="$LONG_OPTARG"
            ;;
        jni-dir=?*)
            JNI_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        unit-dir=?*)
            UNIT_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        python=?*)
            PYTHON=$(readlink -f "$LONG_OPTARG")
            ;;
        python-dir=?*)
            PYTHON_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        install-dir=?*)
            INSTALL_DIR=$(readlink -f "$LONG_OPTARG")
            ;;
        source-tag=?*)
            SOURCE_TAG="$LONG_OPTARG"
            ;;
        spec=?*)
            SPEC_TEMPLATE="$LONG_OPTARG"
            ;;
        with-timestamp)
            WITH_TIMESTAMP=true
            ;;
        with-commit-id)
            WITH_COMMIT_ID=true
            ;;
        dist=?*)
            DIST="$LONG_OPTARG"
            ;;
        without-java)
            WITH_JAVA=false
            ;;
        with-console)
            WITH_CONSOLE=true
            ;;
        with-pkgs=?*)
            if [ "$WITHOUT_PKGS" != "" ]; then
                echo "ERROR: The --with-pkgs and --without-pkgs options are mutually exclusive" >&2
                exit 1
            fi
            WITH_PKGS="$LONG_OPTARG"
            ;;
        without-pkgs=?*)
            if [ "$WITH_PKGS" != "" ]; then
                echo "ERROR: The --with-pkgs and --without-pkgs options are mutually exclusive" >&2
                exit 1
            fi
            WITHOUT_PKGS="$LONG_OPTARG"
            ;;
        without-test)
            RUN_TESTS=false
            ;;
        verbose)
            VERBOSE=true
            ;;
        debug)
            VERBOSE=true
            DEBUG=true
            ;;
        help)
            usage
            exit
            ;;
        '')
            break # "--" terminates argument processing
            ;;
        name* | product-name* | product-id* | theme* | work-dir* | \
        prefix-dir* | include-dir* | lib-dir* | sysconf-dir* | share-dir* | \
        cmake* | c-flags* | java-home* | jni-dir* | \
        unit-dir* | python* | python-dir* | install-dir* | \
        source-tag* | spec* | with-pkgs* | without-pkgs* | dist*)
            echo "ERROR: Missing argument for --$OPTARG option" >&2
            exit 1
            ;;
        *)
            echo "ERROR: Illegal option --$OPTARG" >&2
            exit 1
            ;;
        esac
        ;;
    \?)
        exit 1 # getopts already reported the illegal option
        ;;
    esac
done

# remove parsed options and args from $@ list
shift $((OPTIND-1))

if [ "$#" -lt 1 ] ; then
    BUILD_TARGET=dist
else
    BUILD_TARGET=$1
fi

if [ "$WORK_DIR" = "" ] ; then
    WORK_DIR="$HOME/build/$NAME"
fi

if [ "$WITH_PKGS" != "" ] ; then

    PKGS_TO_BUILD=( $(echo "$WITH_PKGS" | sed 's/ *, */ /g') )
    PKGS_TO_SKIP=()

    for package in "${ALL_PKGS[@]}"
    do
        # if package is not in PKGS_TO_BUILD, skip
        if [[ ! " ${PKGS_TO_BUILD[*]} " =~ " $package " ]]; then
            PKGS_TO_SKIP+=($package)
        fi
    done

else
    PKGS_TO_SKIP=( $(echo "$WITHOUT_PKGS" | sed 's/ *, */ /g') )
    PKGS_TO_BUILD=()

    for package in "${ALL_PKGS[@]}"
    do
        # if package is not in PKGS_TO_SKIP, build
        if [[ ! " ${PKGS_TO_SKIP[*]} " =~ " $package " ]]; then
            PKGS_TO_BUILD+=($package)
        fi
    done
fi

if [ "$DEBUG" = true ] ; then
    echo "NAME: $NAME"
    echo "WORK_DIR: $WORK_DIR"
    echo "PREFIX_DIR: $PREFIX_DIR"
    echo "INCLUDE_DIR: $INCLUDE_DIR"
    echo "LIB_DIR: $LIB_DIR"
    echo "SYSCONF_DIR: $SYSCONF_DIR"
    echo "SHARE_DIR: $SHARE_DIR"
    echo "CMAKE: $CMAKE"
    echo "C_FLAGS: $C_FLAGS"
    echo "JAVA_HOME: $JAVA_HOME"
    echo "JNI_DIR: $JNI_DIR"
    echo "PYTHON: $PYTHON"
    echo "PYTHON_DIR: $PYTHON_DIR"
    echo "UNIT_DIR: $UNIT_DIR"
    echo "INSTALL_DIR: $INSTALL_DIR"
    echo "BUILD_TARGET: $BUILD_TARGET"
fi

if [ "$BUILD_TARGET" != "dist" ] &&
        [ "$BUILD_TARGET" != "install" ] &&
        [ "$BUILD_TARGET" != "src" ] &&
        [ "$BUILD_TARGET" != "spec" ] &&
        [ "$BUILD_TARGET" != "srpm" ] &&
        [ "$BUILD_TARGET" != "rpm" ] ; then
    echo "ERROR: Invalid build target: $BUILD_TARGET" >&2
    exit 1
fi

################################################################################
# Initialization
################################################################################

if [ "$VERBOSE" = true ] ; then
    echo "Initializing $WORK_DIR"
fi

mkdir -p "$WORK_DIR"
cd "$WORK_DIR"

spec=$(<"$SPEC_TEMPLATE")

if [ "$PRODUCT_NAME" = "" ] ; then
    # if product name not specified, get from spec template

    regex=$'%global *product_name *([^\n]+)'
    if [[ $spec =~ $regex ]] ; then
        PRODUCT_NAME="${BASH_REMATCH[1]}"
    else
        echo "ERROR: Missing product_name macro in $SPEC_TEMPLATE"
        exit 1
    fi
fi

if [ "$DEBUG" = true ] ; then
    echo "PRODUCT_NAME: $PRODUCT_NAME"
fi

if [ "$PRODUCT_ID" = "" ] ; then
    # if product ID not specified, get from spec template

    regex=$'%global *product_id *([^\n]+)'
    if [[ $spec =~ $regex ]] ; then
        PRODUCT_ID="${BASH_REMATCH[1]}"
    else
        echo "ERROR: Missing product_id macro in $SPEC_TEMPLATE"
        exit 1
    fi
fi

if [ "$DEBUG" = true ] ; then
    echo "PRODUCT_ID: $PRODUCT_ID"
fi

if [ "$THEME" = "" ] ; then
    # if theme not specified, get from spec template

    regex=$'%global *theme *([^\n]+)'
    if [[ $spec =~ $regex ]] ; then
        THEME="${BASH_REMATCH[1]}"
    else
        echo "ERROR: Missing theme macro in $SPEC_TEMPLATE"
        exit 1
    fi
fi

if [ "$DEBUG" = true ] ; then
    echo "THEME: $THEME"
fi

regex=$'%global *major_version *([^\n]+)'
if [[ $spec =~ $regex ]] ; then
    MAJOR_VERSION="${BASH_REMATCH[1]}"
else
    echo "ERROR: Missing major_version macro in $SPEC_TEMPLATE"
    exit 1
fi

regex=$'%global *minor_version *([^\n]+)'
if [[ $spec =~ $regex ]] ; then
    MINOR_VERSION="${BASH_REMATCH[1]}"
else
    echo "ERROR: Missing minor_version macro in $SPEC_TEMPLATE"
    exit 1
fi

regex=$'%global *update_version *([^\n]+)'
if [[ $spec =~ $regex ]] ; then
    UPDATE_VERSION="${BASH_REMATCH[1]}"
else
    echo "ERROR: Missing update_version macro in $SPEC_TEMPLATE"
    exit 1
fi

VERSION="$MAJOR_VERSION.$MINOR_VERSION.$UPDATE_VERSION"

if [ "$DEBUG" = true ] ; then
    echo "VERSION: $VERSION"
fi

regex=$'%global *release_number *([^\n]+)'
if [[ $spec =~ $regex ]] ; then
    RELEASE_NUMBER="${BASH_REMATCH[1]}"
    RELEASE=$RELEASE_NUMBER
else
    echo "ERROR: Missing release_number macro in $SPEC_TEMPLATE"
    exit 1
fi

if [ "$DEBUG" = true ] ; then
    echo "RELEASE_NUMBER: $RELEASE_NUMBER"
fi

regex=$'%global *phase *([^\n]+)'
if [[ $spec =~ $regex ]] ; then
    PHASE="${BASH_REMATCH[1]}"
    RELEASE=$RELEASE.$PHASE
fi

if [ "$DEBUG" = true ] ; then
    echo "PHASE: $PHASE"
fi

if [ "$WITH_TIMESTAMP" = true ] ; then
    TIMESTAMP=$(date -u +"%Y%m%d%H%M%S%Z")
    RELEASE=$RELEASE.$TIMESTAMP
fi

if [ "$DEBUG" = true ] ; then
    echo "TIMESTAMP: $TIMESTAMP"
fi

if [ "$WITH_COMMIT_ID" = true ]; then
    COMMIT_ID=$(git -C "$SRC_DIR" rev-parse --short=8 HEAD)
    RELEASE=$RELEASE.$COMMIT_ID
fi

if [ "$DEBUG" = true ] ; then
    echo "COMMIT_ID: $COMMIT_ID"
fi

if [ "$DEBUG" = true ] ; then
    echo "RELEASE: $RELEASE"
fi

FULL_VERSION=$VERSION

if [ "$PHASE" != "" ]; then
    FULL_VERSION=$FULL_VERSION-$PHASE
fi

if [ "$DEBUG" = true ] ; then
    echo "FULL_VERSION: $FULL_VERSION"
fi

regex=$'%global *p11_kit_trust *([^\n]+)'
if [[ $spec =~ $regex ]] ; then
    P11_KIT_TRUST="${BASH_REMATCH[1]}"
else
    echo "ERROR: Missing p11_kit_trust macro in $SPEC_TEMPLATE"
    exit 1
fi

if [ "$DEBUG" = true ] ; then
    echo "P11_KIT_TRUST: $P11_KIT_TRUST"
fi

regex=$'%global *app_server *([^\n]+)'
if [[ $spec =~ $regex ]] ; then
    APP_SERVER="${BASH_REMATCH[1]}"
else
    echo "ERROR: Missing app_server macro in $SPEC_TEMPLATE"
    exit 1
fi

if [ "$DEBUG" = true ] ; then
    echo "APP_SERVER: $APP_SERVER"
fi

################################################################################
# Build PKI
################################################################################

if [ "$BUILD_TARGET" = "dist" ] ; then

    if [ "$VERBOSE" = true ] ; then
        echo "Building $NAME"
    fi

    OPTIONS=()

    OPTIONS+=(-S $SRC_DIR)
    OPTIONS+=(-B $WORK_DIR)

    # Set environment variables for CMake
    # (see /usr/lib/rpm/macros.d/macros.cmake)

    OPTIONS+=(-DCMAKE_C_FLAGS_RELEASE:STRING=-DNDEBUG)
    OPTIONS+=(-DCMAKE_CXX_FLAGS_RELEASE:STRING=-DNDEBUG)
    OPTIONS+=(-DCMAKE_Fortran_FLAGS_RELEASE:STRING=-DNDEBUG)
    OPTIONS+=(-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON)
    OPTIONS+=(-DCMAKE_INSTALL_DO_STRIP:BOOL=OFF)
    OPTIONS+=(-DCMAKE_INSTALL_PREFIX:PATH=$PREFIX_DIR)

    OPTIONS+=(-DINCLUDE_INSTALL_DIR:PATH=$INCLUDE_DIR)
    OPTIONS+=(-DLIB_INSTALL_DIR:PATH=$LIB_DIR)
    OPTIONS+=(-DSYSCONF_INSTALL_DIR:PATH=$SYSCONF_DIR)
    OPTIONS+=(-DSHARE_INSTALL_PREFIX:PATH=$SHARE_DIR)

    OPTIONS+=(-DLIB_SUFFIX=64)
    OPTIONS+=(-DBUILD_SHARED_LIBS:BOOL=ON)
    OPTIONS+=(-DCMAKE_C_FLAGS:STRING="$C_FLAGS")

    if [ "$VERBOSE" = true ] ; then
        OPTIONS+=(-DCMAKE_JAVA_COMPILE_FLAGS:STRING="-Xlint:deprecation")
        OPTIONS+=(-DCMAKE_INSTALL_MESSAGE:STRING=ALWAYS)
    fi

    OPTIONS+=(--no-warn-unused-cli)
    OPTIONS+=(-DPRODUCT_NAME="$PRODUCT_NAME")
    OPTIONS+=(-DTHEME=$THEME)
    OPTIONS+=(-DVERSION=$VERSION)
    OPTIONS+=(-DRELEASE=$RELEASE)

    OPTIONS+=(-DVAR_INSTALL_DIR:PATH=/var)
    OPTIONS+=(-DP11_KIT_TRUST=$P11_KIT_TRUST)

    if [ "$JAVA_HOME" != "" ] ; then
        OPTIONS+=(-DJAVA_HOME=$JAVA_HOME)
    fi

    OPTIONS+=(-DJAVA_LIB_INSTALL_DIR=$JNI_DIR)
    OPTIONS+=(-DAPP_SERVER=$APP_SERVER)

    if [ "$PYTHON" != "" ] ; then
        OPTIONS+=(-DPYTHON_EXECUTABLE=$PYTHON)
    fi

    if [ "$PYTHON_DIR" != "" ] ; then
        OPTIONS+=(-DPYTHON3_SITE_PACKAGES=$PYTHON_DIR)
    fi

    OPTIONS+=(-DSYSTEMD_LIB_INSTALL_DIR=$UNIT_DIR)

    if [ "$WITH_JAVA" = false ] ; then
        OPTIONS+=(-DWITH_JAVA=FALSE)
    fi

    for package in "${PKGS_TO_SKIP[@]}"
    do
        package=${package^^}
        OPTIONS+=(-DWITH_$package:BOOL=OFF)
    done

    for package in "${PKGS_TO_BUILD[@]}"
    do
        package=${package^^}
        OPTIONS+=(-DWITH_$package:BOOL=ON)
    done

    if [ "$WITH_CONSOLE" = true ] ; then
        OPTIONS+=(-DWITH_CONSOLE:BOOL=ON)
    fi

    if [ "$RUN_TESTS" = false ] ; then
        OPTIONS+=(-DRUN_TESTS:BOOL=OFF)
    fi

    $CMAKE "${OPTIONS[@]}"

    OPTIONS=()

    if [ "$VERBOSE" = true ] ; then
        OPTIONS+=(VERBOSE=1)
    fi

    OPTIONS+=(CMAKE_NO_VERBOSE=1)
    OPTIONS+=(--no-print-directory)

    if [ "$WITH_JAVA" = true ] ; then
        # build Java binaries
        make "${OPTIONS[@]}" java
    fi

    if [ "$THEME" != "" ] ; then
        # build PKI theme
        make "${OPTIONS[@]}" theme
    fi

    if [[ " ${PKGS_TO_BUILD[*]} " =~ " javadoc " ]]; then
        # build Javadoc
        make "${OPTIONS[@]}" javadoc
    fi

    # build native binaries
    make "${OPTIONS[@]}" all

    if [ "$RUN_TESTS" = true ] ; then
        ctest --output-on-failure
    fi

    echo
    echo "Build artifacts:"

    if [ "$WITH_JAVA" = true ] ; then
        echo "- Java binaries:"
        if [[ " ${PKGS_TO_BUILD[*]} " =~ " base " ]]; then
            echo "    $WORK_DIR/dist/pki-common.jar"
            echo "    $WORK_DIR/dist/pki-tools.jar"
        fi
        if [[ " ${PKGS_TO_BUILD[*]} " =~ " server " ]]; then
            echo "    $WORK_DIR/dist/pki-tomcat.jar"
            echo "    $WORK_DIR/dist/pki-tomcat-9.0.jar"
            echo "    $WORK_DIR/dist/pki-server.jar"
            echo "    $WORK_DIR/dist/pki-server-webapp.jar"
        fi
        if [[ " ${PKGS_TO_BUILD[*]} " =~ " ca " ]]; then
            echo "    $WORK_DIR/dist/pki-ca.jar"
        fi
        if [[ " ${PKGS_TO_BUILD[*]} " =~ " kra " ]]; then
            echo "    $WORK_DIR/dist/pki-kra.jar"
        fi
        if [[ " ${PKGS_TO_BUILD[*]} " =~ " ocsp " ]]; then
            echo "    $WORK_DIR/dist/pki-ocsp.jar"
        fi
        if [[ " ${PKGS_TO_BUILD[*]} " =~ " tks " ]]; then
            echo "    $WORK_DIR/dist/pki-tks.jar"
        fi
        if [[ " ${PKGS_TO_BUILD[*]} " =~ " tps " ]]; then
            echo "    $WORK_DIR/dist/pki-tps.jar"
        fi
        if [[ " ${PKGS_TO_BUILD[*]} " =~ " acme " ]]; then
            echo "    $WORK_DIR/dist/pki-acme.jar"
        fi
        if [[ " ${PKGS_TO_BUILD[*]} " =~ " est " ]]; then
            echo "    $WORK_DIR/dist/pki-est.jar"
        fi
        if [ "$WITH_CONSOLE" = true ] ; then
            echo "    $WORK_DIR/dist/pki-console.jar"
        fi
    fi

    echo "- native binaries:"
    echo "    $WORK_DIR/base/tools/src/main/native/pistool/src/pistool"
    echo "    $WORK_DIR/base/tools/src/main/native/revoker/revoker"
    echo "    $WORK_DIR/base/tools/src/main/native/setpin/setpin"
    echo "    $WORK_DIR/base/tools/src/main/native/tkstool/tkstool"
    echo "    $WORK_DIR/base/tools/src/main/native/tpsclient/tpsclient"

    echo "- documentation:"
    echo "    $WORK_DIR/base/common/python/man"
    echo "    $WORK_DIR/base/common/man"
    echo "    $WORK_DIR/base/tools/src/main/native/tpsclient/man"
    echo "    $WORK_DIR/base/tools/man"
    echo "    $WORK_DIR/base/server/man"
    echo "    $WORK_DIR/base/tps/man"
    echo "    $WORK_DIR/base/common/python/html"
    if [[ " ${PKGS_TO_BUILD[*]} " =~ " javadoc " ]]; then
        echo "    $WORK_DIR/base/javadoc/javadoc/pki"
    fi

    echo
    echo "To install the build: $0 install"
    echo "To create RPM packages: $0 rpm"
    echo

    exit
fi

################################################################################
# Install PKI
################################################################################

if [ "$BUILD_TARGET" = "install" ] ; then

    if [ "$VERBOSE" = true ] ; then
        echo "Installing $NAME"
    fi

    OPTIONS=()

    if [ "$VERBOSE" = true ] ; then
        OPTIONS+=(VERBOSE=1)
    fi

    OPTIONS+=(CMAKE_NO_VERBOSE=1)
    OPTIONS+=(DESTDIR=$INSTALL_DIR)
    OPTIONS+=(INSTALL="install -p")
    OPTIONS+=(--no-print-directory)

    make "${OPTIONS[@]}" install

    exit
fi

################################################################################
# Prepare RPM build
################################################################################

echo "Building $NAME-$VERSION-$RELEASE"

rm -rf BUILD
rm -rf BUILDROOT
rm -rf RPMS
rm -rf SOURCES
rm -rf SPECS
rm -rf SRPMS

mkdir BUILD
mkdir BUILDROOT
mkdir RPMS
mkdir SOURCES
mkdir SPECS
mkdir SRPMS

################################################################################
# Generate RPM sources
################################################################################

SPEC_FILE="$WORK_DIR/SPECS/$NAME.spec"

generate_rpm_sources

echo "RPM sources:"
find "$WORK_DIR/SOURCES" -type f -printf " %p\n"

if [ "$BUILD_TARGET" = "src" ] ; then
    exit
fi

################################################################################
# Generate RPM spec
################################################################################

generate_rpm_spec

echo "RPM spec:"
find "$WORK_DIR/SPECS" -type f -printf " %p\n"

if [ "$BUILD_TARGET" = "spec" ] ; then
    exit
fi

################################################################################
# Build source package
################################################################################

OPTIONS=()

OPTIONS+=(--quiet)
OPTIONS+=(--define "_topdir ${WORK_DIR}")

if [ "$DIST" != "" ] ; then
    OPTIONS+=(--define "dist .$DIST")
fi

if [ "$RUN_TESTS" = false ] ; then
    OPTIONS+=(--without test)
fi

if [ "$DEBUG" = true ] ; then
    echo "rpmbuild -bs" "${OPTIONS[@]}" " $SPEC_FILE"
fi

# build SRPM with user-provided options
rpmbuild -bs "${OPTIONS[@]}" "$SPEC_FILE"

rc=$?

if [ $rc != 0 ]; then
    echo "ERROR: Unable to build SRPM package"
    exit 1
fi

SRPM="$(find "$WORK_DIR/SRPMS" -type f)"

echo "SRPM package:"
echo " $SRPM"

if [ "$BUILD_TARGET" = "srpm" ] ; then
    exit
fi

################################################################################
# Build binary packages
################################################################################

OPTIONS=()

if [ "$VERBOSE" = true ] ; then
    OPTIONS+=(--define "_verbose 1")
fi

OPTIONS+=(--define "_topdir ${WORK_DIR}")

if [ "$DEBUG" = true ] ; then
    echo "rpmbuild --rebuild" "${OPTIONS[@]}" "$SRPM"
fi

# rebuild RPM with hard-coded options in SRPM
rpmbuild --rebuild "${OPTIONS[@]}" "$SRPM"

rc=$?

if [ $rc != 0 ]; then
    echo "ERROR: Unable to build RPM packages"
    exit 1
fi

# install SRPM to restore sources and spec file removed during rebuild
rpm -i --define "_topdir $WORK_DIR" "$SRPM"

# flatten folder
find "$WORK_DIR/RPMS" -mindepth 2 -type f -exec mv -i '{}' "$WORK_DIR/RPMS" ';'

# remove empty subfolders
find "$WORK_DIR/RPMS" -mindepth 1 -type d -delete

echo "RPM packages:"
find "$WORK_DIR/RPMS" -type f -printf " %p\n"
