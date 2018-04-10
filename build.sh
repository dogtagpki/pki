#!/bin/bash -e

# BEGIN COPYRIGHT BLOCK
# (C) 2018 Red Hat, Inc.
# All rights reserved.
# END COPYRIGHT BLOCK

NAME=pki

SCRIPT_PATH=`readlink -f "$0"`
SCRIPT_NAME=`basename "$SCRIPT_PATH"`
SRC_DIR=`dirname "$SCRIPT_PATH"`

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] <target>"
    echo
    echo "Options:"
    echo "    --work-dir <path>    Build directory (default: ~/build/$NAME)."
    echo "    --with-timestamp     Append timestamp to release number."
    echo "    --with-commit-id     Append commit ID to release number."
    echo "    --without-test       Do not run unit tests."
    echo "    --without-server     Do not build server packages."
    echo "    --without-javadoc    Do not build javadoc package."
    echo "    --without-console    Do not build console package."
    echo "    --without-theme      Do not build theme packages."
    echo "    --without-meta       Do not build meta package."
    echo "    --without-debug      Do not build debug packages."
    echo " -v,--verbose            Run in verbose mode."
    echo "    --debug              Run in debug mode."
    echo "    --help               Show help message."
    echo
    echo "Target:"
    echo "    spec   Generate RPM spec."
    echo "    src    Generate RPM sources."
    echo "    srpm   Build SRPM package."
    echo "    rpm    Build RPM packages."
}

WORK_DIR="$HOME/build/$NAME"
BUILD_TARGET=rpm

WITH_TIMESTAMP=
WITH_COMMIT_ID=

WITHOUT_TEST=
WITHOUT_SERVER=
WITHOUT_JAVADOC=
WITHOUT_CONSOLE=
WITHOUT_THEME=
WITHOUT_META=
WITHOUT_DEBUG=

VERBOSE=
DEBUG=

while getopts v-: arg ; do
    case $arg in
    v)
        VERBOSE=true
        ;;
    -)
        LONG_OPTARG="${OPTARG#*=}"

        case $OPTARG in
        work-dir=?*)
            WORK_DIR="$LONG_OPTARG"
            ;;
        with-timestamp)
            WITH_TIMESTAMP=true
            ;;
        with-commit-id)
            WITH_COMMIT_ID=true
            ;;
        without-test)
            WITHOUT_TEST=true
            ;;
        without-server)
            WITHOUT_SERVER=true
            ;;
        without-javadoc)
            WITHOUT_JAVADOC=true
            ;;
        without-console)
            WITHOUT_CONSOLE=true
            ;;
        without-theme)
            WITHOUT_THEME=true
            ;;
        without-meta)
            WITHOUT_META=true
            ;;
        without-debug)
            WITHOUT_DEBUG=true
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
        work-dir*)
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
    usage
    exit
fi

BUILD_TARGET=$1

if [ "$DEBUG" = true ] ; then
    echo "WORK_DIR: $WORK_DIR"
    echo "BUILD_TARGET: $BUILD_TARGET"
fi

if [ "$BUILD_TARGET" != "spec" ] &&
        [ "$BUILD_TARGET" != "src" ] &&
        [ "$BUILD_TARGET" != "srpm" ] &&
        [ "$BUILD_TARGET" != "rpm" ] ; then
    echo "ERROR: Invalid build target: $BUILD_TARGET" >&2
    exit 1
fi

SPEC_TEMPLATE="$SRC_DIR/specs/pki.spec.in"
VERSION="`rpmspec -P "$SPEC_TEMPLATE" | grep "^Version:" | awk '{print $2;}'`"

if [ "$DEBUG" = true ] ; then
    echo "VERSION: $VERSION"
fi

RELEASE="`rpmspec -P "$SPEC_TEMPLATE" --undefine dist | grep "^Release:" | awk '{print $2;}'`"

if [ "$DEBUG" = true ] ; then
    echo "RELEASE: $RELEASE"
fi

if [ "$WITH_TIMESTAMP" = true ] ; then
    TIMESTAMP=`date +"%Y%m%d%H%M%S"`
    _TIMESTAMP=`printf ".%.14s" $TIMESTAMP`
fi

if [ "$DEBUG" = true ] ; then
    echo "TIMESTAMP: $TIMESTAMP"
fi

if [ "$WITH_COMMIT_ID" = true ]; then
    COMMIT_ID=`git -C "$SRC_DIR" rev-parse --short=8 HEAD`
    _COMMIT_ID=`printf ".%.8s" $COMMIT_ID`
fi

if [ "$DEBUG" = true ] ; then
    echo "COMMIT_ID: $COMMIT_ID"
fi

echo "Building $NAME-$VERSION-$RELEASE${_TIMESTAMP}${_COMMIT_ID}"

################################################################################
# Initialize working directory
################################################################################

if [ "$VERBOSE" = true ] ; then
    echo "Initializing $WORK_DIR"
fi

mkdir -p $WORK_DIR
cd $WORK_DIR

rm -rf BUILD
rm -rf RPMS
rm -rf SOURCES
rm -rf SPECS
rm -rf SRPMS

mkdir BUILD
mkdir RPMS
mkdir SOURCES
mkdir SPECS
mkdir SRPMS

################################################################################
# Generate RPM spec
################################################################################

RPM_SPEC="$WORK_DIR/SPECS/pki.spec"

if [ "$VERBOSE" = true ] ; then
    echo "Generating $RPM_SPEC"
fi

sed "s/%{?_timestamp}/${_TIMESTAMP}/g; s/%{?_commit_id}/${_COMMIT_ID}/g" \
    "$SPEC_TEMPLATE" > "$RPM_SPEC"

echo "RPM spec:"
echo " $RPM_SPEC"

if [ "$BUILD_TARGET" = "spec" ] ; then
    exit
fi

################################################################################
# Generate RPM sources
################################################################################

TARBALL="$WORK_DIR/SOURCES/pki-$VERSION.tar.gz"

if [ "$VERBOSE" = true ] ; then
    echo "Generating $TARBALL"
fi

tar czf "$TARBALL" \
 --transform "s,^./,pki-$VERSION/," \
 --exclude .git \
 --exclude .svn \
 --exclude .swp \
 --exclude .metadata \
 --exclude build \
 --exclude .tox \
 --exclude dist \
 --exclude MANIFEST \
 --exclude *.pyc \
 --exclude __pycache__ \
 -C "$SRC_DIR" \
 .

echo "RPM sources:"
find "$WORK_DIR/SOURCES" -type f -printf " %p\n"

if [ "$BUILD_TARGET" = "src" ] ; then
    exit
fi

################################################################################
# Construct rpmbuild options
################################################################################

OPTIONS=()

if [ "$BUILD_TARGET" = "srpm" ] ; then
    OPTIONS+=(--bs)

elif [ "$BUILD_TARGET" = "rpm" ] ; then
    OPTIONS+=(--ba)
fi

if [ "$VERBOSE" = true ] ; then
    OPTIONS+=(--define "_verbose 1")
else
    OPTIONS+=(--quiet)
fi

OPTIONS+=(--define "_topdir ${WORK_DIR}")

if [ "$WITH_TIMESTAMP" = true ] ; then
    OPTIONS+=(--define "_timestamp ${_TIMESTAMP}")
fi

if [ "$WITH_COMMIT_ID" = true ] ; then
    OPTIONS+=(--define "_commit_id ${_COMMIT_ID}")
fi

if [ "$WITHOUT_TEST" = true ] ; then
    OPTIONS+=(--without test)
fi

if [ "$WITHOUT_SERVER" = true ] ; then
    OPTIONS+=(--without server)
fi

if [ "$WITHOUT_JAVADOC" = true ] ; then
    OPTIONS+=(--without javadoc)
fi

if [ "$WITHOUT_CONSOLE" = true ] ; then
    OPTIONS+=(--without console)
fi

if [ "$WITHOUT_THEME" = true ] ; then
    OPTIONS+=(--without theme)
fi

if [ "$WITHOUT_META" = true ] ; then
    OPTIONS+=(--without meta)
fi

if [ "$WITHOUT_DEBUG" = true ] ; then
    OPTIONS+=(--define "debug_package %{nil}")
fi

################################################################################
# Build packages
################################################################################

if [ "$DEBUG" = true ] ; then
    echo "rpmbuild "${OPTIONS[@]}" $RPM_SPEC"
fi

rpmbuild "${OPTIONS[@]}" "$RPM_SPEC"

echo "SRPM package:"
find "$WORK_DIR/SRPMS" -type f -printf " %p\n"

if [ "$BUILD_TARGET" = "srpm" ] ; then
    exit
fi

# flatten folder
find "$WORK_DIR/RPMS" -mindepth 2 -type f -exec mv -i '{}' "$WORK_DIR/RPMS" ';'

# remove empty subfolders
rm -rf "$WORK_DIR/RPMS/*/"

echo "RPM packages:"
find "$WORK_DIR/RPMS" -type f -printf " %p\n"
