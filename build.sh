#!/bin/bash -e

# BEGIN COPYRIGHT BLOCK
# (C) 2018 Red Hat, Inc.
# All rights reserved.
# END COPYRIGHT BLOCK

NAME=pki

SCRIPT_PATH=`readlink -f "$0"`
SCRIPT_NAME=`basename "$SCRIPT_PATH"`

SRC_DIR=`dirname "$SCRIPT_PATH"`
WORK_DIR="$HOME/build/$NAME"

SOURCE_TAG=

WITH_TIMESTAMP=
WITH_COMMIT_ID=

WITHOUT_TEST=

WITH_PKGS=
WITHOUT_PKGS=

VERBOSE=
DEBUG=

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS] <target>"
    echo
    echo "Options:"
    echo "    --work-dir=<path>      Working directory (default: $WORK_DIR)."
    echo "    --source-tag=<tag>     Generate RPM sources from a source tag."
    echo "    --with-timestamp       Append timestamp to release number."
    echo "    --with-commit-id       Append commit ID to release number."
    echo "    --without-test         Do not run unit tests."
    echo "    --with-pkgs=<list>     Build packages specified in comma-separated list only."
    echo "    --without-pkgs=<list>  Build everything except packages specified in comma-separated list."
    echo " -v,--verbose              Run in verbose mode."
    echo "    --debug                Run in debug mode."
    echo "    --help                 Show help message."
    echo
    echo "Packages:"
    echo "    base, server, ca, kra, ocsp, tks, tps, javadoc, console, theme, meta, debug"
    echo
    echo "Target:"
    echo "    spec   Generate RPM spec."
    echo "    src    Generate RPM sources."
    echo "    srpm   Build SRPM package."
    echo "    rpm    Build RPM packages."
}

generate_rpm_spec() {

    RPM_SPEC="$NAME.spec"

    if [ "$VERBOSE" = true ] ; then
        echo "Generating $RPM_SPEC"
    fi

    # update timestamp and commit ID
    sed "s/%{?_timestamp}/${_TIMESTAMP}/g; s/%{?_commit_id}/${_COMMIT_ID}/g" \
        "$SPEC_TEMPLATE" > "$WORK_DIR/SPECS/$RPM_SPEC"

    if [ "$SOURCE_TAG" != "" ] &&
        [ "$SOURCE_TAG" != "HEAD" ] ; then

        PATCH="$NAME-$VERSION-$RELEASE.patch"

        # update patch
        sed "s/# Patch: pki-VERSION-RELEASE.patch/Patch: $PATCH/g" \
            "$WORK_DIR/SPECS/$RPM_SPEC" > "$WORK_DIR/SPECS/$RPM_SPEC.tmp"
        mv "$WORK_DIR/SPECS/$RPM_SPEC.tmp" "$WORK_DIR/SPECS/$RPM_SPEC"
    fi

    rpmlint "$WORK_DIR/SPECS/$RPM_SPEC"
}

generate_patch() {

    if [ "$VERBOSE" = true ] ; then
        echo "Generating $PATCH for all changes since $SOURCE_TAG tag"
    fi

    git -C "$SRC_DIR" \
        format-patch \
        --stdout \
        $SOURCE_TAG \
        > "$WORK_DIR/SOURCES/$PATCH"
}

generate_rpm_sources() {

    TARBALL="$NAME-$VERSION.tar.gz"

    if [ "$SOURCE_TAG" != "" ] ; then

        if [ "$VERBOSE" = true ] ; then
            echo "Generating $TARBALL from $SOURCE_TAG tag"
        fi

        git -C "$SRC_DIR" \
            archive \
            --format=tar.gz \
            --prefix $NAME-$VERSION/ \
            -o "$WORK_DIR/SOURCES/$TARBALL" \
            $SOURCE_TAG

        if [ "$SOURCE_TAG" != "HEAD" ] ; then
            generate_patch
        fi

        return
    fi

    if [ "$VERBOSE" = true ] ; then
        echo "Generating $TARBALL"
    fi

    tar czf "$WORK_DIR/SOURCES/$TARBALL" \
        --transform "s,^./,$NAME-$VERSION/," \
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
}

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
        source-tag=?*)
            SOURCE_TAG="$LONG_OPTARG"
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
        work-dir* | source-tag* | with-pkgs* | without-pkgs*)
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
    echo "ERROR: Missing build target" >&2
    usage
    exit 1
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

SPEC_TEMPLATE="$SRC_DIR/specs/$NAME.spec.in"
VERSION="`rpmspec -P "$SPEC_TEMPLATE" | grep "^Version:" | awk '{print $2;}'`"

if [ "$DEBUG" = true ] ; then
    echo "VERSION: $VERSION"
fi

RELEASE="`rpmspec -P "$SPEC_TEMPLATE" --undefine dist | grep "^Release:" | awk '{print $2;}'`"

if [ "$DEBUG" = true ] ; then
    echo "RELEASE: $RELEASE"
fi

if [ "$WITH_TIMESTAMP" = true ] ; then
    TIMESTAMP="`date +"%Y%m%d%H%M%S"`"
    _TIMESTAMP=".$TIMESTAMP"
fi

if [ "$DEBUG" = true ] ; then
    echo "TIMESTAMP: $TIMESTAMP"
fi

if [ "$WITH_COMMIT_ID" = true ]; then
    COMMIT_ID="`git -C "$SRC_DIR" rev-parse --short=8 HEAD`"
    _COMMIT_ID=".$COMMIT_ID"
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

generate_rpm_spec

echo "RPM spec:"
find "$WORK_DIR/SPECS" -type f -printf " %p\n"

if [ "$BUILD_TARGET" = "spec" ] ; then
    exit
fi

################################################################################
# Generate RPM sources
################################################################################

generate_rpm_sources

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
    OPTIONS+=(-bs)

elif [ "$BUILD_TARGET" = "rpm" ] ; then
    OPTIONS+=(-ba)
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

if [ "$WITH_PKGS" != "" ] ; then

    # Build specified packages only.
    OPTIONS+=(--with pkgs)

    # Don't build debug package unless specified.
    WITHOUT_DEBUG=true

    # Parse comma-separated list of packages.
    for package in `echo $WITH_PKGS | sed 's/,/\n/g'`
    do
        if [ "$package" == "debug" ] ; then
            # Build debug package.
            WITHOUT_DEBUG=
        else
            # Build specified package.
            OPTIONS+=(--with $package)
        fi
    done

else
    # Build everything except specified packages.
    # Do not add --with pkgs into OPTIONS.

    # Build debug package unless specified.
    WITHOUT_DEBUG=

    # Parse comma-separated list of packages.
    for package in `echo $WITHOUT_PKGS | sed 's/,/\n/g'`
    do
        if [ "$package" == "debug" ] ; then
            # Don't build debug package.
            WITHOUT_DEBUG=true
        else
            # Don't build specified package.
            OPTIONS+=(--without $package)
        fi
    done
fi

if [ "$WITHOUT_DEBUG" = true ] ; then
    OPTIONS+=(--define "debug_package %{nil}")
fi

################################################################################
# Build packages
################################################################################

if [ "$DEBUG" = true ] ; then
    echo "rpmbuild "${OPTIONS[@]}" $WORK_DIR/SPECS/$RPM_SPEC"
fi

rpmbuild "${OPTIONS[@]}" "$WORK_DIR/SPECS/$RPM_SPEC"

echo "SRPM package:"
find "$WORK_DIR/SRPMS" -type f -printf " %p\n"

if [ "$BUILD_TARGET" = "srpm" ] ; then
    exit
fi

# flatten folder
find "$WORK_DIR/RPMS" -mindepth 2 -type f -exec mv -i '{}' "$WORK_DIR/RPMS" ';'

# remove empty subfolders
find "$WORK_DIR/RPMS" -mindepth 1 -type d -delete

echo "RPM packages:"
find "$WORK_DIR/RPMS" -type f -printf " %p\n"
