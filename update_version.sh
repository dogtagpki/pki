#!/bin/bash -e

# Use this script to automate updating pki version.
#
# Usage: ./update_version.sh <major> <minor> <update> <phase> # (phase is optional)
#
# Explanation:
# -    change_spec_version
# -        Updates the spec version to the new version provided
# -    commit_version_change
# -        Commits that change
# -    create_tag
# -        Creates a tag based on the new version provided
# -    create_source_tarball
# -        Creates a source tarball based on the new version provided

NEXT_MAJOR=$1
NEXT_MINOR=$2
NEXT_UPDATE=$3
NEXT_PHASE=$4

if [ -z "$NEXT_PHASE" ] ; then
    NEXT_VERSION=$NEXT_MAJOR.$NEXT_MINOR.$NEXT_UPDATE
else
    NEXT_VERSION=$NEXT_MAJOR.$NEXT_MINOR.$NEXT_UPDATE-$NEXT_PHASE
fi
echo "New version is $NEXT_VERSION"

verify_phase() {
    if [[ "$NEXT_PHASE" =~ ^(alpha|beta)[0-9]+$ ]] ; then
        echo "$NEXT_PHASE is a valid phase"
    elif [ -z "$NEXT_PHASE" ] ; then
        echo "Empty phase"
    else
        echo "$NEXT_PHASE is an invalid phase, aborting"
        exit 1
    fi
}

change_spec_version() {
    CURRENT_MAJOR=$(grep "major_version " pki.spec | grep -Eo '[0-9]+$')
    CURRENT_MINOR=$(grep "minor_version " pki.spec | grep -Eo '[0-9]+$')
    CURRENT_UPDATE=$(grep "update_version " pki.spec | grep -Eo '[0-9]+$')
    CURRENT_PHASE=$(grep "phase " pki.spec | grep -E 'alpha|beta' | awk '{print $(NF)}')

    echo "Update major version to $NEXT_MAJOR"
    sed -i "/major_version /c\%global           major_version $NEXT_MAJOR" pki.spec
    echo "Update minor version to $NEXT_MINOR"
    sed -i "/minor_version /c\%global           minor_version $NEXT_MINOR" pki.spec
    echo "Update update version to $NEXT_UPDATE"
    sed -i "/update_version /c\%global           update_version $NEXT_UPDATE" pki.spec

    if [[ "$CURRENT_PHASE" != "$NEXT_PHASE" ]] ; then
        if [ -z "$NEXT_PHASE" ] ; then
            echo "Remove phase"
            sed -i "/phase /c\#global           phase" pki.spec
        elif [ -z "$CURRENT_PHASE" ] ; then
            echo "Add phase, set to $NEXT_PHASE"
            sed -i "/#global           phase/c\%global           phase $NEXT_PHASE" pki.spec
        else
            echo "Update phase to $NEXT_PHASE"
            sed -i "/phase /c\%global           phase $NEXT_PHASE" pki.spec
        fi
    fi
}

commit_version_change() {
    git add pki.spec
    git commit -m "Updating version to v$NEXT_VERSION"
 }

create_tag() {
    git tag v"$NEXT_VERSION"
}

create_source_tarball() {
    ./build.sh --source-tag=v"$NEXT_VERSION" src
}

### Perform operations

verify_phase
change_spec_version
commit_version_change
create_tag
create_source_tarball
