#!/bin/bash -e

release_branch='^v[0-9]+\.[0-9]+$'
release_branch_with_suffix='^v[0-9]+\.[0-9]+-.*$'

if [ "$BASE_IMAGE" = "" ]; then
    # By default use fedora:latest to provide a stable development platform.
    # For release branches use the target Fedora version (e.g. rawhide).
    if [[ "$BRANCH_NAME" =~ ^v11\.9$ ]] \
            || [[ "$BRANCH_NAME" =~ ^v11\.9-.*$ ]]; then
        BASE_IMAGE=registry.fedoraproject.org/fedora:44
        echo "BASE_IMAGE=$BASE_IMAGE" | tee -a $GITHUB_ENV

    elif [[ "$BRANCH_NAME" =~ $release_branch ]] \
            || [[ "$BRANCH_NAME" =~ $release_branch_with_suffix ]]; then
        BASE_IMAGE=registry.fedoraproject.org/fedora:rawhide
        echo "BASE_IMAGE=$BASE_IMAGE" | tee -a $GITHUB_ENV

    else
        BASE_IMAGE=registry.fedoraproject.org/fedora:latest
        echo "BASE_IMAGE=$BASE_IMAGE" | tee -a $GITHUB_ENV
    fi
fi

if [ "$COPR_REPO" = "" ]; then
    # By default use @pki/master for development (e.g. to try new dependencies).
    # For release branches don't use COPR repo since the dependencies should
    # have already been added into the official Fedora repository.
    if [[ "$BRANCH_NAME" =~ $release_branch ]] \
            || [[ "$BRANCH_NAME" =~ $release_branch_with_suffix ]]; then
        : # skip

    else
        COPR_REPO=@pki/master
        echo "COPR_REPO=$COPR_REPO" | tee -a $GITHUB_ENV
    fi
fi
