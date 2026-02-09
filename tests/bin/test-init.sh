#!/bin/bash -e

if [ "$BASE_IMAGE" = "" ]; then
    # For master branch use fedora:latest to provide a stable development
    # platform. For other branches use the target Fedora version.
    if [ "$BRANCH_NAME" = "master" ]; then
        BASE_IMAGE=registry.fedoraproject.org/fedora:latest
        echo "BASE_IMAGE=$BASE_IMAGE" | tee -a $GITHUB_ENV

    elif [ "$BRANCH_NAME" = "v11.9" ]; then
        BASE_IMAGE=registry.fedoraproject.org/fedora:44
        echo "BASE_IMAGE=$BASE_IMAGE" | tee -a $GITHUB_ENV
    fi
fi

if [ "$COPR_REPO" = "" ]; then
    # For master branch use @pki/master to introduce new dependencies.
    # For other branches don't use COPR repo since the dependencies
    # should have already been added into the official Fedora repository.
    if [ "$BRANCH_NAME" = "master" ]
    then
        COPR_REPO=@pki/master
        echo "COPR_REPO=$COPR_REPO" | tee -a $GITHUB_ENV
    fi
fi
