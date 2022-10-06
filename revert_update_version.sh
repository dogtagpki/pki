#!/bin/bash -e

# Use this script to revert the commit and delete the tag created using the update_version.sh script.

HEAD_TAG=$(git tag --points-at HEAD)

HEAD_COMMIT_MESSAGE=$(git log --format=%B -n 1 HEAD)
UPDATE_COMMIT_MESSAGE="Updating version to"

# Only proceed if the HEAD commit is a version update

if [[ "$HEAD_COMMIT_MESSAGE=" == *"$UPDATE_COMMIT_MESSAGE"* ]]; then
    git tag -d "$HEAD_TAG"
    git reset --hard HEAD~1
else
    echo "The HEAD commit is not a version update, aborting."
    exit 1
fi

