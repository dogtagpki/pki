#!/bin/bash -e

if [ "$BASE64_OS" != "" ]
then
    OS_VERSION=$(echo "$BASE64_OS" | base64 -d)
else
    OS_VERSION=34
fi

BASE_IMAGE=registry.fedoraproject.org/fedora:$OS_VERSION
echo "BASE_IMAGE: $BASE_IMAGE"
echo "base-image=$BASE_IMAGE" >> $GITHUB_OUTPUT

if [ "$BASE64_REPO" == "" ]
then
    REPO=""
else
    REPO=$(echo "$BASE64_REPO" | base64 -d)
fi

echo "REPO: $REPO"
echo "repo=$REPO" >> $GITHUB_OUTPUT
