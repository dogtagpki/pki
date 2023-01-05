#!/bin/bash -e

if [ "$BASE64_OS" != "" ]
then
    OS_VERSION=$(echo "$BASE64_OS" | base64 -d)
else
    OS_VERSION=latest
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

if [ "$BASE64_DATABASE" != "" ]
then
    DATABASE=$(echo "$BASE64_DATABASE" | base64 -d)
    DB_IMAGE=$(echo "$DATABASE" | jq -r .image)
fi

echo "DB_IMAGE: $DB_IMAGE"
echo "db-image=$DB_IMAGE" >> $GITHUB_OUTPUT
