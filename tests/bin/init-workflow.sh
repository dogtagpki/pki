#!/bin/bash -e

if [ "$BASE64_MATRIX" == "" ]
then
    latest=$(cat /etc/fedora-release | awk '{ print $3 }')
    previous=$(cat /etc/fedora-release | awk '{ print $3 - 1 }')
    MATRIX="{\"os\":[\"$previous\", \"$latest\"]}"
else
    MATRIX=$(echo "$BASE64_MATRIX" | base64 -d)
fi

echo "MATRIX: $MATRIX"
echo "::set-output name=matrix::$MATRIX"

if [ "$BASE64_REPO" == "" ]
then
    REPO="@pki/master"
else
    REPO=$(echo "$BASE64_REPO" | base64 -d)
fi

echo "REPO: $REPO"
echo "::set-output name=repo::$REPO"
