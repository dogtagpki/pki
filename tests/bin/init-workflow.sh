#!/bin/bash -e

if [ "$BASE64_MATRIX" == "" ]
then
    MATRIX="{\"os\":[\"34\"]}"
else
    MATRIX=$(echo "$BASE64_MATRIX" | base64 -d)
fi

echo "MATRIX: $MATRIX"
echo "::set-output name=matrix::$MATRIX"

if [ "$BASE64_REPO" == "" ]
then
    REPO="@pki/10.12"
else
    REPO=$(echo "$BASE64_REPO" | base64 -d)
fi

echo "REPO: $REPO"
echo "::set-output name=repo::$REPO"
