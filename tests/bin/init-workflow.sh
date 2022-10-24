#!/bin/bash -e

if [ "$BASE64_MATRIX" == "" ]
then
    MATRIX="{\"os\":[\"latest\"]}"
else
    MATRIX=$(echo "$BASE64_MATRIX" | base64 -d)
fi

echo "MATRIX: $MATRIX"
echo "matrix=$MATRIX" >> $GITHUB_OUTPUT

if [ "$BASE64_REPO" == "" ]
then
    REPO="@pki/11.0"
else
    REPO=$(echo "$BASE64_REPO" | base64 -d)
fi

echo "REPO: $REPO"
echo "repo=$REPO" >> $GITHUB_OUTPUT
