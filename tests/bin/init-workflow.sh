#!/bin/bash -e

if [ "$BASE64_MATRIX" == "" ]
then
    MATRIX="{\"os\":[\"latest\"]}"
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

if [ "$BASE64_DATABASE" != "" ]
then
    DATABASE=$(echo "$BASE64_DATABASE" | base64 -d)
    DB_IMAGE=$(echo "$DATABASE" | jq -r .image)
fi

echo "DB_IMAGE: $DB_IMAGE"
echo "::set-output name=db-image::$DB_IMAGE"
