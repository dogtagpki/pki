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
