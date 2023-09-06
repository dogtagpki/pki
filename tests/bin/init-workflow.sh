#!/bin/bash -e

################################################################################
# Database image

if [ "$BASE64_DATABASE" != "" ]
then
    DATABASE=$(echo "$BASE64_DATABASE" | base64 -d)
    DB_IMAGE=$(echo "$DATABASE" | jq -r .image)
fi

echo "DB_IMAGE: $DB_IMAGE"
echo "db-image=$DB_IMAGE" >> $GITHUB_OUTPUT
