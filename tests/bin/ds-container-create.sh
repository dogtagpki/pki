#!/bin/bash -e

# https://fy.blackhats.net.au/blog/html/2020/03/28/389ds_in_containers.html

SCRIPT_PATH=`readlink -f "$0"`
SCRIPT_NAME=`basename "$SCRIPT_PATH"`
SCRIPT_DIR=`dirname "$SCRIPT_PATH"`

NAME=$1

if [ "$NAME" == "" ]
then
    echo "Usage: ds-container-create.sh <name>"
    exit 1
fi

if [ "$PASSWORD" == "" ]
then
    PASSWORD=Secret.123
fi

max_wait=60 # seconds

echo "Creating DS container"

docker create \
    --name=$NAME \
    --hostname=$HOSTNAME \
    -e DS_DM_PASSWORD=$PASSWORD \
    quay.io/389ds/dirsrv > /dev/null

$SCRIPT_DIR/ds-container-start.sh $NAME

echo "Creating suffix"

docker exec $NAME \
    dsconf localhost backend create \
        --suffix dc=example,dc=com \
        --be-name userRoot > /dev/null

echo "Adding base entries"

docker exec $NAME \
    ldapadd \
    -H ldap://$HOSTNAME:3389 \
    -D "cn=Directory Manager" \
    -w $PASSWORD \
    -x > /dev/null << EOF
dn: dc=example,dc=com
objectClass: domain
dc: example

dn: dc=pki,dc=example,dc=com
objectClass: domain
dc: pki
EOF

echo "DS container is ready"
