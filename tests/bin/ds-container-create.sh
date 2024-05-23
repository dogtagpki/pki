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
    echo "Missing Directory Manager password"
    exit 1
fi

if [ "$IMAGE" == "" ]
then
    IMAGE=quay.io/389ds/dirsrv
fi

create_server() {

    echo "Creating DS server"

    OPTIONS=()
    OPTIONS+=(--hostname=$HOSTNAME)

    if [ "$NETWORK" != "" ]
    then
        OPTIONS+=(--network=$NETWORK)
    fi

    if [ "$ALIAS" != "" ]
    then
        OPTIONS+=(--network-alias=$ALIAS)
    fi

    $SCRIPT_DIR/runner-init.sh "${OPTIONS[@]}" $NAME

    docker exec $NAME dnf install -y 389-ds-base

    docker exec $NAME dscreate create-template ds.inf

    docker exec $NAME sed -i \
        -e "s/;instance_name = .*/instance_name = localhost/g" \
        -e "s/;port = .*/port = 3389/g" \
        -e "s/;secure_port = .*/secure_port = 3636/g" \
        -e "s/;root_password = .*/root_password = Secret.123/g" \
        -e "s/;suffix = .*/suffix = dc=example,dc=com/g" \
        -e "s/;self_sign_cert = .*/self_sign_cert = False/g" \
        ds.inf

    docker exec $NAME dscreate from-file ds.inf
}

create_container() {

    echo "Creating DS volume"

    docker volume create $NAME-data > /dev/null

    echo "Creating DS container"

    docker create \
        --name=$NAME \
        --hostname=$HOSTNAME \
        -v $NAME-data:/data \
        -v $GITHUB_WORKSPACE:$SHARED \
        -e DS_DM_PASSWORD=$PASSWORD \
        -p 3389 \
        -p 3636 \
        $IMAGE > /dev/null

    OPTIONS=()
    OPTIONS+=(--image=$IMAGE)
    OPTIONS+=(--password=$PASSWORD)

    $SCRIPT_DIR/ds-start.sh "${OPTIONS[@]}" $NAME

    echo "Creating certs folder"

    docker exec $NAME mkdir -p /data/tls/ca

    echo "Creating database backend"

    docker exec $NAME dsconf localhost backend create \
        --suffix dc=example,dc=com \
        --be-name userRoot > /dev/null

    docker exec $NAME dsconf localhost backend suffix list
}

add_base_entries() {

    echo "Adding base entries"

    docker exec -i $NAME ldapadd \
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
}

if [ "$IMAGE" == "pki-runner" ]
then
    create_server
else
    create_container
fi

add_base_entries

docker exec $NAME ldapsearch \
    -H ldap://$HOSTNAME:3389 \
    -D "cn=Directory Manager" \
    -w $PASSWORD \
    -x \
    -b "dc=example,dc=com"

echo "DS container is ready"
