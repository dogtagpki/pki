#!/bin/bash -e

# https://fy.blackhats.net.au/blog/html/2020/03/28/389ds_in_containers.html

SCRIPT_PATH=$(readlink -f "$0")
SCRIPT_NAME=$(basename "$SCRIPT_PATH")
SCRIPT_DIR=$(dirname "$SCRIPT_PATH")

SUFFIX=
BASE_DN=

VERBOSE=
DEBUG=

usage() {
    echo "Usage: $SCRIPT_NAME [OPTIONS]"
    echo
    echo "Options:"
    echo "    --suffix=<DN>          Suffix (default: dc=example,dc=com)"
    echo "    --base-dn=<DN>         Base DN (default: dc=pki,dc=example,dc=com)"
    echo " -v,--verbose              Run in verbose mode."
    echo "    --debug                Run in debug mode."
    echo "    --help                 Show help message."
}

while getopts v-: arg ; do
    case $arg in
    v)
        VERBOSE=true
        ;;
    -)
        LONG_OPTARG="${OPTARG#*=}"

        case $OPTARG in
        suffix=?*)
            SUFFIX="$LONG_OPTARG"
            ;;
        base-dn=?*)
            BASE_DN="$LONG_OPTARG"
            ;;
        verbose)
            VERBOSE=true
            ;;
        debug)
            VERBOSE=true
            DEBUG=true
            ;;
        help)
            usage
            exit
            ;;
        '')
            break # "--" terminates argument processing
            ;;
        suffix* | base-dn*)
            echo "ERROR: Missing argument for --$OPTARG option" >&2
            exit 1
            ;;
        *)
            echo "ERROR: Illegal option --$OPTARG" >&2
            exit 1
            ;;
        esac
        ;;
    \?)
        exit 1 # getopts already reported the illegal option
        ;;
    esac
done

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
        -e "s/;root_password = .*/root_password = $PASSWORD/g" \
        -e "s/;suffix = .*/suffix = $SUFFIX/g" \
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

    $SCRIPT_DIR/ds-container-start.sh "${OPTIONS[@]}" $NAME

    echo "Creating certs folder"

    docker exec $NAME mkdir -p /data/tls/ca

    echo "Creating database backend"

    docker exec $NAME dsconf localhost backend create \
        --suffix "$SUFFIX" \
        --be-name userRoot > /dev/null

    docker exec $NAME dsconf localhost backend suffix list
}

add_base_entries() {

    echo "Adding base entries"

    SUFFIX_DC=$(echo "$SUFFIX" | sed 's/^dc=\([^,]*\),.*$/\1/')
    BASE_DC=$(echo "$BASE_DN" | sed 's/^dc=\([^,]*\),.*$/\1/')

    docker exec -i $NAME ldapadd \
        -H ldap://$HOSTNAME:3389 \
        -D "cn=Directory Manager" \
        -w $PASSWORD \
        -x > /dev/null << EOF
dn: $SUFFIX
objectClass: domain
dc: $SUFFIX_DC

dn: $BASE_DN
objectClass: domain
dc: $BASE_DC
EOF
}

# remove parsed options and args from $@ list
shift $((OPTIND-1))

NAME=$1

if [ "$NAME" = "" ]
then
    echo "Usage: ds-container-create.sh <name>"
    exit 1
fi

if [ "$PASSWORD" = "" ]
then
    echo "Missing Directory Manager password"
    exit 1
fi

if [ "$IMAGE" = "" ]
then
    IMAGE=quay.io/389ds/dirsrv
fi

if [ "$SUFFIX" = "" ] && [ "$BASE_DN" = "" ]
then
    SUFFIX="dc=example,dc=com"
    BASE_DN="dc=pki,$SUFFIX"

elif [ "$SUFFIX" = "" ]
then
    SUFFIX=$(echo "$BASE_DN" | sed 's/^dc=[^,]*,\(.*$\)/\1/')

elif [ "$BASE_DN" = "" ]
then
    BASE_DN="dc=pki,$SUFFIX"
fi

if [ "$DEBUG" = true ] ; then
    echo "NAME: $NAME"
    echo "IMAGE: $IMAGE"
    echo "SUFFIX: $SUFFIX"
    echo "BASE_DN: $BASE_DN"
fi

if [ "$IMAGE" = "pki-runner" ]
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
    -b "$SUFFIX"

echo "DS container is ready"
