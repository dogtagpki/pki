#!/bin/bash -e

# https://fy.blackhats.net.au/blog/html/2020/03/28/389ds_in_containers.html

NAME=$1

if [ "$NAME" == "" ]
then
    echo "Usage: ds-container-certs-import.sh <name> <input>"
    exit 1
fi

INPUT=$2

if [ "$INPUT" == "" ]
then
    echo "Usage: ds-container-certs-import.sh <name> <input>"
    exit 1
fi

if [ "$PASSWORD" == "" ]
then
    PASSWORD=Secret.123
fi

import_certs() {

    echo "Importing DS certs"

    # Import input file into container

    docker cp $INPUT $NAME:/tmp/certs.p12

    # Fix file ownership

    docker exec -u 0 $NAME chown dirsrv.dirsrv /tmp/certs.p12

    # Export server cert into /data/tls/server.crt

    docker exec $NAME openssl pkcs12 \
        -in /tmp/certs.p12 \
        -passin pass:$PASSWORD \
        -out /data/tls/server.crt \
        -clcerts \
        -nokeys

    # Export server key into /data/tls/server.key

    docker exec $NAME openssl pkcs12 \
        -in /tmp/certs.p12 \
        -passin pass:$PASSWORD \
        -out /data/tls/server.key \
        -nodes \
        -nocerts

    # Export CA cert into /data/tls/ca/ca.crt

    docker exec $NAME openssl pkcs12 \
        -in /tmp/certs.p12 \
        -passin pass:$PASSWORD \
        -out /data/tls/ca/ca.crt \
        -cacerts \
        -nokeys
}

import_certs

echo "DS certs imported"
