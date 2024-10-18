#!/bin/bash -e

NAME=$1

docker exec $NAME pki-server ca-config-find \
    | grep \
        -e dbs.beginSerialNumber \
        -e dbs.endSerialNumber \
        -e dbs.nextBeginSerialNumber \
        -e dbs.nextEndSerialNumber \
        -e dbs.serialCloneTransferNumber \
        -e dbs.serialIncrement \
        -e dbs.serialLowWaterMark
