#!/bin/bash -e

NAME=$1

docker exec $NAME pki-server ca-config-find \
    | grep \
        -e dbs.beginRequestNumber \
        -e dbs.endRequestNumber \
        -e dbs.nextBeginRequestNumber \
        -e dbs.nextEndRequestNumber \
        -e dbs.requestCloneTransferNumber \
        -e dbs.requestIncrement \
        -e dbs.requestLowWaterMark
