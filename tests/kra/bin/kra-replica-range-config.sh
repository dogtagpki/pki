#!/bin/bash -e

NAME=$1

docker exec $NAME pki-server kra-config-find \
    | grep \
        -e dbs.beginReplicaNumber \
        -e dbs.endReplicaNumber \
        -e dbs.nextBeginReplicaNumber \
        -e dbs.nextEndReplicaNumber \
        -e dbs.replicaCloneTransferNumber \
        -e dbs.replicaIncrement \
        -e dbs.replicaLowWaterMark
