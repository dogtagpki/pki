#!/bin/bash

CONTAINER=$1
INSTANCE=$2

if [ "$INSTANCE" == "" ]
then
    INSTANCE=localhost
fi

ARTIFACTS=/tmp/artifacts/$CONTAINER

mkdir -p $ARTIFACTS/etc
mkdir -p $ARTIFACTS/var/log

docker exec $CONTAINER ls -la /etc/dirsrv
docker cp $CONTAINER:/etc/dirsrv $ARTIFACTS/etc

docker exec $CONTAINER ls -la /var/log/dirsrv
docker cp $CONTAINER:/var/log/dirsrv $ARTIFACTS/var/log
docker exec $CONTAINER journalctl -u dirsrv@$INSTANCE.service > $ARTIFACTS/var/log/dirsrv/slapd-$INSTANCE/systemd.log
