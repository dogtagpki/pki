#!/bin/bash

CONTAINER=$1
INSTANCE=$2

if [ "$INSTANCE" == "" ]
then
    INSTANCE=localhost
fi

ARTIFACTS=/tmp/artifacts/$CONTAINER

docker exec $CONTAINER ls -la /etc/dirsrv
mkdir -p $ARTIFACTS/etc
docker cp $CONTAINER:/etc/dirsrv $ARTIFACTS/etc

docker exec $CONTAINER ls -la /var/log/dirsrv
mkdir -p $ARTIFACTS/var/log
docker cp $CONTAINER:/var/log/dirsrv $ARTIFACTS/var/log

mkdir -p $ARTIFACTS/var/log/dirsrv/slapd-$INSTANCE
docker exec $CONTAINER journalctl -u dirsrv@$INSTANCE.service > $ARTIFACTS/var/log/dirsrv/slapd-$INSTANCE/systemd.log
