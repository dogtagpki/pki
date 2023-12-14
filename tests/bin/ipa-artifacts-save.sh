#!/bin/bash

CONTAINER=$1
ARTIFACTS=/tmp/artifacts/$CONTAINER

mkdir -p $ARTIFACTS/var/log

docker exec $CONTAINER ls -la /var/log
docker cp $CONTAINER:/var/log/ipaclient-install.log $ARTIFACTS/var/log
docker cp $CONTAINER:/var/log/ipaclient-uninstall.log $ARTIFACTS/var/log
docker cp $CONTAINER:/var/log/ipareplica-ca-install.log $ARTIFACTS/var/log
docker cp $CONTAINER:/var/log/ipareplica-conncheck.log $ARTIFACTS/var/log
docker cp $CONTAINER:/var/log/ipareplica-install.log $ARTIFACTS/var/log
docker cp $CONTAINER:/var/log/ipaserver-install.log $ARTIFACTS/var/log
docker cp $CONTAINER:/var/log/ipaserver-uninstall.log $ARTIFACTS/var/log
docker cp $CONTAINER:/var/log/ipaserver-kra-install.log $ARTIFACTS/var/log
docker cp $CONTAINER:/var/log/ipa $ARTIFACTS/var/log
docker cp $CONTAINER:/var/log/httpd $ARTIFACTS/var/log
