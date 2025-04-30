#!/bin/bash -e

NAME=$1

RANGE_DN=ou=replica,dc=ca,dc=pki,dc=example,dc=com

docker exec $NAME ldapsearch \
    -H ldap://$NAME.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b $RANGE_DN \
    -s base \
    -o ldif_wrap=no \
    -LLL \
    | grep nextRange:
