#!/bin/bash -e

NAME=$1

RANGE_DN=ou=replica,ou=ranges,dc=ca,dc=pki,dc=example,dc=com

LIST=$(docker exec $NAME ldapsearch \
    -H ldap://$NAME.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b $RANGE_DN \
    -s one \
    -o ldif_wrap=no \
    -LLL \
    dn \
    | sed -n 's/^dn: *\(.*\)$/\1/p')

for DN in $LIST
do
    docker exec $NAME ldapsearch \
        -H ldap://$NAME.example.com:3389 \
        -D "cn=Directory Manager" \
        -w Secret.123 \
        -b $DN \
        -s base \
        -o ldif_wrap=no \
        -LLL \
        | grep \
            -e SecurePort: \
            -e beginRange: \
            -e endRange: \
            -e host: \
        | sort

    echo
done
