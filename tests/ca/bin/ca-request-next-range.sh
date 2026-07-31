#!/bin/bash -e

GENERATOR_TYPE=legacy

while getopts "t:" arg ; do
    case $arg in
    t)
        GENERATOR_TYPE=$OPTARG
        ;;
    esac
done

# remove parsed options and args from $@ list
shift $((OPTIND-1))

NAME=$1

if [ "$GENERATOR_TYPE" == "legacy2" ]
then
    RANGE_DN=ou=requests,ou=ranges_v2,dc=ca,dc=pki,dc=example,dc=com
else
    RANGE_DN=ou=ca,ou=requests,dc=ca,dc=pki,dc=example,dc=com
fi

docker exec $NAME ldapsearch \
    -H ldap://$NAME.example.com:3389 \
    -D "cn=Directory Manager" \
    -w Secret.123 \
    -b $RANGE_DN \
    -s base \
    -o ldif_wrap=no \
    -LLL \
    | grep nextRange:
