#!/bin/bash -ex

# This command needs to be executed as it pulls the machine name
# dynamically.
dscreate create-template ds.inf

sed -i \
    -e "s/;instance_name = .*/instance_name = localhost/g" \
    -e "s/;root_password = .*/root_password = Secret.123/g" \
    -e "s/;suffix = .*/suffix = dc=example,dc=com/g" \
    -e "s/;self_sign_cert = .*/self_sign_cert = False/g" \
    ds.inf

dscreate from-file ds.inf

ldapadd -H ldap://$HOSTNAME -x -D "cn=Directory Manager" -w Secret.123 << EOF
dn: dc=example,dc=com
objectClass: domain
dc: example

dn: dc=pki,dc=example,dc=com
objectClass: domain
dc: pki
EOF
