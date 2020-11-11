#!/bin/bash -ex

# This command needs to be executed as it pulls the machine name
# dynamically.
dscreate create-template ds.tmp

sed \
    -e 's/;root_password = .*/root_password = Secret.123/g' \
    -e 's/;suffix = .*/suffix = dc=example,dc=com/g' \
    -e 's/;instance_name = .*/instance_name = localhost/g' \
    ds.tmp > ds.inf

dscreate from-file ds.inf
