#!/bin/bash -ex

# submit a cert request and capture the request ID
pki client-cert-request uid=caauditor | sed -n "s/^\s*Request ID:\s*\(\S*\)$/\1/p" > /tmp/request_id

# approve the cert request and capture the cert ID
pki -n caadmin ca-cert-request-approve `cat /tmp/request_id` --force | sed -n "s/^\s*Certificate ID:\s*\(\S*\)$/\1/p" > /tmp/cert_id

# assign the cert to the user
pki -n caadmin ca-user-cert-add caauditor --serial `cat /tmp/cert_id`

# import the cert into client
pki client-cert-import caauditor --serial `cat /tmp/cert_id`

# test client certificate
pki -n caauditor ca-audit-file-find
