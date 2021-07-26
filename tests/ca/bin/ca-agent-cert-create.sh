#!/bin/bash -ex

# submit a cert request and capture the request ID
pki client-cert-request uid=caagent | sed -n "s/^\s*Request ID:\s*\(\S*\)$/\1/p" > /tmp/request_id

# approve the cert request and capture the cert ID
pki -n caadmin ca-cert-request-approve `cat /tmp/request_id` --force | sed -n "s/^\s*Certificate ID:\s*\(\S*\)$/\1/p" > /tmp/cert_id

# assign the cert to the user
# ignore JSS issue (https://github.com/dogtagpki/jss/issues/781)
pki -n caadmin ca-user-cert-add caagent --serial `cat /tmp/cert_id` || true

# import the cert into client
pki client-cert-import caagent --serial `cat /tmp/cert_id`

# test the client certificate
pki -n caagent ca-cert-request-find
