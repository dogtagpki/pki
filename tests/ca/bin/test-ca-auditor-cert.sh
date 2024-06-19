#!/bin/bash -ex

# submit a cert request and capture the request ID
pki client-cert-request uid=caauditor | sed -n "s/^\s*Request ID:\s*\(\S*\)$/\1/p" > /tmp/request_id

# approve the cert request and capture the cert ID
pki -u caadmin -w Secret.123 ca-cert-request-approve `cat /tmp/request_id` --force | sed -n "s/^\s*Certificate ID:\s*\(\S*\)$/\1/p" > /tmp/cert_id
CERT_ID=$(cat /tmp/cert_id)

# assign the cert to the user
# ignore JSS issue (https://github.com/dogtagpki/jss/issues/781)
pki -u caadmin -w Secret.123 ca-user-cert-add caauditor --serial $CERT_ID || true

# import the cert into client
pki ca-cert-export $CERT_ID --output-file /tmp/caauditor.crt
pki nss-cert-import caauditor --cert /tmp/caauditor.crt

# test client certificate
pki -u caauditor -w Secret.123 ca-audit-file-find
