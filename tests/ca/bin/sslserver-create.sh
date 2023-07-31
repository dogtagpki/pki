#!/bin/bash -ex

# https://github.com/dogtagpki/pki/wiki/Generating-SSL-Server-CSR-with-PKI-NSS
# https://github.com/dogtagpki/pki/wiki/Issuing-SSL-Server-Certificate-with-PKI-CA

# submit a cert request and capture the request ID
pki nss-cert-request \
    --subject "CN=$HOSTNAME" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr sslserver.csr

pki ca-cert-request-submit --profile caServerCert --csr-file sslserver.csr | tee /tmp/output

sed -n "s/^\s*Request ID:\s*\(\S*\)$/\1/p" /tmp/output > /tmp/request_id
REQUEST_ID=$(cat /tmp/request_id)

# approve the cert request and capture the cert ID
pki -n caadmin ca-cert-request-approve $REQUEST_ID --force | tee /tmp/output

sed -n "s/^\s*Certificate ID:\s*\(\S*\)$/\1/p" /tmp/output > /tmp/cert_id
CERT_ID=$(cat /tmp/cert_id)

pki ca-cert-export $CERT_ID --output-file sslserver.crt

pki nss-cert-import sslserver --cert sslserver.crt
