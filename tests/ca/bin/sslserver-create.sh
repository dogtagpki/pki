#!/bin/bash -ex

# https://github.com/dogtagpki/pki/wiki/Generating-SSL-Server-CSR-with-PKI-NSS
# https://github.com/dogtagpki/pki/wiki/Issuing-SSL-Server-Certificate-with-PKI-CA

# submit a cert request and capture the request ID
pki nss-cert-request \
    --subject "CN=$HOSTNAME" \
    --ext /usr/share/pki/server/certs/sslserver.conf \
    --csr sslserver.csr

pki \
    -n caadmin \
    ca-cert-issue \
    --profile caServerCert \
    --csr-file sslserver.csr \
    --output-file sslserver.crt

pki nss-cert-import sslserver --cert sslserver.crt
