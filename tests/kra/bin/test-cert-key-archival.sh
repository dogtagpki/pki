#!/bin/bash -e

# https://github.com/dogtagpki/pki/wiki/Getting-KRA-Transport-Certificate
pki kra-cert-transport-export --output-file kra_transport.crt

# https://github.com/dogtagpki/pki/wiki/Submitting-Certificate-Request-with-Key-Archival
CRMFPopClient \
    -d ~/.dogtag/nssdb \
    -p "" \
    -m $HOSTNAME:8080 \
    -f caDualCert \
    -n UID=testuser \
    -u testuser \
    -b kra_transport.crt | tee output

REQUEST_ID=$(sed -n "s/^\s*Request ID:\s*\(\S*\)\s*$/\1/p" output)
echo "Request ID: $REQUEST_ID"

# https://github.com/dogtagpki/pki/wiki/Handling-Certificate-Request
pki -n caadmin ca-cert-request-approve $REQUEST_ID --force | tee output

CERT_ID=$(sed -n "s/^\s*Certificate ID:\s*\(\S*\)\s*$/\1/p" output)
echo "Cert ID: $CERT_ID"

# https://github.com/dogtagpki/pki/wiki/Retrieving-Certificate
pki ca-cert-export $CERT_ID --output-file testuser.crt

# import cert into NSS database
pki nss-cert-import testuser --cert testuser.crt
pki nss-cert-show testuser | tee output

# verify that the cert matches the key in NSS database (trust flags must be u,u,u)
sed -n "s/^\s*Trust Flags:\s*\(\S*\)\s*$/\1/p" output > actual
echo "u,u,u" > expected
diff expected actual

# https://github.com/dogtagpki/pki/wiki/Retrieving-Archived-Certificate-Key
# Currently there's no mechanism in KRA to find the key that corresponds to
# a cert so the test will try to find all keys in KRA instead.
# TODO: add mechanism to find the cert's exact key
pki -n caadmin kra-key-find | tee output

KEY_ID=$(sed -n "s/^\s*Key ID:\s*\(\S*\)$/\1/p" output)
echo "Key ID: $KEY_ID"

# verify that the key ID is not empty
[ ! -z "$KEY_ID" ]

# TODO: retrieve the key and validate that it matches the cert
