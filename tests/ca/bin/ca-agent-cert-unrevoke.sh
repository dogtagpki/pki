#!/bin/bash -ex

CERT_ID=$(cat /tmp/cert_id)

# unrevoke the cert
pki -u caadmin -w Secret.123 ca-cert-release-hold $CERT_ID --force

# unrevoked cert should work again
pki -n caagent ca-cert-request-find
