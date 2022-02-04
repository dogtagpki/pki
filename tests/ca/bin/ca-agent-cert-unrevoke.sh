#!/bin/bash -ex

# unrevoke the cert
pki -u caadmin -w Secret.123 ca-cert-release-hold `cat /tmp/cert_id` --force

# unrevoked cert should work again
pki -n caagent ca-cert-request-find
