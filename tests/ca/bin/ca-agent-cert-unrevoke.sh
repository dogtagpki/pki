#!/bin/bash -ex

# unrevoke the cert
pki -n caadmin ca-cert-release-hold `cat /tmp/cert_id` --force

# unrevoked cert should work again
pki -n caagent ca-cert-request-find
