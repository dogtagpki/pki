#!/bin/bash -ex

# revoke the cert
pki -u caadmin -w Secret.123 ca-cert-hold `cat /tmp/cert_id` --force

set +e

# revoked cert should not work
pki -n caagent ca-cert-request-find || echo $? > /tmp/actual

set -e

echo 255 > /tmp/expected
diff /tmp/actual /tmp/expected
