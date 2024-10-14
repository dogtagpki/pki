#!/bin/bash -e

# list certs in CA
pki ca-cert-find | tee /tmp/certs.txt

# get the number of certs returned
sed -n "s/^\(\S*\) entries found$/\1/p" /tmp/certs.txt > /tmp/certs.count

# by default there should be 6 certs initially
echo 6 > /tmp/expected
diff /tmp/certs.count /tmp/expected
