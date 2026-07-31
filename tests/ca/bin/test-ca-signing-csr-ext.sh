#!/bin/bash -e

INPUT=$1

if [ "$INPUT" = "" ]; then
    INPUT=ca_signing.csr
fi

openssl req -text -noout -in $INPUT | tee output

# verify basic constraints extension
echo "X509v3 Basic Constraints: critical" > expected
echo "CA:TRUE" >> expected
sed -En 'N; s/^ *(X509v3 Basic Constraints: .*)\n *(.*)$/\1\n\2/p; D' output | tee actual
diff actual expected

# verify key usage extension
echo "X509v3 Key Usage: critical" > expected
echo "Digital Signature, Non Repudiation, Certificate Sign, CRL Sign" >> expected
sed -En 'N; s/^ *(X509v3 Key Usage: .*)\n *(.*)$/\1\n\2/p; D' output | tee actual
diff actual expected
