#!/bin/bash -e

INPUT=$1

if [ "$INPUT" = "" ]; then
    INPUT=subca_signing.crt
fi

openssl x509 -text -noout -in $INPUT | tee output

# verify SKI extension
echo "X509v3 Subject Key Identifier: " > expected
sed -En 's/^ *(X509v3 Subject Key Identifier: .*)$/\1/p' output | tee actual
diff actual expected

# verify AKI extension
echo "X509v3 Authority Key Identifier: " > expected
sed -En 's/^ *(X509v3 Authority Key Identifier: .*)$/\1/p' output | tee actual
diff actual expected

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

# verify MS subordinate CA extension
echo "1.3.6.1.4.1.311.20.2: " > expected
echo "." >> expected
echo ".S.u.b.C.A" >> expected
sed -En '1N;$!N;s/^ *(1.3.6.1.4.1.311.20.2: .*)\n *(.*)\n *(.*)/\1\n\2\n\3/p;D' output | tee actual
diff actual expected
