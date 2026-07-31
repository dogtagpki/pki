#!/bin/bash -ex

# get CA signing cert using certutil
certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -n ca_signing -r > /tmp/ca_signing.crt

# get CA signing cert using pki ca-cert-signing-export
pki ca-cert-signing-export > /tmp/ca_signing.pem
openssl x509 -outform der -in /tmp/ca_signing.pem -out /tmp/ca_signing.der

# the certs should be identical
diff /tmp/ca_signing.crt /tmp/ca_signing.der
