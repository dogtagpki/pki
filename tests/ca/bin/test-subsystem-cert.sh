#!/bin/bash -ex

# get subsystem cert using certutil
certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -n subsystem -r > /tmp/subsystem.crt

# get subsystem cert using pki ca-cert-subsystem-export
pki ca-cert-subsystem-export > /tmp/subsystem.pem
openssl x509 -outform der -in /tmp/subsystem.pem -out /tmp/subsystem.der

# the certs should be identical
diff /tmp/subsystem.crt /tmp/subsystem.der
