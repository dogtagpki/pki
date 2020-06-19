Configuring ACME Issuer
=======================

## Overview

This document describes the process to configure an issuer for ACME responder.
The issuer configuration is located at /etc/pki/pki-tomcat/acme/issuer.conf.

## Configuring PKI Issuer

To configure a PKI issuer, copy the sample [issuer.conf](../../../base/acme/conf/issuer/pki/issuer.conf) with the following command:

```
$ cp /usr/share/pki/acme/conf/issuer/pki/issuer.conf \
    /etc/pki/pki-tomcat/acme/issuer.conf
```

Customize the configuration as needed. The issuer.conf should look like the following:

```
class=org.dogtagpki.acme.issuer.PKIIssuer
url=https://localhost.localdomain:8443
profile=acmeServerCert
username=caadmin
password=Secret.123
```

## See Also

* [Configuring ACME Responder](https://www.dogtagpki.org/wiki/Configuring_ACME_Responder)
* [Installing ACME Responder](Installing_ACME_Responder.md)
