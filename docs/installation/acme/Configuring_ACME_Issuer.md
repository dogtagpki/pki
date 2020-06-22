Configuring ACME Issuer
=======================

## Overview

This document describes the process to configure an issuer for ACME responder.
The issuer configuration is located at /etc/pki/pki-tomcat/acme/issuer.conf.

## Configuring PKI Issuer

The ACME responder can be configured to issue certificates using a PKI issuer.

To configure a PKI issuer, copy the sample [issuer.conf](../../../base/acme/issuer/pki/issuer.conf) with the following command:

```
$ cp /usr/share/pki/acme/issuer/pki/issuer.conf \
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

The **url** parameter is used to specify the PKI issuer location.

The **profile** parameter is used to specify the certificate profile to use.

To use client certificate authentication, specify the client certificate nickname in the **nickname** parameter.

To use basic authentication, specify the username in the **username** parameter
and the password in the **password** parameter.


## Configuring NSS Issuer

The ACME responder can be configured to issue certificates using a local NSS database.

To configure an NSS issuer, copy the sample [issuer.conf](../../../base/acme/issuer/nss/issuer.conf) with the following command:

```
$ cp /usr/share/pki/acme/issuer/nss/issuer.conf \
    /etc/pki/pki-tomcat/acme/issuer.conf
```

Customize the configuration as needed. The issuer.conf should look like the following:

```
class=org.dogtagpki.acme.issuer.NSSIssuer
nickname=ca_signing
extensions=/usr/share/pki/acme/issuer/nss/sslserver.conf
```

The **nickname** parameter can be used to specify the nickname of the CA signing certificate.

The **extensions** parameter can be used to configure the certificate extensions for the issued certificates.
Sample extension configuration files are available at:

* [/usr/share/pki/acme/issuer/nss/sslserver.conf](../../../base/acme/issuer/nss/sslserver.conf)
* [/usr/share/pki/acme/issuer/nss/ca_signing.conf](../../../base/acme/issuer/nss/ca_signing.conf)

Customize the configuration as needed. The format is based on [OpenSSL x509v3_config](https://www.openssl.org/docs/manmaster/man5/x509v3_config.html).

## See Also

* [Configuring ACME Responder](https://www.dogtagpki.org/wiki/Configuring_ACME_Responder)
* [Installing ACME Responder](Installing_ACME_Responder.md)
