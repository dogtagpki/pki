Configuring ACME Issuer
=======================

## Overview

This document describes the process to configure an issuer for ACME responder.
The issuer configuration is located at /etc/pki/pki-tomcat/acme/issuer.conf.

## Configuring PKI Issuer

The ACME responder can be configured to issue certificates using a PKI issuer.

A sample PKI issuer configuration is available at
[/usr/share/pki/acme/issuer/pki/issuer.conf](../../../base/acme/issuer/pki/issuer.conf).

To configure a PKI issuer, copy the sample issuer.conf into the /etc/pki/pki-tomcat/acme folder,
or execute the following command to customize some of the parameters:

```
$ pki-server acme-issuer-mod --type pki \
    -Dusername=caadmin \
    -Dpassword=Secret.123
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

A sample NSS issuer configuration is available at
[/usr/share/pki/acme/issuer/nss/issuer.conf](../../../base/acme/issuer/nss/issuer.conf).

To configure an NSS issuer, copy the sample issuer.conf into the /etc/pki/pki-tomcat/acme folder,
or execute the following command to customize some of the parameters:

```
$ pki-server acme-issuer-mod --type nss \
    -Dnickname=ca_signing
```

Customize the configuration as needed. The issuer.conf should look like the following:

```
class=org.dogtagpki.acme.issuer.NSSIssuer
nickname=ca_signing
```

The **nickname** parameter can be used to specify the nickname of the CA signing certificate.
The default value is **ca_signing**.

The **extensions** parameter can be used to configure the certificate extensions for the issued certificates.
The default value is **/usr/share/pki/acme/issuer/nss/sslserver.conf**.
Sample extension configuration files are available at:

* [/usr/share/pki/acme/issuer/nss/sslserver.conf](../../../base/acme/issuer/nss/sslserver.conf)
* [/usr/share/pki/acme/issuer/nss/ca_signing.conf](../../../base/acme/issuer/nss/ca_signing.conf)

Customize the configuration as needed. The format is based on [OpenSSL x509v3_config](https://www.openssl.org/docs/manmaster/man5/x509v3_config.html).

## See Also

* [Configuring ACME Responder](https://www.dogtagpki.org/wiki/Configuring_ACME_Responder)
* [Installing PKI ACME Responder](Installing_PKI_ACME_Responder.md)
