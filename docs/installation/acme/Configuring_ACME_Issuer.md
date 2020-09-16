Configuring ACME Issuer
=======================

## Overview

This document describes the process to configure an issuer for ACME responder.
The issuer configuration is located at /etc/pki/pki-tomcat/acme/issuer.conf.

The `pki-server acme-issuer-mod` can be used to configure the issuer via command-line.
If the command is invoked without any parameters, it will enter an interactive mode, for example:

```
$ pki-server acme-issuer-mod
The current value is displayed in the square brackets.
To keep the current value, simply press Enter.
To change the current value, enter the new value.
To remove the current value, enter a blank space.

Enter the type of the certificate issuer. Available types: nss, pki.
  Issuer Type: pki

Enter the location of the PKI server (e.g. https://localhost.localdomain:8443).
  Server URL [https://localhost.localdomain:8443]:

Enter the certificate nickname for client authentication.
This might be the CA agent certificate.
Enter blank to use basic authentication.
  Client Certificate:

Enter the username of the CA agent for basic authentication.
Enter blank if a CA agent certificate is used for client authentication.
  Agent Username [caadmin]:

Enter the CA agent password for basic authentication.
Enter blank if the password is already stored in a separate property file
or if a CA agent certificate is used for client authentication.
  Agent Password [********]:

Enter the certificate profile for issuing ACME certificates (e.g. acmeServerCert).
  Certificate Profile [acmeServerCert]:
```

If the command is invoked with `--type` parameter, it will create a new configuration based on the specified type.
If the command is invoked with other parameters, it will update the specified parameters.

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

* [Configuring PKI ACME Responder](https://www.dogtagpki.org/wiki/Configuring_PKI_ACME_Responder)
* [Installing PKI ACME Responder](Installing_PKI_ACME_Responder.md)
