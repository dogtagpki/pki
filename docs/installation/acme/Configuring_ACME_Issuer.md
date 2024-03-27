Configuring ACME Issuer
=======================

## Overview

This document describes the process to configure an issuer for ACME responder.
The issuer configuration is located at /var/lib/pki/pki-tomcat/conf/acme/issuer.conf.

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
See [Configuring ACME with PKI Issuer](Configuring-ACME-with-PKI-Issuer.adoc).

## Configuring NSS Issuer

The ACME responder can be configured to issue certificates using a local NSS database.
See [Configuring ACME with NSS Issuer](Configuring-ACME-with-NSS-Issuer.adoc).

## See Also

* [Installing PKI ACME Responder](Installing_PKI_ACME_Responder.md)
