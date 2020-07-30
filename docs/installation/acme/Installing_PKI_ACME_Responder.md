Installing PKI ACME Responder
=============================

## Overview

This document describes the process to install an ACME responder on a PKI server that already has a CA subsystem.
It assumes that the CA was [installed](../ca/Installing_CA.md) with the default instance name (i.e. pki-tomcat).

## Installing PKI ACME Responder

To install PKI ACME responder on PKI server, execute the following command:

```
$ pki-server acme-create
```

The command will create the initial configuration files in /etc/pki/pki-tomcat/acme folder.

See also [pki-server-acme(8)](../../manuals/man8/pki-server-acme.8.md).

## Configuring ACME Database

See [Configuring ACME Database](Configuring_ACME_Database.md).

## Configuring ACME Issuer

See [Configuring ACME Issuer](Configuring_ACME_Issuer.md).

## Deploying ACME Responder

Once everything is ready, deploy the ACME responder with the following command:

```
$ pki-server acme-deploy
```

The command will create a deployment descriptor at /etc/pki/pki-tomcat/Catalina/localhost/acme.xml.

The server will start the ACME responder automatically in a few seconds.
It is not necessary to restart PKI server.

To verify that the ACME responder is running, execute the following command:

```
$ curl -s -k https://$HOSTNAME:8443/acme/directory | python -m json.tool
{
    "meta": {
        "caaIdentities": [
            "dogtagpki.org"
        ],
        "externalAccountRequired": false,
        "termsOfService": "https://www.dogtagpki.org/wiki/PKI_ACME_Responder",
        "website": "https://www.dogtagpki.org"
    },
    "newAccount": "https://<hostname>:8443/acme/new-account",
    "newNonce": "https://<hostname>:8443/acme/new-nonce",
    "newOrder": "https://<hostname>:8443/acme/new-order",
    "revokeCert": "https://<hostname>:8443/acme/revoke-cert"
}
```

See also [pki-server-acme(8)](../../manuals/man8/pki-server-acme.8.md).

## See Also

* [Installing CA](../ca/Installing_CA.md)
* [Using PKI ACME Responder with Certbot](../../user/acme/Using_PKI_ACME_Responder_with_Certbot.md)
