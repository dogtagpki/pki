Installing ACME Responder
=========================

## Overview

This document describes the process to install an ACME responder on a PKI server that already has a CA subsystem.
It assumes that the CA was [installed](Installing_CA.md) with the default instance name (i.e. pki-tomcat).

**Note:** The ACME responder is currently a tech preview which means:
* It is not intended for production.
* It may corrupt your data.
* There is no guarantee for correctness, security, or performance.
* There is no guarantee for documentation or support.
* The API, configuration, or the database may change in the future.
* There may be no easy upgrade path to the future version.

## Installing SANToCNDefault Policy

The SANToCNDefault is a certificate profile policy which generates
a default subject DN for the certificate in case the CSR does not provide one.
The subject DN will be generated from the first DNS name in the the SAN extension.

This policy is needed by the ACME profile, but currently it is not installed by default in the CA,
so it has to be added manually.

To add the policy, edit /etc/pki/pki-tomcat/ca/registry.cfg as follows:

```
defaultPolicy.ids=...,SANToCNDefault
defaultPolicy.SANToCNDefault.class=com.netscape.cms.profile.def.SANToCNDefault
defaultPolicy.SANToCNDefault.desc=SAN to CN Default
defaultPolicy.SANToCNDefault.name=SAN to CN Default
```

**Note:** Restart the server to enable the policy.

## Installing ACME Profile

The acmeServerCert.cfg is a sample profile for generating server certificates via ACME responder.

This profile is currently not installed by default in the CA, so it needs to be added and enabled manually.

To add the profile, execute the following command:

```
$ pki -u caadmin -w Secret.123 ca-profile-add /usr/share/pki/ca/profiles/acmeServerCert.cfg --raw
```

To enable the profile, execute the following command:

```
$ pki -u caadmin -w Secret.123 ca-profile-enable acmeServerCert
```

## Installing ACME Responder

To install the ACME responder on PKI server, execute the following command:

```
$ pki-server acme-create
```

The command will create the initial configuration files in /etc/pki/pki-tomcat/acme folder.

For more info execute `pki-server acme-create --help`.

## Configuring ACME Responder Database

The database configuration for the ACME responder is located at /etc/pki/pki-tomcat/acme/database.json.

To use an in-memory database, copy the sample configuration file with the following command:

```
$ cp /usr/share/pki/acme/conf/database/in-memory/database.json \
    /etc/pki/pki-tomcat/acme/database.json
```

Alternatively, edit the file as follows:

```
{
    "class": "org.dogtagpki.acme.database.InMemoryDatabase"
}
```

Currently there are no parameters to configure for in-memory database.

See also [Configuring ACME Responder](https://www.dogtagpki.org/wiki/Configuring_ACME_Responder).

## Configuring ACME Responder Backend

The backend configuration for the ACME responder is located at /etc/pki/pki-tomcat/acme/backend.json.

To use the CA subsystem as the backend for the ACME responder,
copy the sample configuration with the following command:

```
$ cp /usr/share/pki/acme/conf/backend/pki/backend.json \
    /etc/pki/pki-tomcat/acme/backend.json
```

Alternatively, edit the file as follows:

```
{
    "class": "org.dogtagpki.acme.backend.PKIBackend",
    "parameters": {
        "url": "https://localhost:8443",
        "profile": "acmeServerCert",
        "username": "caadmin",
        "password": "Secret.123"
    }
}
```

Configure the parameters as needed.

See also [Configuring ACME Responder](https://www.dogtagpki.org/wiki/Configuring_ACME_Responder).

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
        "termsOfService": "https://www.dogtagpki.org/wiki/PKI_ACME_Service",
        "website": "https://www.dogtagpki.org"
    },
    "newAccount": "https://<hostname>:8443/acme/new-account",
    "newNonce": "https://<hostname>:8443/acme/new-nonce",
    "newOrder": "https://<hostname>:8443/acme/new-order"
}
```

For more info execute `pki-server acme-deploy --help`.

## Using ACME Responder with certbot

Note that certbot does not accept self-signed CA certificate,
so the sample operations below are executed over insecure HTTP connections.

| WARNING: Do not use ACME over insecure HTTP connections in production environment. |
| --- |

### Certificate Enrollment with HTTP-01

To request a certificate with automatic http-01 validation, execute the following command:

```
$ certbot certonly --standalone \
    --server http://$HOSTNAME:8080/acme/directory \
    -d $HOSTNAME \
    --preferred-challenges http \
    --register-unsafely-without-email
```

### Certificate Enrollment with DNS-01

To request a certificate with manual dns-01 validation, execute the following command:

```
$ certbot certonly --manual \
    --server http://$HOSTNAME:8080/acme/directory \
    -d server.example.com \
    --preferred-challenges dns \
    --register-unsafely-without-email
```

Create a TXT record in the DNS server as instructed by certbot.
Check the TXT record propagation with the following command:

```
$ dig _acme-challenge.server.example.com TXT
```

Once the TXT record is propagated properly, complete the enrollment using certbot.
