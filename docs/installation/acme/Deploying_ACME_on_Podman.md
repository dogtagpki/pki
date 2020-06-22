Deploying ACME on Podman
========================

## Overview

This document describes the process to deploy PKI ACME responder as a container on Podman.
The container image is available at [quay.io/dogtagpki/pki-acme](https://quay.io/repository/dogtagpki/pki-acme).

By default the responder will use a temporary CA signing certificate.
The temporary certificate is self-signed and if the responder is restarted the certificate will be recreated .
It is possible to replace it with a permanent CA signing certificate.

Also, by default the responder will use a temporary database.
This temporary database is non-persistent, so if the responder is restarted the database will disappear.
It is possible to replace it with a persistent database.

## Deploying PKI ACME Responder

Create a pod to encapsulate PKI ACME containers with the following command:

```
$ podman pod create --name acme -p 8080:8080 -p 8443:8443
```

Deploy the PKI ACME responder with the following command:

```
$ podman run \
    --name pki-acme \
    --pod acme \
    --rm \
    -it \
    quay.io/dogtagpki/pki-acme
```

The responder should be accessible at http://localhost.localdomain:8080/acme/directory.

## Deploying Permanent CA Signing Certificate

To deploy a permanent CA signing certificate, prepare a folder (e.g. certs) to store the certificate and key.

If the CA signing certificate and key are available in PEM format,
store the certificate in a file called **ca_signing.crt**,
and store the key in a file called **ca_signing.key**.

If the CA signing certificate is stored in an NSS database,
export the certificate and the key and import them into a PKCS #12 file called **certs.p12**
with a **ca_signing** friendly name,
and store the PKCS #12 password in a file called **password**.

For example:

```
$ echo <PKCS #12 password> > password
$ pki -d <NSS database directory> -c <NSS database password> pkcs12-cert-import \
    --friendly-name ca_signing \
    --pkcs12 certs.p12 \
    --password-file password \
    <cert nickname in NSS database>
```

Restart the responder with the following command:

```
$ podman run \
    --name pki-acme \
    --pod acme \
    --rm \
    --privileged \
    -v ./certs:/var/lib/tomcats/pki/conf/certs \
    -it \
    quay.io/dogtagpki/pki-acme
```

## Deploying Persistent Database

To deploy a persistent database, run the database container in the same pod.
For example, deploy a PostgreSQL database with the following command:

```
$ podman run \
    --name postgresql \
    --rm \
    --pod acme \
    -e POSTGRES_USER=acme \
    -e POSTGRES_PASSWORD=Secret.123 \
    -e POSTGRESQL_DATABASE=acme \
    -it \
    postgres
```

Next, configure the PKI ACME responder to use the persistent database.
Prepare a folder (e.g. database) and store the configuration parameters in separate files.
For example:

- **class**: org.dogtagpki.acme.database.PostgreSQLDatabase
- **url**: jdbc:postgresql://localhost.localdomain:5432/acme
- **user**: acme
- **password**: Secret.123

Restart the responder with the following command:

```
$ podman run \
    --name pki-acme \
    --pod acme \
    --rm \
    --privileged \
    -v ./certs:/var/lib/tomcats/pki/conf/certs \
    -v ./database:/var/lib/tomcats/pki/conf/acme/database \
    -it \
    quay.io/dogtagpki/pki-acme
```

To initialize the database, execute the following command:

```
$ podman exec -ti pki-acme \
    psql postgres://acme:Secret.123@localhost.localdomain/acme \
    -f /usr/share/pki/acme/database/postgresql/create.sql
```

## See also

* [Configuring ACME Database](Configuring_ACME_Database.md)
* [Configuring ACME Issuer](Configuring_ACME_Issuer.md)
* [Using ACME Responder](../../user/acme/Using_ACME_Responder.md)
