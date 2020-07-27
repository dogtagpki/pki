Deploying PKI ACME Responder on OpenShift
=========================================

## Overview

This document describes the process to deploy PKI ACME responder as a container on OpenShift.
The container image is available at [quay.io/dogtagpki/pki-acme](https://quay.io/repository/dogtagpki/pki-acme).

By default the responder will use a temporary CA signing certificate.
The temporary certificate is self-signed and if the responder is restarted the certificate will be recreated .
It is possible to replace it with a permanent CA signing certificate.

Also, by default the responder will use a temporary database.
This temporary database is non-persistent, so if the responder is restarted the database will disappear.
It is possible to replace it with a persistent database.

## Deploying PKI ACME Responder

A sample configuration for PKI ACME responder is available at:

- [/usr/share/pki/acme/openshift/pki-acme-certs.yaml](../../../base/acme/openshift/pki-acme-certs.yaml)
- [/usr/share/pki/acme/openshift/pki-acme-metadata.yaml](../../../base/acme/openshift/pki-acme-metadata.yaml)
- [/usr/share/pki/acme/openshift/pki-acme-database.yaml](../../../base/acme/openshift/pki-acme-database.yaml)
- [/usr/share/pki/acme/openshift/pki-acme-issuer.yaml](../../../base/acme/openshift/pki-acme-issuer.yaml)
- [/usr/share/pki/acme/openshift/pki-acme-is.yaml](../../../base/acme/openshift/pki-acme-is.yaml)
- [/usr/share/pki/acme/openshift/pki-acme-deployment.yaml](../../../base/acme/openshift/pki-acme-deployment.yaml)
- [/usr/share/pki/acme/openshift/pki-acme-svc.yaml](../../../base/acme/openshift/pki-acme-svc.yaml)
- [/usr/share/pki/acme/openshift/pki-acme-route.yaml](../../../base/acme/openshift/pki-acme-route.yaml)

Customize the configuration as needed. Deploy the responder with the following command:

```
$ oc apply -f/usr/share/pki/acme/openshift/pki-acme-{certs,metadata,database,issuer,is,deployment,svc,route}.yaml
```

Once it's deployed, get the route's hostname with the following command:

```
$ oc get routes pki-acme
```

The responder should be accessible at http://&lt;hostname&gt;/acme/directory.

## Deploying Permanent CA Signing Certificate

To deploy a permanent CA signing certificate, the certificate and key need to be deployed in a secret.
A sample configuration for the secret is available at
[/usr/share/pki/acme/openshift/pki-acme-certs.yaml](../../../base/acme/openshift/pki-acme-certs.yaml).

Customize the configuration as needed. Deploy the secret with the following command:

```
$ oc apply -f /usr/share/pki/acme/openshift/pki-acme-certs.yaml
```

Alternatively, the secret can be created from files directly.
Prepare a folder to store the files (e.g. certs).

If the CA signing certificate and key are available in PEM format,
store the certificate in a file called **ca_signing.crt**,
and store the key in a file called **ca_signing.key**.

If the CA signing certificate is stored in an NSS database,
export the certificate and the key and then import them into a PKCS #12 file called **certs.p12**
with a **ca_signing** friendly name,
and store the PKCS #12 password in a file called **password**.

For example:

```
$ echo <PKCS #12 password> > password
$ pki -d <NSS database directory> -c <NSS database password> pkcs12-cert-import \
    --pkcs12 certs.p12 \
    --password-file password \
    --friendly-name ca_signing \
    <cert nickname in NSS database>
```

Deploy the secret with the following commands:

```
$ oc delete secret pki-acme-certs
$ oc create secret generic pki-acme-certs --from-file=certs --save-config=true
```

Once it's deployed, restart the responder by deleting the current pods with the following command:

```
$ oc delete pods -l app=pki-acme
```

## Deploying Persistent Database

To deploy a persistent database, use OpenShift console or **oc new-app** command.
For example, deploy a PostgreSQL database with the following command:

```
$ oc new-app postgresql-persistent \
    -p POSTGRESQL_USER=acme \
    -p POSTGRESQL_PASSWORD=Secret.123 \
    -p POSTGRESQL_DATABASE=acme
```

Next, configure the PKI ACME responder to use the persistent database.
A sample database configuration for PKI ACME responder is available at
[/usr/share/pki/acme/openshift/pki-acme-database.yaml](../../../base/acme/openshift/pki-acme-database.yaml).

Customize the configuration as needed. Deploy the configuration with the following command:

```
$ oc apply -f /usr/share/pki/acme/openshift/pki-acme-database.yaml
```

Restart the responder by deleting the current pods with the following command:

```
$ oc delete pods -l app=pki-acme
```

To verify the database connection, list the responder's pods with the following command:

```
$ oc get pods -l app=pki-acme
```

Select one of the pods, then execute the following command:

```
$ oc rsh <pod name> \
    psql postgres://acme:Secret.123@postgresql/acme
```

## Deploying Secure Route

To deploy a secure route, prepare a route configuration that contains the following properties:

- **certificate**: The external SSL server certificate
- **key**: The external SSL server key
- **caCertificate**: The CA certificate that issued the external SSL server certificate
- **destinationCACertificate**: The CA signing certificate deployed in **pki-acme-certs** secret

A sample route configuration is available at
[/usr/share/pki/acme/openshift/pki-acme-route.yaml](../../../base/acme/openshift/pki-acme-route.yaml).

Customize the configuration as needed. Deploy the configuration with the following commands:

```
$ oc delete route pki-acme
$ oc apply -f /usr/share/pki/acme/openshift/pki-acme-route.yaml
```

The responder should now be accessible at https://&lt;hostname&gt;/acme/directory.

## See also

* [Configuring ACME Database](../acme/Configuring_ACME_Database.md)
* [Configuring ACME Issuer](../acme/Configuring_ACME_Issuer.md)
* [Using ACME Responder](../../user/acme/Using_ACME_Responder.md)
