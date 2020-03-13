Using ACME Responder
====================

## Overview

This document describes how to use PKI ACME responder with certbot.
Note that certbot does not accept self-signed CA certificate,
so the examples below are executed over insecure HTTP connections.

| WARNING: Do not use ACME over insecure HTTP connections in production environment. |
| --- |

**Note:** The ACME responder is currently a tech preview which means:
* It is not intended for production.
* It may corrupt your data.
* There is no guarantee for correctness, security, or performance.
* There is no guarantee for documentation or support.
* The API, configuration, or the database may change in the future.
* There may be no easy upgrade path to the future version.

## Certificate Enrollment

### Certificate enrollment with HTTP-01

To request a certificate with automatic http-01 validation, execute the following command:

```
$ certbot certonly --standalone \
    --server http://$HOSTNAME:8080/acme/directory \
    -d $HOSTNAME \
    --preferred-challenges http \
    -m user@example.com
```

### Certificate enrollment with DNS-01

To request a certificate with manual dns-01 validation, execute the following command:

```
$ certbot certonly --manual \
    --server http://$HOSTNAME:8080/acme/directory \
    -d server.example.com \
    --preferred-challenges dns \
    -m user@example.com
```

Create a TXT record in the DNS server as instructed by certbot.
Check the TXT record propagation with the following command:

```
$ dig _acme-challenge.server.example.com TXT
```

Once the TXT record is propagated properly, complete the enrollment using certbot.

## Account Management

### Creating an account

To create an ACME account:

```
$ certbot register \
    --server http://$HOSTNAME:8080/acme/directory \
    -m user@example.com \
    --agree-tos
```

### Updating an account

To update an ACME account:

```
$ certbot update_account \
    --server http://$HOSTNAME:8080/acme/directory \
    -m user@example.com
```

### Deactivating an account

To deactivate an ACME account:

```
$ certbot unregister --server http://$HOSTNAME:8080/acme/directory
```

## See Also

* [Installing ACME Responder](../installation/Installing_ACME_Responder.md)
