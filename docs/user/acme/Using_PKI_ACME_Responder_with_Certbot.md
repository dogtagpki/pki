Using PKI ACME Responder with Certbot
=====================================

## Overview

This document describes how to use PKI ACME responder with certbot.
Note that certbot does not accept self-signed CA certificate,
so the examples below are executed over insecure HTTP connections.

| WARNING: Do not use ACME over insecure HTTP connections in production environment. |
| --- |

## Certificate Enrollment

The PKI ACME responder supports certificate enrollment using certbot.
The certificate enrollment can be done with either of the following domain validations:
* HTTP-01
* DNS-01

When enrolling a certificate, certbot will try to create an ACME account on the responder,
unless an account was already created previously.

If a new account is required, enter an email address when asked by certbot
(or specify a `-m <email address>` parameter) and also accept the terms of service
(or specify a `--agree-tos` parameter).

### Certificate enrollment with HTTP-01

To enroll a certificate with automatic HTTP-01 validation, execute the following command:

```
$ certbot certonly --standalone \
    --server http://$HOSTNAME:8080/acme/directory \
    -d server.example.com \
    --preferred-challenges http
```

To enroll a certificate with manual HTTP-01 validation, execute the following command:

```
$ certbot certonly --manual \
    --server http://$HOSTNAME:8080/acme/directory \
    -d server.example.com \
    --preferred-challenges http
```

Configure the challenge response on a web server as instructed by certbot,
then check with the following command:

```
$ curl http://server.example.com/.well-known/acme-challenge/<token>
```

Once the challenge response is configured properly, complete the enrollment using certbot.

### Certificate enrollment with DNS-01

To enroll a certificate with manual DNS-01 validation, execute the following command:

```
$ certbot certonly --manual \
    --server http://$HOSTNAME:8080/acme/directory \
    -d server.example.com \
    --preferred-challenges dns
```

To enroll a wildcard certificate with manual DNS-01 validation, execute the following command:

```
$ certbot certonly --manual \
    --server http://$HOSTNAME:8080/acme/directory \
    -d *.example.com \
    --preferred-challenges dns
```

Create a TXT record in the DNS server as instructed by certbot.
Check the TXT record propagation with the following command:

```
$ dig _acme-challenge.<DNS name> TXT
```

Once the TXT record is propagated properly, complete the enrollment using certbot.

## Certificate Revocation

To revoke a certificate owned by the ACME account:

```
$ certbot revoke \
    --server http://$HOSTNAME:8080/acme/directory \
    --cert-path /etc/letsencrypt/live/server.example.com/cert.pem
```

To revoke a certificate associated with a private key:

```
$ certbot revoke \
    --server http://$HOSTNAME:8080/acme/directory \
    --cert-path /etc/letsencrypt/live/server.example.com/cert.pem \
    --key-path /etc/letsencrypt/live/server.example.com/privkey.pem
```

## Account Management

### Creating an account

To create an ACME account without certificate enrollment:

```
$ certbot register \
    --server http://$HOSTNAME:8080/acme/directory \
    -m <email address> \
    --agree-tos
```

### Updating an account

To update an ACME account:

```
$ certbot update_account \
    --server http://$HOSTNAME:8080/acme/directory \
    -m <new email address>
```

### Deactivating an account

To deactivate an ACME account:

```
$ certbot unregister --server http://$HOSTNAME:8080/acme/directory
```

## See Also

* [certbot](https://certbot.eff.org)
* [Installing ACME Responder](../../installation/acme/Installing_ACME_Responder.md)
