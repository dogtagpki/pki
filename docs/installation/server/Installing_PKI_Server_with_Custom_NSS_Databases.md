# Installing PKI Server with Custom NSS Databases

## Overview

This page describes the process to create a PKI server with custom NSS databases.

Normally, when installing a PKI subsystem (e.g. CA) some NSS databases will be created by default, for example:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/ca/alias

Under some circumstances the admin may want to use custom NSS databases (e.g. with trust policy).
In those cases the installation can be done in multiple steps:
* create a basic PKI server
* optionally, create a custom NSS database for the server
* optionally, create a custom NSS database for the admin
* install PKI subsystem with regular installation procedure

## Creating Basic PKI Server

To create a basic PKI server, execute the following command:

```
$ pki-server create
```

This will create a server in /var/lib/pki/pki-tomcat with configuration files in /etc/pki/pki-tomcat.

See also [PKI Server CLI](https://github.com/dogtagpki/pki/wiki/PKI-Server-CLI).

## Creating Custom NSS Database for PKI Server

To create a custom NSS database for the server execute the following commands:

```
$ pki-server nss-create --password <server password>
```

To enable trust policy:

```
$ modutil \
    -dbdir /etc/pki/pki-tomcat/alias \
    -add p11-kit-trust \
    -libfile /usr/share/pki/lib/p11-kit-trust.so
```

See also [PKI Server NSS CLI](https://github.com/dogtagpki/pki/wiki/PKI-Server-NSS-CLI).

## Creating Custom NSS Database for PKI Administrator

To create a custom NSS database for the admin execute the following commands:

```
$ pki -d ~/.dogtag/pki-tomcat/ca/alias -c <client password> nss-create
```

To enable trust policy:

```
$ modutil \
    -dbdir ~/.dogtag/pki-tomcat/ca/alias \
    -add p11-kit-trust \
    -libfile /usr/share/pki/lib/p11-kit-trust.so
```

See also [PKI NSS CLI](https://github.com/dogtagpki/pki/wiki/PKI-NSS-CLI).

## Installling PKI Subsystem

To install a PKI subsystem in this server, follow the regular [installation procedure](https://www.dogtagpki.org/wiki/PKI_10_Installation).
Make sure to use the same NSS database passwords, for example:

```
[DEFAULT]
pki_server_database_password=<server password>

[CA]
pki_client_database_password=<client password>
```
