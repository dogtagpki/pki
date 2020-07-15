Configuring ACME Database
=========================

## Overview

This document describes the process to configure a database for ACME responder.
The database configuration is located at /etc/pki/pki-tomcat/acme/database.conf.

## Configuring In-Memory Database

The ACME responder can be configured with an in-memory database.

A sample in-memory database configuration is available at
[/usr/share/pki/acme/database/in-memory/database.conf](../../../base/acme/database/in-memory/database.conf).

To use an in-memory database, copy the sample database.conf into the /etc/pki/pki-tomcat/acme folder,
or execute the following command:

```
$ pki-server acme-database-mod --type in-memory
```

The database.conf should look like the following:

```
class=org.dogtagpki.acme.database.InMemoryDatabase
```

There are no parameters to configure for in-memory database.

## Configuring LDAP Database

The ACME responder can be configured with an LDAP database.

First, add the ACME LDAP schema by importing [/usr/share/pki/acme/database/ldap/schema.ldif](../../../base/acme/database/ldap/schema.ldif) with the following command:

```
$ ldapmodify -h $HOSTNAME -x -D "cn=Directory Manager" -w Secret.123 \
    -f /usr/share/pki/acme/database/ldap/schema.ldif
```

Next, prepare an LDIF file to create the ACME LDAP tree.
An sample LDIF file is available at [/usr/share/pki/acme/database/ldap/create.ldif](../../../base/acme/database/ldap/create.ldif).
This example uses dc=acme,dc=pki,dc=example,dc=com as the base DN.
Import the file with the following command:

```
$ ldapadd -h $HOSTNAME -x -D "cn=Directory Manager" -w Secret.123 \
    -f /usr/share/pki/acme/database/ldap/create.ldif
```

A sample LDAP database configuration is available at
[/usr/share/pki/acme/database/ldap/database.conf](../../../base/acme/database/ldap/database.conf).

To use the LDAP database, copy the sample database.conf into the /etc/pki/pki-tomcat/acme folder,
or execute the following command to customize some of the parameters:

```
$ pki-server acme-database-mod --type ldap \
    -DbaseDN=dc=acme,dc=pki,dc=example,dc=com \
    -DbindPassword=Secret.123
```

Customize the configuration as needed. In a standalone ACME deployment, the database.conf should look like the following:

```
class=org.dogtagpki.acme.database.LDAPDatabase
url=ldap://<hostname>:389
authType=BasicAuth
bindDN=cn=Directory Manager
bindPassword=Secret.123
baseDN=dc=acme,dc=pki,dc=example,dc=com
```

In a shared CA and ACME deployment, the database.conf should look like the following:

```
class=org.dogtagpki.acme.database.LDAPDatabase
configFile=conf/ca/CS.cfg
baseDN=dc=acme,dc=pki,dc=example,dc=com
```

## Configuring PosgreSQL Database

The ACME responder can be configured with a PostgreSQL database.

First, prepare a database (e.g. acme) and a user (e.g. acme) to access the database.
Verify the database connection with the following command:

```
$ psql -h $HOSTNAME -d acme -U acme
```

A sample PostgreSQL database configuration is available at
[/usr/share/pki/acme/database/postgresql/database.conf](../../../base/acme/database/postgresql/database.conf).

To use the PostgreSQL database, copy the sample database.conf into the /etc/pki/pki-tomcat/acme folder,
or execute the following command to customize some of the parameters:

```
$ pki-server acme-database-mod --type postgresql \
    -Dpassword=Secret.123
```

The database.conf should look like the following:

```
class=org.dogtagpki.acme.database.PostgreSQLDatabase
url=jdbc:postgresql://<hostname>:5432/acme
user=acme
password=Secret.123
```

## See Also

* [Configuring ACME Responder](https://www.dogtagpki.org/wiki/Configuring_ACME_Responder)
* [Installing ACME Responder](Installing_ACME_Responder.md)
