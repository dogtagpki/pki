Configuring ACME Database
=========================

## Overview

This document describes the process to configure a database for ACME responder.
The database configuration is located at /etc/pki/pki-tomcat/acme/database.conf.

## Configuring In-Memory Database

To configure an in-memory database, copy the sample [database.conf](../../../base/acme/conf/database/in-memory/database.conf) with the following command:

```
$ cp /usr/share/pki/acme/conf/database/in-memory/database.conf \
    /etc/pki/pki-tomcat/acme/database.conf
```

The database.conf should look like the following:

```
class=org.dogtagpki.acme.database.InMemoryDatabase
```

There are no parameters to configure for in-memory database.

## Configuring LDAP Database

First, add the ACME LDAP schema by importing the [schema.ldif](../../../base/acme/conf/database/ldap/schema.ldif) with the following command:

```
$ ldapmodify -h $HOSTNAME -x -D "cn=Directory Manager" -w Secret.123 \
    -f /usr/share/pki/acme/conf/database/ldap/schema.ldif
```

Next, prepare an LDIF file to create the ACME LDAP tree.
An sample LDIF file is available at [/usr/share/pki/acme/conf/database/ldap/create.ldif](../../../base/acme/conf/database/ldap/create.ldif).
This example uses dc=acme,dc=pki,dc=example,dc=com as the base DN.
Import the file with the following command:

```
$ ldapadd -h $HOSTNAME -x -D "cn=Directory Manager" -w Secret.123 \
    -f /usr/share/pki/acme/conf/database/ldap/create.ldif
```

Then copy the sample [database.conf](../../../base/acme/conf/database/ldap/database.conf) with the following command:

```
$ cp /usr/share/pki/acme/conf/database/ldap/database.conf \
    /etc/pki/pki-tomcat/acme/database.conf
```

Customize the configuration as needed. In a standalone ACME deployment, the database.conf should look like the following:

```
class=org.dogtagpki.acme.database.LDAPDatabase
basedn=dc=acme,dc=pki,dc=example,dc=com
internaldb.ldapauth.authtype=BasicAuth
internaldb.ldapauth.bindDN=cn=Directory Manager
internaldb.ldapauth.bindPWPrompt=internaldb
internaldb.ldapconn.host=<hostname>
internaldb.ldapconn.port=389
internaldb.ldapconn.secureConn=false
internaldb.maxConns=15
internaldb.minConns=3
password.internaldb=Secret.123
```

In a shared CA and ACME deployment, the database.conf should look like the following:

```
class=org.dogtagpki.acme.database.LDAPDatabase
configFile=conf/ca/CS.cfg
basedn=dc=acme,dc=pki,dc=example,dc=com
```

## Configuring PosgreSQL Database

Prepare a database (e.g. acme) and a user (e.g. acme) to access the database,
then create the ACME tables by executing the [create.sql](../../../base/acme/conf/database/postgresql/create.sql)
with the following command:

```
$ psql -h $HOSTNAME -d acme -U acme \
    -f /usr/share/pki/acme/conf/database/postgresql/create.sql
```

Then copy the sample [database.conf](../../../base/acme/conf/database/postgresql/database.conf) with the following command:

```
$ cp /usr/share/pki/acme/conf/database/postgresql/database.conf \
    /etc/pki/pki-tomcat/acme/database.conf
```

Customize the configuration as needed. The database.conf should look like the following:

```
class=org.dogtagpki.acme.database.PostgreSQLDatabase
url=jdbc:postgresql://<hostname>:5432/acme
user=acme
password=Secret.123
```

## See Also

* [Configuring ACME Responder](https://www.dogtagpki.org/wiki/Configuring_ACME_Responder)
* [Installing ACME Responder](Installing_ACME_Responder.md)
