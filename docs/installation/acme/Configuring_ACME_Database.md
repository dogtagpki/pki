Configuring ACME Database
=========================

## Overview

This document describes the process to configure a database for ACME responder.
The database configuration for the ACME responder is located at /etc/pki/pki-tomcat/acme/database.conf.

## Configuring In-Memory Database

To configure an in-memory database, copy the sample configuration file with the following command:

```
$ cp /usr/share/pki/acme/conf/database/in-memory/database.conf \
    /etc/pki/pki-tomcat/acme/database.conf
```

The database.conf should look like the following:

```
class=org.dogtagpki.acme.database.InMemoryDatabase
```

Currently there are no parameters to configure for in-memory database.

## Configuring LDAP Database

To configure an LDAP database, import the ACME LDAP schema with the following command:

```
$ ldapmodify -h $HOSTNAME -x -D "cn=Directory Manager" -w Secret.123 \
    -f /usr/share/pki/acme/conf/database/ldap/schema.ldif
```

Next, prepare an LDIF file to create the ACME LDAP tree.
An sample LDIF file is available at [/usr/share/pki/acme/conf/database/ldap/create.ldif](../../../base/acme/conf/database/ldap/create.ldif).
This example uses dc=acme,dc=pki,dc=example,dc=com as the base DN of the LDAP tree.
Import the file with the following command:

```
$ ldapadd -h $HOSTNAME -x -D "cn=Directory Manager" -w Secret.123 \
    -f /usr/share/pki/acme/conf/database/ldap/create.ldif
```

Then copy the sample configuration file with the following command:

```
$ cp /usr/share/pki/acme/conf/database/ldap/database.conf \
    /etc/pki/pki-tomcat/acme/database.conf
```

In a standalone ACME deployment, the database.conf should look like the following:

```
class=org.dogtagpki.acme.database.LDAPDatabase
basedn=dc=acme,dc=pki,dc=example,dc=com
internaldb.ldapauth.authtype=BasicAuth
internaldb.ldapauth.bindDN=cn=Directory Manager
internaldb.ldapauth.bindPWPrompt=internaldb
internaldb.ldapconn.host=localhost.localdomain
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

## See Also

* [Configuring ACME Responder](https://www.dogtagpki.org/wiki/Configuring_ACME_Responder)
* [Installing ACME Responder](Installing_ACME_Responder.md)
