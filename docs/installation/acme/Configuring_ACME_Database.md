Configuring ACME Database
=========================

## Overview

This document describes the process to configure a database for ACME responder.
The database configuration is located at /etc/pki/pki-tomcat/acme/database.conf.

The `pki-server acme-database-mod` can be used to configure the database via command-line.
If the command is invoked without any parameters, it will enter an interactive mode, for example:

```
$ pki-server acme-database-mod
The current value is displayed in the square brackets.
To keep the current value, simply press Enter.
To change the current value, enter the new value.
To remove the current value, enter a blank space.

Enter the type of the database. Available types: ds, in-memory, ldap, openldap, postgresql.
  Database Type: ds

Enter the location of the LDAP server (e.g. ldap://localhost.localdomain:389).
  Server URL [ldap://localhost.localdomain:389]:

Enter the authentication type. Available types: BasicAuth, SslClientAuth.
  Authentication Type [BasicAuth]:

Enter the bind DN.
  Bind DN [cn=Directory Manager]:

Enter the bind password.
  Bind Password [********]:

Enter the base DN for the ACME subtree.
  Base DN [dc=acme,dc=pki,dc=example,dc=com]:
```

If the command is invoked with `--type` parameter, it will create a new configuration based on the specified type.
If the command is invoked with other parameters, it will update the specified parameters.

Some ACME configuration properties are stored in the database such that
all ACME responders in the cluster can be configured consistently.
By default the ACME responder will access the database directly
when retrieving or updating the ACME configuration properties,
which may increase the load on the database.
Some databases might provide an ACME configuration monitor to reduce the load on the database.

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

## Configuring DS Database

The ACME responder can be configured with a DS database.

First, add the ACME DS schema by importing [/usr/share/pki/acme/database/ds/schema.ldif](../../../base/acme/database/ds/schema.ldif) with the following command:

```
$ ldapmodify -h $HOSTNAME -x -D "cn=Directory Manager" -w Secret.123 \
    -f /usr/share/pki/acme/database/ds/schema.ldif
```

Next, prepare an LDIF file to create the ACME subtree.
A sample LDIF file is available at [/usr/share/pki/acme/database/ds/create.ldif](../../../base/acme/database/ds/create.ldif).
This example uses dc=acme,dc=pki,dc=example,dc=com as the base DN.
Import the file with the following command:

```
$ ldapadd -h $HOSTNAME -x -D "cn=Directory Manager" -w Secret.123 \
    -f /usr/share/pki/acme/database/ds/create.ldif
```

A sample DS database configuration is available at
[/usr/share/pki/acme/database/ds/database.conf](../../../base/acme/database/ds/database.conf).

To use the DS database, copy the sample database.conf into the /etc/pki/pki-tomcat/acme folder,
or execute the following command to customize some of the parameters:

```
$ pki-server acme-database-mod --type ds \
    -DbindPassword=Secret.123
```

Customize the configuration as needed. In a standalone ACME deployment, the database.conf should look like the following:

```
class=org.dogtagpki.acme.database.DSDatabase
url=ldap://<hostname>:389
authType=BasicAuth
bindDN=cn=Directory Manager
bindPassword=Secret.123
baseDN=dc=acme,dc=pki,dc=example,dc=com
```

In a shared CA and ACME deployment, the database.conf should look like the following:

```
class=org.dogtagpki.acme.database.DSDatabase
configFile=conf/ca/CS.cfg
baseDN=dc=acme,dc=pki,dc=example,dc=com
```

The DS database provides an ACME configuration monitor using search persistence.
It can be enabled with the following parameter:

```
monitor.enabled=true
```

## Configuring OpenLDAP Database

The ACME responder can be configured with an OpenLDAP database.

First, add the ACME OpenLDAP schema by importing [/usr/share/pki/acme/database/openldap/schema.ldif](../../../base/acme/database/openldap/schema.ldif) with the following command:

```
$ ldapadd -H ldapi:/// -Y EXTERNAL \
    -f /usr/share/pki/acme/database/openldap/schema.ldif
```

Next, prepare an LDIF file to create the ACME subtree.
A sample LDIF file is available at [/usr/share/pki/acme/database/openldap/create.ldif](../../../base/acme/database/openldap/create.ldif).
This example uses dc=acme,dc=pki,dc=example,dc=com as the base DN.
Import the file with the following command:

```
$ ldapadd -h $HOSTNAME -x -D "cn=Manager,dc=example,dc=com" -w Secret.123 \
    -f /usr/share/pki/acme/database/openldap/create.ldif
```

A sample OpenLDAP database configuration is available at
[/usr/share/pki/acme/database/openldap/database.conf](../../../base/acme/database/openldap/database.conf).

To use the OpenLDAP database, copy the sample database.conf into the /etc/pki/pki-tomcat/acme folder,
or execute the following command to customize some of the parameters:

```
$ pki-server acme-database-mod --type openldap \
    -DbindPassword=Secret.123
```

Customize the configuration as needed. The database.conf should look like the following:

```
class=org.dogtagpki.acme.database.OpenLDAPDatabase
url=ldap://<hostname>:389
authType=BasicAuth
bindDN=cn=Manager,dc=example,dc=com
bindPassword=Secret.123
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

* [Configuring PKI ACME Responder](https://www.dogtagpki.org/wiki/Configuring_PKI_ACME_Responder)
* [Installing PKI ACME Responder](Installing_PKI_ACME_Responder.md)
