Configuring ACME Realm
======================

## Overview

This document describes the process to configure a realm for ACME responder.
The realm configuration is located at /etc/pki/pki-tomcat/acme/realm.conf.

The `pki-server acme-realm-mod` can be used to configure the realm via command-line.
If the command is invoked without any parameters, it will enter an interactive mode, for example:

```
$ pki-server acme-realm-mod
The current value is displayed in the square brackets.
To keep the current value, simply press Enter.
To change the current value, enter the new value.
To remove the current value, enter a blank space.

Enter the type of the realm. Available types: ds.
  Database Type: ds

Enter the location of the LDAP server (e.g. ldap://localhost.localdomain:389).
  Server URL [ldap://localhost.localdomain:389]:

Enter the authentication type. Available types: BasicAuth, SslClientAuth.
  Authentication Type [BasicAuth]:

Enter the bind DN.
  Bind DN [cn=Directory Manager]:

Enter the bind password.
  Bind Password [********]:

Enter the base DN for the ACME users subtree.
  Users DN [ou=people,dc=acme,dc=pki,dc=example,dc=com]:

Enter the base DN for the ACME groups subtree.
  Groups DN [ou=groups,dc=acme,dc=pki,dc=example,dc=com]:
```

If the command is invoked with `--type` parameter, it will create a new configuration based on the specified type.
If the command is invoked with other parameters, it will update the specified parameters.

## Configuring ACME with In-Memory Realm

The ACME responder can be configured with an in-memory realm.

A sample in-memory realm configuration is available at
[/usr/share/pki/acme/realm/in-memory/realm.conf](../../../base/acme/realm/in-memory/realm.conf).

To use an in-memory realm, copy the sample realm.conf into the /etc/pki/pki-tomcat/acme folder,
or execute the following command:

```
$ pki-server acme-realm-mod --type in-memory
```

The realm.conf should look like the following:

```
class=org.dogtagpki.acme.realm.InMemoryRealm
username=admin
password=Secret.123
```

## Configuring ACME with DS Realm

The ACME responder can be configured with a DS realm.
See [Configuring ACME with DS Realm](Configuring-ACME-with-DS-Realm.adoc).

## Configuring ACME with PosgreSQL Realm

The ACME responder can be configured with a PostgreSQL realm.

First, prepare a database (e.g. acme) and a user (e.g. acme) to access the database.
Verify the database connection with the following command:

```
$ psql -h $HOSTNAME -d acme -U acme
```

A sample PostgreSQL realm configuration is available at
[/usr/share/pki/acme/realm/postgresql/realm.conf](../../../base/acme/realm/postgresql/realm.conf).

To use the PostgreSQL realm, copy the sample realm.conf into the /etc/pki/pki-tomcat/acme folder,
or execute the following command to customize some of the parameters:

```
$ pki-server acme-realm-mod --type postgresql \
    -Dpassword=Secret.123
```

The realm.conf should look like the following:

```
class=org.dogtagpki.acme.realm.PostgreSQLRealm
url=jdbc:postgresql://<hostname>:5432/acme
user=acme
password=Secret.123
```

## See Also

* [Configuring PKI ACME Responder](https://www.dogtagpki.org/wiki/Configuring_PKI_ACME_Responder)
* [Installing PKI ACME Responder](Installing_PKI_ACME_Responder.md)
* [Managing PostgreSQL Realm](../../admin/acme/Managing_PostgreSQL_Realm.adoc)
