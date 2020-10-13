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

## Configuring DS Realm

The ACME responder can be configured with a DS realm.

Prepare subtrees for ACME users and groups in DS.
A sample LDIF file is available at [/usr/share/pki/acme/realm/ds/create.ldif](../../../base/acme/realm/ds/create.ldif).
This example uses dc=acme,dc=pki,dc=example,dc=com as the base DN.
Import the file with the following command:

```
$ ldapadd -h $HOSTNAME -x -D "cn=Directory Manager" -w Secret.123 \
    -f /usr/share/pki/acme/realm/ds/create.ldif
```

A sample DS realm configuration is available at
[/usr/share/pki/acme/realm/ds/realm.conf](../../../base/acme/realm/ds/realm.conf).

To use the DS realm, copy the sample realm.conf into the /etc/pki/pki-tomcat/acme folder,
or execute the following command to customize some of the parameters:

```
$ pki-server acme-realm-mod --type ds \
    -DbindPassword=Secret.123
```

Customize the configuration as needed. In a standalone ACME deployment, the realm.conf should look like the following:

```
class=org.dogtagpki.acme.realm.DSRealm
url=ldap://<hostname>:389
authType=BasicAuth
bindDN=cn=Directory Manager
bindPassword=Secret.123
usersDN=ou=people,dc=acme,dc=pki,dc=example,dc=com
groupsDN=ou=groups,dc=acme,dc=pki,dc=example,dc=com
```

In a shared CA and ACME deployment, the realm.conf should look like the following:

```
class=org.dogtagpki.acme.realm.DSRealm
configFile=conf/ca/CS.cfg
usersDN=ou=people,dc=ca,dc=pki,dc=example,dc=com
groupsDN=ou=groups,dc=ca,dc=pki,dc=example,dc=com
```

## Configuring PosgreSQL Realm

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
* [Managing DS Realm](../../admin/acme/Managing_DS_Realm.adoc)
* [Managing PostgreSQL Realm](../../admin/acme/Managing_PostgreSQL_Realm.adoc)
