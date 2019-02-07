Installing TPS with Secure Database Connection
==============================================

Overview
--------

This page describes the process to install a TPS subsystem a secure database connection.

Ensure that the secure connection has been enabled on the directory server.
Export the signing certificate for the directory server into ds_signing.crt.
This step is described [here](https://www.dogtagpki.org/wiki/DS_SSL).

TPS Subsystem Installation
--------------------------

Prepare a file (e.g. tps.cfg) that contains the deployment configuration, for example:

```
[DEFAULT]
pki_server_database_password=Secret.123

[TPS]
pki_admin_cert_file=ca_admin.cert
pki_admin_email=tpsadmin@example.com
pki_admin_name=tpsadmin
pki_admin_nickname=tpsadmin
pki_admin_password=Secret.123
pki_admin_uid=tpsadmin

pki_client_database_password=Secret.123
pki_client_database_purge=False
pki_client_pkcs12_password=Secret.123

pki_ds_ldaps_port=636
pki_ds_secure_connection=True
pki_ds_secure_connection_ca_nickname=ds_signing
pki_ds_secure_connection_ca_pem_file=ds_signing.crt

pki_ds_base_dn=dc=tps,dc=pki,dc=example,dc=com
pki_ds_database=tps
pki_ds_password=Secret.123

pki_security_domain_name=EXAMPLE
pki_security_domain_user=caadmin
pki_security_domain_password=Secret.123

pki_audit_signing_nickname=tps_audit_signing
pki_sslserver_nickname=sslserver
pki_subsystem_nickname=subsystem
```

Then execute the following command:

```
$ pkispawn -f tps.cfg -s TPS
```

It will install TPS subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/tps/alias

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ds_signing                                                   CT,C,C
ca_signing                                                   CT,C,C
subsystem                                                    u,u,u
tps_audit_signing                                            u,u,Pu
sslserver                                                    u,u,u
```

Verifying Database Configuration
--------------------------------

Verify that the TPS database is configured with a secure connection:

```
$ pki-server tps-db-config-show
  Hostname: server.example.com
  Port: 636
  Secure: true
  Authentication: BasicAuth
  Bind DN: cn=Directory Manager
  Bind Password Prompt: internaldb
  Database: tps
  Base DN: dc=tps,dc=pki,dc=example,dc=com
  Multiple suffix: false
  Maximum connections: 15
  Minimum connections: 3
```

Verifying Admin Certificate
---------------------------

Prepare a client NSS database (e.g. ~/.dogtag/nssdb):

```
$ pki -c Secret.123 client-init
```

Import the CA signing certificate:

```
$ pki -c Secret.123 client-cert-import ca_signing --ca-cert ca_signing.crt
```

Import admin key and certificate:

```
$ pki -c Secret.123 client-cert-import \
 --pkcs12 ca_admin_cert.p12 \
 --pkcs12-password-file pkcs12_password.conf
```

Verify that the admin certificate can be used to access the TPS subsystem by executing the following command:

```
$ pki -c Secret.123 -n caadmin tps-user-show tpsadmin
---------------
User "tpsadmin"
---------------
  User ID: tpsadmin
  Full name: tpsadmin
  Email: tpsadmin@example.com
  Type: adminType
  State: 1
  TPS Profiles:
    All Profiles
```
