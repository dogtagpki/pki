Installing KRA with Secure Database Connection
==============================================

Overview
--------

This page describes the process to install a KRA subsystem with a secure database connection.

Ensure that the secure connection has been enabled on the directory server.
Export the signing certificate for the directory server into ds_signing.crt.
This step is described [here](https://www.dogtagpki.org/wiki/DS_SSL).

KRA Subsystem Installation
--------------------------

Prepare a file (e.g. kra.cfg) that contains the deployment configuration, for example:

```
[DEFAULT]
pki_server_database_password=Secret.123

[KRA]
pki_admin_cert_file=ca_admin.cert
pki_admin_email=kraadmin@example.com
pki_admin_name=kraadmin
pki_admin_nickname=kraadmin
pki_admin_password=Secret.123
pki_admin_uid=kraadmin

pki_client_database_password=Secret.123
pki_client_database_purge=False
pki_client_pkcs12_password=Secret.123

pki_ds_ldaps_port=636
pki_ds_secure_connection=True
pki_ds_secure_connection_ca_nickname=ds_signing
pki_ds_secure_connection_ca_pem_file=ds_signing.crt

pki_ds_base_dn=dc=kra,dc=pki,dc=example,dc=com
pki_ds_database=kra
pki_ds_password=Secret.123

pki_security_domain_name=EXAMPLE
pki_security_domain_user=caadmin
pki_security_domain_password=Secret.123

pki_storage_nickname=kra_storage
pki_transport_nickname=kra_transport
pki_audit_signing_nickname=kra_audit_signing
pki_sslserver_nickname=sslserver
pki_subsystem_nickname=subsystem
```

Then execute the following command:

```
$ pkispawn -f kra.cfg -s KRA
```

It will install KRA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/kra/alias

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ds_signing                                                   CT,C,C
ca_signing                                                   CT,C,C
kra_transport                                                u,u,u
kra_storage                                                  u,u,u
subsystem                                                    u,u,u
kra_audit_signing                                            u,u,Pu
sslserver                                                    u,u,u
```

Verifying Database Configuration
--------------------------------

Verify that the KRA database is configured with a secure connection:

```
$ pki-server kra-db-config-show
  Hostname: server.example.com
  Port: 636
  Secure: true
  Authentication: BasicAuth
  Bind DN: cn=Directory Manager
  Bind Password Prompt: internaldb
  Database: kra
  Base DN: dc=kra,dc=pki,dc=example,dc=com
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

Verify that the admin certificate can be used to access the KRA subsystem by executing the following command:

```
$ pki -c Secret.123 -n caadmin kra-user-show kraadmin
---------------
User "kraadmin"
---------------
  User ID: kraadmin
  Full name: kraadmin
  Email: kraadmin@example.com
  Type: adminType
  State: 1
```

Verifying KRA Connector
-----------------------

Verify that the KRA connector is configured in the CA subsystem:

```
$ pki -c Secret.123 -n caadmin ca-kraconnector-show

Host: server.example.com:8443
Enabled: true
Local: false
Timeout: 30
URI: /kra/agent/kra/connector
Transport Cert:

<base-64 certificate>
```
