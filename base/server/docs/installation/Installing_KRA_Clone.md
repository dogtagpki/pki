Installing KRA Clone
====================

Overview
--------

This page describes the process to install a KRA subsystem as a clone of an existing KRA subsystem.

Exporting Existing System Certificates
--------------------------------------

Export the existing system certificates (including the certificate chain) into a PKCS #12 file, for example:

```
$ pki-server kra-clone-prepare --pkcs12-file kra-certs.p12 --pkcs12-password Secret.123
```

If necessary, third-party certificates (e.g. trust anchors) can be added into the same PKCS #12 file with the following command:

```
$ pki -d /etc/pki/pki-tomcat/alias -f /etc/pki/pki-tomcat/password.conf \
    pkcs12-cert-import <nickname> --pkcs12-file kra-certs.p12 --pkcs12-password Secret.123 --append
```

KRA Subsystem Installation
--------------------------

Prepare a file (e.g. kra.cfg) that contains the deployment configuration, for example:

```
[DEFAULT]
pki_server_database_password=Secret.123

[KRA]
pki_admin_email=kraadmin@example.com
pki_admin_name=kraadmin
pki_admin_nickname=kraadmin
pki_admin_password=Secret.123
pki_admin_uid=kraadmin

pki_client_database_password=Secret.123
pki_client_database_purge=False
pki_client_pkcs12_password=Secret.123

pki_ds_base_dn=dc=kra,dc=pki,dc=example,dc=com
pki_ds_database=kra
pki_ds_password=Secret.123

pki_security_domain_hostname=server.example.com
pki_security_domain_https_port=8443
pki_security_domain_user=caadmin
pki_security_domain_password=Secret.123

pki_storage_nickname=kra_storage
pki_transport_nickname=kra_transport
pki_audit_signing_nickname=kra_audit_signing
pki_sslserver_nickname=sslserver
pki_subsystem_nickname=subsystem

pki_clone=True
pki_clone_replicate_schema=True
pki_clone_uri=https://server.example.com:8443
pki_clone_pkcs12_path=kra-certs.p12
pki_clone_pkcs12_password=Secret.123
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

ca_signing                                                   CT,C,C
kra_storage                                                  u,u,u
sslserver                                                    u,u,u
subsystem                                                    u,u,u
kra_audit_signing                                            u,u,Pu
kra_transport                                                u,u,u
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

Import the master's admin key and certificate:

```
$ pki -c Secret.123 client-cert-import \
 --pkcs12 ca_admin_cert.p12 \
 --pkcs12-password-file pkcs12_password.conf
```

Verify that the admin certificate can be used to access the KRA clone by executing the following command:

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
