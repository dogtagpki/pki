Installing KRA with ECC
======================

Overview
--------

This page describes the process to install a KRA subsystem with ECC.

Supported ECC curves:

- nistp256 
- nistp384
- nistp521

Supported ECC key algorithms:

- SHA256withEC 
- SHA384withEC
- SHA512withEC

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

pki_ds_base_dn=dc=kra,dc=pki,dc=example,dc=com
pki_ds_database=kra
pki_ds_password=Secret.123

pki_security_domain_name=EXAMPLE
pki_security_domain_user=caadmin
pki_security_domain_password=Secret.123

pki_storage_nickname=kra_storage
pki_storage_key_type=rsa
pki_storage_key_algorithm=SHA512withRSA
pki_storage_key_size=2048
pki_storage_signing_algorithm=SHA512withRSA

pki_transport_nickname=kra_transport
pki_transport_key_type=rsa
pki_transport_key_algorithm=SHA512withRSA
pki_transport_key_size=2048
pki_transport_signing_algorithm=SHA512withRSA

pki_audit_signing_nickname=kra_audit_signing
pki_audit_signing_key_type=ecc
pki_audit_signing_key_algorithm=SHA512withEC
pki_audit_signing_key_size=nistp521
pki_audit_signing_signing_algorithm=SHA512withEC

pki_sslserver_nickname=sslserver
pki_sslserver_key_type=ecc
pki_sslserver_key_algorithm=SHA512withEC
pki_sslserver_key_size=nistp521

pki_subsystem_nickname=subsystem
pki_subsystem_key_type=ecc
pki_subsystem_key_algorithm=SHA512withEC
pki_subsystem_key_size=nistp521
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
kra_transport                                                u,u,u
kra_storage                                                  u,u,u
subsystem                                                    u,u,u
kra_audit_signing                                            u,u,Pu
sslserver                                                    u,u,u
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
--------------
User "kraadmin"
--------------
  User ID: kraadmin
  Full name: kraadmin
  Email: kraadmin@example.com
  Type: adminType
  State: 1
```
