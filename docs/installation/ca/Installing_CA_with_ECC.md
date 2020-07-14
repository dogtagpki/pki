Installing CA with ECC
======================

Overview
--------

This page describes the process to install a CA subsystem with ECC self-signed CA signing certificate.

Before beginning with the installation, please ensure that you have configured the directory server and added base entries. The step is described [here](http://www.dogtagpki.org/wiki/Installing_DS).

Additionally, please verify that your FQDN is correctly reported by the following command:

    python -c 'import socket; print(socket.getfqdn())'

If it isn't, please add and entry at the beginning of the `/etc/hosts` file:

    127.0.0.1 server.example.com
    ::1 server.example.com

Supported ECC curves:

- nistp256 
- nistp384
- nistp521

Supported ECC key algorithms:

- SHA256withEC 
- SHA384withEC
- SHA512withEC

CA Subsystem Installation
-------------------------

Prepare a file (e.g. ca.cfg) that contains the deployment configuration, for example:
```
[DEFAULT]
pki_server_database_password=Secret.123

[CA]
pki_admin_email=caadmin@example.com
pki_admin_name=caadmin
pki_admin_nickname=caadmin
pki_admin_password=Secret.123
pki_admin_uid=caadmin
pki_admin_key_type=ecc
pki_admin_key_size=nistp521
pki_admin_key_algorithm=SHA512withEC

pki_client_database_password=Secret.123
pki_client_database_purge=False
pki_client_pkcs12_password=Secret.123

pki_ds_base_dn=dc=ca,dc=pki,dc=example,dc=com
pki_ds_database=ca
pki_ds_password=Secret.123

pki_security_domain_name=EXAMPLE

pki_ca_signing_nickname=ca_signing
pki_ca_signing_key_type=ecc
pki_ca_signing_key_algorithm=SHA512withEC
pki_ca_signing_key_size=nistp521
pki_ca_signing_signing_algorithm=SHA512withEC

pki_ocsp_signing_nickname=ca_ocsp_signing
pki_ocsp_signing_key_type=ecc
pki_ocsp_signing_key_algorithm=SHA512withEC
pki_ocsp_signing_key_size=nistp521
pki_ocsp_signing_signing_algorithm=SHA512withEC

pki_audit_signing_nickname=ca_audit_signing
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
$ pkispawn -f ca.cfg -s CA
```

It will install CA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/ca/alias

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CTu,Cu,Cu
ca_ocsp_signing                                              u,u,u
subsystem                                                    u,u,u
ca_audit_signing                                             u,u,Pu
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
 --pkcs12 ~/.dogtag/pki-tomcat/ca_admin_cert.p12 \
 --pkcs12-password-file ~/.dogtag/pki-tomcat/ca/pkcs12_password.conf
```

Verify that the admin certificate can be used to access the CA subsystem by executing the following command:

```
$ pki -c Secret.123 -n caadmin ca-user-show caadmin
--------------
User "caadmin"
--------------
  User ID: caadmin
  Full name: caadmin
  Email: caadmin@example.com
  Type: adminType
  State: 1
```
