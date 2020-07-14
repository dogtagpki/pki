Installing OCSP with ECC
========================

Overview
--------

This page describes the process to install a OCSP subsystem with ECC.

Supported ECC curves:

- nistp256 
- nistp384
- nistp521

Supported ECC key algorithms:

- SHA256withEC 
- SHA384withEC
- SHA512withEC

OCSP Subsystem Installation
---------------------------

Prepare a file (e.g. ocsp.cfg) that contains the deployment configuration, for example:

```
[DEFAULT]
pki_server_database_password=Secret.123

[OCSP]
pki_admin_cert_file=ca_admin.cert
pki_admin_email=ocspadmin@example.com
pki_admin_name=ocspadmin
pki_admin_nickname=ocspadmin
pki_admin_password=Secret.123
pki_admin_uid=ocspadmin

pki_client_database_password=Secret.123
pki_client_database_purge=False
pki_client_pkcs12_password=Secret.123

pki_ds_base_dn=dc=ocsp,dc=pki,dc=example,dc=com
pki_ds_database=ocsp
pki_ds_password=Secret.123

pki_security_domain_name=EXAMPLE
pki_security_domain_user=caadmin
pki_security_domain_password=Secret.123

pki_ocsp_signing_nickname=ocsp_signing
pki_ocsp_signing_key_type=ecc
pki_ocsp_signing_key_algorithm=SHA512withEC
pki_ocsp_signing_key_size=nistp521

pki_audit_signing_nickname=ocsp_audit_signing
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
$ pkispawn -f ocsp.cfg -s OCSP
```

It will install OCSP subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
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
subsystem                                                    u,u,u
ocsp_audit_signing                                           u,u,Pu
ocsp_signing                                                 u,u,u
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

Verify that the admin certificate can be used to access the OCSP subsystem by executing the following command:

```
$ pki -c Secret.123 -n caadmin ocsp-user-show ocspadmin
--------------
User "ocspadmin"
--------------
  User ID: ocspadmin
  Full name: ocspadmin
  Email: ocspadmin@example.com
  Type: adminType
  State: 1
```
