Installing TKS with HSM
=======================

Overview
--------

This page describes the process to install a TKS subsystem
where the system certificates and their keys will be stored in HSM.

TKS Subsystem Installation
--------------------------

Prepare a file (e.g. tks.cfg) that contains the deployment configuration, for example:

```
[DEFAULT]
pki_server_database_password=Secret.123

pki_hsm_enable=True
pki_hsm_libfile=/usr/lib64/pkcs11/libsofthsm2.so
pki_hsm_modulename=softhsm
pki_token_name=token
pki_token_password=Secret.123

[TKS]
pki_admin_cert_file=ca_admin.cert
pki_admin_email=tksadmin@example.com
pki_admin_name=tksadmin
pki_admin_nickname=tksadmin
pki_admin_password=Secret.123
pki_admin_uid=tksadmin

pki_client_database_password=Secret.123
pki_client_database_purge=False
pki_client_pkcs12_password=Secret.123

pki_ds_base_dn=dc=tks,dc=pki,dc=example,dc=com
pki_ds_database=tks
pki_ds_password=Secret.123

pki_security_domain_name=EXAMPLE
pki_security_domain_user=caadmin
pki_security_domain_password=Secret.123

pki_audit_signing_nickname=tks_audit_signing
pki_sslserver_nickname=sslserver
pki_subsystem_nickname=subsystem
```

Then execute the following command:

```
$ pkispawn -f tks.cfg -s TKS
```

It will install TKS subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/tks/alias

Verifying System Certificates
-----------------------------

Verify that the internal token contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
tks_audit_signing                                            ,,P
```

Verify that the HSM contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias -h token -f token.pwd

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

token:subsystem                                              u,u,u
token:tks_audit_signing                                      u,u,Pu
token:sslserver                                              u,u,u
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

Verify that the admin certificate can be used to access the TKS subsystem by executing the following command:

```
$ pki -c Secret.123 -n caadmin tks-user-show tksadmin
---------------
User "tksadmin"
---------------
  User ID: tksadmin
  Full name: tksadmin
  Email: tksadmin@example.com
  Type: adminType
  State: 1
```
