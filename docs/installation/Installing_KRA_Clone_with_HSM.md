Installing KRA Clone with HSM
=============================

Overview
--------

This page describes the process to install a KRA subsystem as a clone of an existing KRA subsystem
where the system certificates and their keys are stored in HSM.

Since the certificates and the keys are already in HSM, it's not necessary to export them into a
PKCS #12 file to create a clone.

KRA Subsystem Installation
--------------------------

Prepare a file (e.g. kra.cfg) that contains the deployment configuration, for example:

```
[DEFAULT]
pki_server_database_password=Secret.123

pki_hsm_enable=True
pki_hsm_libfile=/usr/lib64/pkcs11/libsofthsm2.so
pki_hsm_modulename=softhsm
pki_token_name=token
pki_token_password=Secret.123

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
pki_sslserver_nickname=sslserver/replica.example.com
pki_subsystem_nickname=subsystem

pki_clone=True
pki_clone_replicate_schema=True
pki_clone_uri=https://server.example.com:8443
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

Verify that the internal token contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
kra_audit_signing                                            ,,P
```

Verify that the HSM contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias -h token -f token.pwd

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

token:kra_transport                                          u,u,u
token:kra_storage                                            u,u,u
token:subsystem                                              u,u,u
token:kra_audit_signing                                      u,u,Pu
token:sslserver/replica.example.com                          u,u,u
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
