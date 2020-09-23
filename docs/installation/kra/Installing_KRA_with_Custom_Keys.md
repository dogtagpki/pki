Installing KRA with Custom Keys
===============================

Overview
--------

This page describes the process to install a KRA subsystem with custom KRA system and admin keys, CSRs, and certificates.

Starting KRA Subsystem Installation
-----------------------------------

Prepare a file (e.g. kra-step1.cfg) that contains the deployment configuration step 1, for example:

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

pki_security_domain_name=EXAMPLE
pki_security_domain_user=caadmin
pki_security_domain_password=Secret.123

pki_storage_nickname=kra_storage
pki_transport_nickname=kra_transport
pki_subsystem_nickname=subsystem
pki_sslserver_nickname=sslserver
pki_audit_signing_nickname=kra_audit_signing

pki_external=True
pki_external_step_two=False
```

Then execute the following command:

```
$ pkispawn -f kra-step1.cfg -s KRA
```

It will install KRA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/dogtag/pki-tomcat/kra/alias

Since there are no CSR path parameters specified, it will not generate KRA system and admin keys.

Generating KRA Keys, CSRs, and Certificates
-------------------------------------------

Generate custom KRA system keys in the server NSS database and admin key in the admin NSS database, then generate the CSRs and store them in files, for example:
* kra_storage.csr
* kra_transport.csr
* subsystem.csr
* sslserver.csr
* kra_audit_signing.csr
* kra_admin.csr

Submit the CSRs to an external CA to issue the certificates, then store the certificates in files, for example:
* kra_storage.crt
* kra_transport.crt
* subsystem.crt
* sslserver.crt
* kra_audit_signing.crt
* kra_admin.crt

The certificates can be specified as single certificates or PKCS #7 certificate chains in PEM format.

Store the external CA certificate chain in a file (e.g. ca_signing.crt). The certificate chain can be specified as a single certificate or PKCS #7 certificate chain in PEM format. The certificate chain should include all CA certificates from the root CA to the external CA that issued the KRA system and admin certificates.

See also:
* [Generating KRA Storage Certificate](https://www.dogtagpki.org/wiki/Generating_KRA_Storage_Certificate)
* [Generating KRA Transport Certificate](https://www.dogtagpki.org/wiki/Generating_KRA_Transport_Certificate)
* [Generating Subsystem Certificate](https://www.dogtagpki.org/wiki/Generating_Subsystem_Certificate)
* [Generating SSL Server Certificate](https://www.dogtagpki.org/wiki/Generating_SSL_Server_Certificate)
* [Generating Audit Signing Certificate](https://www.dogtagpki.org/wiki/Generating_Audit_Signing_Certificate)
* [Generating Admin Certificate](https://www.dogtagpki.org/wiki/Generating_Admin_Certificate)

Finishing KRA Subsystem Installation
------------------------------------

Prepare another file (e.g. kra-step2.cfg) that contains the deployment configuration step 2. The file can be copied from step 1 (i.e. kra-step1.cfg) with additional changes below.

Specify step 2 with the following parameter:

```
pki_external_step_two=True
```

Specify the custom CSRs with the following parameters:

```
pki_storage_csr_path=kra_storage.csr
pki_transport_csr_path=kra_transport.csr
pki_subsystem_csr_path=subsystem.csr
pki_sslserver_csr_path=sslserver.csr
pki_audit_signing_csr_path=kra_audit_signing.csr
pki_admin_csr_path=kra_admin.csr
```

Specify the custom certificates with the following parameters:

```
pki_storage_cert_path=kra_storage.crt
pki_transport_cert_path=kra_transport.crt
pki_subsystem_cert_path=subsystem.crt
pki_sslserver_cert_path=sslserver.crt
pki_audit_signing_cert_path=kra_audit_signing.crt
pki_admin_cert_path=kra_admin.crt
```

Specify the external CA certificate chain with the following parameters:

```
pki_cert_chain_nickname=ca_signing
pki_cert_chain_path=ca_signing.crt
```

Finally, execute the following command:

```
$ pkispawn -f kra-step2.cfg -s KRA
```

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
kra_storage                                                  CTu,Cu,Cu
kra_transport                                                u,u,u
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

Import the external CA certificate chain:

```
$ pki -c Secret.123 client-cert-import --ca-cert ca_signing.crt
```

Import the admin key and certificate:

```
$ pki -c Secret.123 client-cert-import \
 --pkcs12 ~/.dogtag/pki-tomcat/kra_admin_cert.p12 \
 --pkcs12-password-file ~/.dogtag/pki-tomcat/ca/pkcs12_password.conf
```

Verify that the admin certificate can be used to access KRA by executing the following command:

```
$ pki -c Secret.123 -n kraadmin kra-user-show kraadmin
---------------
User "kraadmin"
---------------
  User ID: kraadmin
  Full name: kraadmin
  Email: kraadmin@example.com
  Type: adminType
  State: 1
```
