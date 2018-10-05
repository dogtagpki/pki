Installing OCSP with External Certificates
==========================================

Overview
--------

This page describes the process to install a OCSP subsystem with external certificates.

Starting OCSP Subsystem Installation
------------------------------------

Prepare a file (e.g. ocsp-step1.cfg) that contains the deployment configuration step 1, for example:

```
[DEFAULT]
pki_server_database_password=Secret.123

[OCSP]
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
pki_subsystem_nickname=subsystem
pki_sslserver_nickname=sslserver
pki_audit_signing_nickname=ocsp_audit_signing

pki_external=True
pki_external_step_two=False

pki_ocsp_signing_csr_path=ocsp_signing.csr
pki_subsystem_csr_path=subsystem.csr
pki_sslserver_csr_path=sslserver.csr
pki_audit_signing_csr_path=ocsp_audit_signing.csr
pki_admin_csr_path=ocsp_admin.csr
```

Then execute the following command:

```
$ pkispawn -f ocsp-step1.cfg -s OCSP
```

It will install OCSP subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/ocsp/alias

It will also generate the system keys in the server NSS database and the CSRs in the specified paths.

Generating OCSP Certificates
----------------------------

Submit the CSRs to an external CA to issue the certificates, then store the certificates in files, for example:
* ocsp_signing.crt
* subsystem.crt
* sslserver.crt
* ocsp_audit_signing.crt
* ocsp_admin.crt

The certificates can be specified as single certificates or PKCS #7 certificate chains in PEM format.

Store the external CA certificate chain in a file (e.g. ca_signing.crt). The certificate chain can be specified as a single certificate or PKCS #7 certificate chain in PEM format. The certificate chain should include all CA certificates from the root CA to the external CA that issued the OCSP system and admin certificates.

Finishing OCSP Subsystem Installation
-------------------------------------

Prepare another file (e.g. ocsp-step2.cfg) that contains the deployment configuration step 2. The file can be copied from step 1 (i.e. ocsp-step1.cfg) with additional changes below.

Specify step 2 with the following parameter:

```
pki_external_step_two=True
```

Specify the custom certificates with the following parameters:

```
pki_ocsp_signing_cert_path=ocsp_signing.crt
pki_subsystem_cert_path=subsystem.crt
pki_sslserver_cert_path=sslserver.crt
pki_audit_signing_cert_path=ocsp_audit_signing.crt
pki_admin_cert_path=ocsp_admin.crt
```

Specify the external CA certificate chain with the following parameters:

```
pki_cert_chain_nickname=ca_signing
pki_cert_chain_path=ca_signing.crt
```

Finally, execute the following command:

```
$ pkispawn -f ocsp-step2.cfg -s OCSP
```

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
ocsp_signing                                                 CTu,Cu,Cu
subsystem                                                    u,u,u
ocsp_audit_signing                                           u,u,Pu
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
 --pkcs12 ~/.dogtag/pki-tomcat/ocsp_admin_cert.p12 \
 --pkcs12-password-file ~/.dogtag/pki-tomcat/ca/pkcs12_password.conf
```

Verify that the admin certificate can be used to access the OCSP subsystem by executing the following command:

```
$ pki -c Secret.123 -n ocspadmin ocsp-user-show ocspadmin
----------------
User "ocspadmin"
----------------
  User ID: ocspadmin
  Full name: ocspadmin
  Email: ocspadmin@example.com
  Type: adminType
  State: 1
```
