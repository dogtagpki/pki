Installing CA with Existing Keys in HSM
=======================================

Overview
--------

This page describes the process to install a CA subsystem with the system keys, CSRs, and certificates from an existing CA
where the keys are stored in HSM.

To avoid conflicts with the existing CA subsystem, the new CA subsystem will use new SSL server and subsystem certificates,
so they will not be included in the installation process.

Starting CA Subsystem Installation
----------------------------------

Prepare a file (e.g. ca-step1.cfg) that contains the deployment configuration step 1, for example:

```
[DEFAULT]
pki_server_database_password=Secret.123

pki_hsm_enable=True
pki_hsm_libfile=/usr/lib64/pkcs11/libsofthsm2.so
pki_hsm_modulename=softhsm
pki_token_name=token
pki_token_password=Secret.123

[CA]
pki_admin_email=caadmin@example.com
pki_admin_name=caadmin
pki_admin_nickname=caadmin
pki_admin_password=Secret.123
pki_admin_uid=caadmin

pki_client_pkcs12_password=Secret.123

pki_ds_base_dn=dc=ca,dc=pki,dc=example,dc=com
pki_ds_database=ca
pki_ds_password=Secret.123

pki_security_domain_name=EXAMPLE

pki_ca_signing_nickname=ca_signing
pki_ocsp_signing_nickname=ca_ocsp_signing
pki_audit_signing_nickname=ca_audit_signing
pki_sslserver_nickname=sslserver/server.example.com
pki_subsystem_nickname=subsystem/server.example.com

pki_external=True
pki_external_step_two=False
```

Then execute the following command:

```
$ pkispawn -f ca-step1.cfg -s CA
```

It will install CA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/ca/alias

Since there are no CSR path parameters specified, it will not generate CA system and admin keys.

Exporting Existing System Certificates and CSRs
-----------------------------------------------

Export the system certificates from the existing CA with the following commands:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias -h token -f token.pwd -n "token:ca_signing" -a > ca_signing.crt
$ certutil -L -d /etc/pki/pki-tomcat/alias -h token -f token.pwd -n "token:ca_ocsp_signing" -a > ca_ocsp_signing.crt
$ certutil -L -d /etc/pki/pki-tomcat/alias -h token -f token.pwd -n "token:ca_audit_signing" -a > ca_audit_signing.crt
```

Export the CSRs from the existing CA with the following commands:

```
$ echo "-----BEGIN CERTIFICATE REQUEST-----" > ca_signing.csr
$ sed -n "/^ca.signing.certreq=/ s/^[^=]*=// p" < /etc/pki/pki-tomcat/ca/CS.cfg >> ca_signing.csr
$ echo "-----END CERTIFICATE REQUEST-----" >> ca_signing.csr

$ echo "-----BEGIN CERTIFICATE REQUEST-----" > ca_ocsp_signing.csr
$ sed -n "/^ca.ocsp_signing.certreq=/ s/^[^=]*=// p" < /etc/pki/pki-tomcat/ca/CS.cfg >> ca_ocsp_signing.csr
$ echo "-----END CERTIFICATE REQUEST-----" >> ca_ocsp_signing.csr

$ echo "-----BEGIN CERTIFICATE REQUEST-----" > ca_audit_signing.csr
$ sed -n "/^ca.audit_signing.certreq=/ s/^[^=]*=// p" < /etc/pki/pki-tomcat/ca/CS.cfg >> ca_audit_signing.csr
$ echo "-----END CERTIFICATE REQUEST-----" >> ca_audit_signing.csr
```

Finishing CA Subsystem Installation
-----------------------------------

Prepare another file (e.g. ca-step2.cfg) that contains the deployment configuration step 2.
The file can be copied from step 1 (i.e. ca-step1.cfg) with additional changes below.

Specify step 2 with the following parameter:

```
pki_external_step_two=True
```

Specify the existing certificates with the following parameters:

```
pki_ca_signing_cert_path=ca_signing.crt
pki_ocsp_signing_cert_path=ca_ocsp_signing.crt
pki_audit_signing_cert_path=ca_audit_signing.crt
```

Specify the existing CSRs with the following parameters:

```
pki_ca_signing_csr_path=ca_signing.csr
pki_ocsp_signing_csr_path=ca_ocsp_signing.csr
pki_audit_signing_csr_path=ca_audit_signing.csr
```

Specify the serial number starting range such that new certificates will not conflict with the existing certificates:

```
pki_serial_number_range_start=6
```

Finally, execute the following command:

```
$ pkispawn -f ca-step2.cfg -s CA
```

Verifying System Certificates
-----------------------------

Verify that the internal token contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
ca_audit_signing                                             ,,P
```

Verify that the HSM contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias -h token -f token.pwd

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

token:ca_signing                                             CTu,Cu,Cu
token:ca_ocsp_signing                                        u,u,u
token:subsystem/server.example.com                           u,u,u
token:ca_audit_signing                                       u,u,Pu
token:sslserver/server.example.com                           u,u,u
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
    --pkcs12-password Secret.123
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
