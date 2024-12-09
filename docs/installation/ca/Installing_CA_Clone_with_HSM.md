This page has been converted/moved to [Installing_CA_Clone_with_HSM.adoc](../ca/Installing_CA_Clone_with_HSM.adoc)
Remove the following content after finalizing.

Installing CA Clone with HSM
============================

Overview
--------

This page describes the process to install a CA subsystem as a clone of an existing CA subsystem
where the system certificates and their keys are stored in HSM.

Exporting Existing System Certificates
--------------------------------------

Since the system certificates and the keys are already in HSM, it's not necessary to export them into a
PKCS #12 file to create a clone.

However, the CSRs for the system certificates are stored in `CS.cfg` instead of HSM.
They can optionally be exported with the following commands:

```
$ pki-server cert-export ca_signing \
    --csr-file ca_signing.csr

$ pki-server cert-export ca_ocsp_signing \
    --csr-file ca_ocsp_signing.csr

$ pki-server cert-export ca_audit_signing \
    --csr-file ca_audit_signing.csr

$ pki-server cert-export subsystem \
    --csr-file subsystem.csr
```

CA Subsystem Installation
-------------------------

Prepare a file (e.g. ca.cfg) that contains the deployment configuration, for example:

```
[DEFAULT]
pki_server_database_password=Secret.123

pki_hsm_enable=True
pki_hsm_libfile=/usr/lib64/pkcs11/libsofthsm2.so
pki_hsm_modulename=softhsm
pki_token_name=HSM
pki_token_password=Secret.HSM

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

pki_security_domain_hostname=pki.example.com
pki_security_domain_https_port=8443
pki_security_domain_user=caadmin
pki_security_domain_password=Secret.123

pki_ca_signing_nickname=ca_signing
pki_ocsp_signing_nickname=ca_ocsp_signing
pki_audit_signing_nickname=ca_audit_signing
pki_sslserver_nickname=sslserver/replica.example.com
pki_subsystem_nickname=subsystem

pki_clone=True
pki_clone_replicate_schema=True
pki_clone_uri=https://pki.example.com:8443
```

If the CSRs are available, they can be specified with the following parameters:

```
pki_ca_signing_csr_path=ca_signing.csr
pki_ocsp_signing_csr_path=ca_ocsp_signing.csr
pki_audit_signing_csr_path=ca_audit_signing.csr
pki_subsystem_csr_path=subsystem.csr
```

Then execute the following command:

```
$ pkispawn -f ca.cfg -s CA
```

It will install CA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /var/lib/pki/pki-tomcat/conf/alias
* admin NSS database: ~/.dogtag/pki-tomcat/ca/alias

Verifying System Certificates
-----------------------------

Verify that the internal token contains the following certificates:

```
$ certutil -L -d /var/lib/pki/pki-tomcat/conf/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
ca_audit_signing                                             ,,P
```

Verify that the HSM contains the following certificates:

```
$ certutil -L -d /var/lib/pki/pki-tomcat/conf/alias -h HSM -f HSM.pwd

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

HSM:ca_signing                                               CTu,Cu,Cu
HSM:ca_ocsp_signing                                          u,u,u
HSM:subsystem                                                u,u,u
HSM:ca_audit_signing                                         u,u,Pu
HSM:sslserver/replica.example.com                            u,u,u
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
$ pki -c Secret.123 pkcs12-import \
    --pkcs12 ca_admin_cert.p12 \
    --pkcs12-password Secret.123
```

Verify that the admin certificate can be used to access the CA clone by executing the following command:

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
