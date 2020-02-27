Installing OCSP Clone with HSM
==============================

Overview
--------

This page describes the process to install an OCSP subsystem as a clone of an existing OCSP subsystem
where the system certificates and their keys are stored in HSM.

Since the certificates and the keys are already in HSM, it's not necessary to export them into a
PKCS #12 file to create a clone.

OCSP Subsystem Installation
---------------------------

Prepare a file (e.g. ocsp.cfg) that contains the deployment configuration, for example:

```
[DEFAULT]
pki_server_database_password=Secret.123

pki_hsm_enable=True
pki_hsm_libfile=/usr/lib64/pkcs11/libsofthsm2.so
pki_hsm_modulename=softhsm
pki_token_name=token
pki_token_password=Secret.123

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
pki_audit_signing_nickname=ocsp_audit_signing
pki_sslserver_nickname=sslserver/replica.example.com
pki_subsystem_nickname=subsystem

pki_clone=True
pki_clone_replicate_schema=True
pki_clone_uri=https://server.example.com:8443
```

Then execute the following command:

```
$ pkispawn -f ocsp.cfg -s OCSP
```

It will install OCSP subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/ocsp/alias

Verifying System Certificates
-----------------------------

Verify that the internal token contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
ocsp_audit_signing                                           ,,P
```

Verify that the HSM contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias -h token -f token.pwd

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

token:ocsp_signing                                           u,u,u
token:subsystem                                              u,u,u
token:ocsp_audit_signing                                     u,u,Pu
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

Verify that the admin certificate can be used to access the OCSP subsystem by executing the following command:

```
$ pki -c Secret.123 -n caadmin ocsp-user-show ocspadmin
----------------
User "ocspadmin"
----------------
  User ID: ocspadmin
  Full name: ocspadmin
  Email: ocspadmin@example.com
  Type: adminType
  State: 1
```

Verifying OCSP Client
---------------------

Publish the CRL in CA to the directory server as follows:

* Go to CA Agent UI (https://server.example.com:8443/ca/agent/ca/).
* Click **Update Directory Server**.
* Select **Update the certificate revocation list to the directory**.
* Click **Update Directory**.

Verify that the OCSPClient can be used to validate a certificate:

```
$ OCSPClient \
 -d /etc/pki/pki-tomcat/alias \
 -h server.example.com \
 -p 8080 \
 -t /ocsp/ee/ocsp \
 -c ca_signing \
 --serial 1
CertID.serialNumber=1
CertStatus=Good
```
