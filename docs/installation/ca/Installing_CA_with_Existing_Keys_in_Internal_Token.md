Installing CA with Existing Keys in Internal Token
==================================================

Overview
--------

This page describes the process to install a CA subsystem with the system keys, CSRs, and certificates from an existing CA
where the keys are stored in internal token.

To avoid conflicts with the existing CA subsystem, the new CA subsystem will use new SSL server and subsystem certificates,
so they will not be included in the installation process.

Starting CA Subsystem Installation
----------------------------------

Prepare a file (e.g. ca-existing-certs-step1.cfg) that contains the first deployment configuration.

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/ca-existing-certs-step1.cfg](../../../base/server/examples/installation/ca-existing-certs-step1.cfg).

Then execute the following command:

```
$ pkispawn -f ca-existing-certs-step1.cfg -s CA
```

It will install CA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/ca/alias

Since there are no CSR path parameters specified, it will not generate CA system and admin keys.

Exporting Existing System Keys, CSRs, Certificates
--------------------------------------------------

Export the system keys and certificates from the existing CA into a PKCS #12 file with the following command:

```
$ pki -d /etc/pki/pki-tomcat/alias -c Secret.123 pkcs12-export \
  --pkcs12 ca-certs.p12 \
  --password Secret.123
$ pki pkcs12-cert-del --pkcs12-file ca-certs.p12 --pkcs12-password Secret.123 sslserver
$ pki pkcs12-cert-del --pkcs12-file ca-certs.p12 --pkcs12-password Secret.123 subsystem
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

Prepare another file (e.g. ca-existing-certs-step2.cfg) that contains the second deployment configuration.
The file can be created from the first file (i.e. ca-existing-certs-step1.cfg) with the following changes:

```
pki_external_step_two=True
```

Specify the existing keys and certificates in the PKCS #12 file with the following parameters:

```
pki_pkcs12_path=ca-certs.p12
pki_pkcs12_password=Secret.123
```

Specify the existing CSRs with the following parameters:

```
pki_ca_signing_csr_path=ca_signing.csr
pki_ocsp_signing_csr_path=ca_ocsp_signing.csr
pki_audit_signing_csr_path=ca_audit_signing.csr
```

Specify the serial number starting range such that new certificates will not conflict with the existing certificates:

```
pki_serial_number_range_start=4
```

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/ca-existing-certs-step2.cfg](../../../base/server/examples/installation/ca-existing-certs-step2.cfg).

Finally, execute the following command:

```
$ pkispawn -f ca-existing-certs-step2.cfg -s CA
```

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
