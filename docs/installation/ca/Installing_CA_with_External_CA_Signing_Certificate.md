Installing CA with External CA Signing Certificate
==================================================

Overview
--------

This page describes the process to install a CA subsystem with an external CA signing certificate.

Starting CA Subsystem Installation
----------------------------------

Prepare a file (e.g. external-ca-step1.cfg) that contains the first deployment configuration.

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/ca-external-cert-step1.cfg](../../../base/server/examples/installation/ca-external-cert-step1.cfg).

Then execute the following command:

```
$ pkispawn -f ca-external-cert-step1.cfg -s CA
```

It will install CA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/ca/alias

It will also generate the CA signing key in the server NSS database and the CSR in the specified path.

Generating CA Signing Certificate
---------------------------------

Use the CSR to issue the CA signing certificate:
* for root CA installation, generate a self-signed CA signing certificate
* for subordinate CA installation, submit the CSR to an external CA to issue the CA signing certificate

Store the CA signing certificate in a file (e.g. ca_signing.crt).
The CA signing certificate can be specified as a single certificate or a PKCS #7 certificate chain in PEM format.

If the CA signing certificate was issued by an external CA, store the external CA certificate chain in a file (e.g. root-ca_signing.crt).
The certificate chain can be specified as a single certificate or a PKCS #7 certificate chain in PEM format.
The certificate chain should include all CA certificates from the root CA to the external CA that issued the CA signing certificate,
but it should not include the CA signing certificate itself.

See also:
* [Generating CA Signing Certificate](https://github.com/dogtagpki/pki/wiki/Generating-CA-Signing-Certificate)

Finishing CA Subsystem Installation
-----------------------------------

Prepare another file (e.g. ca-external-cert-step2.cfg) that contains the second deployment configuration.
The file can be created from the first file (i.e. ca-external-cert-step1.cfg) with the following changes:

```
pki_external_step_two=True
```

Specify the custom CA signing certificate with the following parameter:

```
pki_ca_signing_cert_path=ca_signing.crt
```

If the CA signing certificate was issued by an external CA, specify the external CA certificate chain with the following parameters:

```
pki_cert_chain_nickname=root-ca_signing
pki_cert_chain_path=root-ca_signing.crt
```

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/ca-external-cert-step2.cfg](../../../base/server/examples/installation/ca-external-cert-step2.cfg).

Finally, execute the following command:

```
$ pkispawn -f ca-external-cert-step2.cfg -s CA
```

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

root-ca_signing                                              CT,C,C
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

Import the external CA certificate chain:

```
$ pki -c Secret.123 client-cert-import --ca-cert root-ca_signing.crt
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
