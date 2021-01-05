Installing OCSP with External Certificates
==========================================

Overview
--------

This page describes the process to install a OCSP subsystem with external certificates.

Starting OCSP Subsystem Installation
------------------------------------

Prepare a file (e.g. ocsp-external-certs-step1.cfg) that contains the first deployment configuration.

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/ocsp-external-certs-step1.cfg](../../../base/server/examples/installation/ocsp-external-certs-step1.cfg).
It assumes that the CA is running at https://ca.example.com:8443,
and the CA signing certificate has been exported into `ca_signing.crt`.

Then execute the following command:

```
$ pkispawn -f ocsp-external-certs-step1.cfg -s OCSP
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

Prepare another file (e.g. ocsp-external-certs-step2.cfg) that contains the second deployment configuration.
The file can be created from the first file (i.e. ocsp-external-certs-step1.cfg) with the following changes:

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

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/ocsp-external-certs-step2.cfg](../../../base/server/examples/installation/ocsp-external-certs-step2.cfg).

Finally, execute the following command:

```
$ pkispawn -f ocsp-external-certs-step2.cfg -s OCSP
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
