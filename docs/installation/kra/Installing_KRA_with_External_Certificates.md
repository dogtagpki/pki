Installing KRA with External Certificates
=========================================

Overview
--------

This page describes the process to install a KRA subsystem with external certificates.

Starting KRA Subsystem Installation
-----------------------------------

Prepare a file (e.g. kra-external-certs-step1.cfg) that contains the first deployment configuration.

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/kra-external-certs-step1.cfg](../../../base/server/examples/installation/kra-external-certs-step1.cfg).
It assumes that the CA is running at https://ca.example.com:8443,
and the CA signing certificate has been exported into `ca_signing.crt`.

Then execute the following command:

```
$ pkispawn -f kra-external-certs-step1.cfg -s KRA
```

It will install KRA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/dogtag/pki-tomcat/kra/alias

It will also generate the system keys in the server NSS database and the CSRs in the specified paths.

Generating KRA Certificates
---------------------------

Submit the CSRs to an external CA to issue the certificates, then store the certificates in files, for example:
* kra_storage.crt
* kra_transport.crt
* subsystem.crt
* sslserver.crt
* kra_audit_signing.crt
* kra_admin.crt

The certificates can be specified as single certificates or PKCS #7 certificate chains in PEM format.

Store the external CA certificate chain in a file (e.g. ca_signing.crt). The certificate chain can be specified as a single certificate or PKCS #7 certificate chain in PEM format. The certificate chain should include all CA certificates from the root CA to the external CA that issued the KRA system and admin certificates.

Finishing KRA Subsystem Installation
------------------------------------

Prepare another file (e.g. kra-external-certs-step2.cfg) that contains the second deployment configuration.
The file can be created from the first file (i.e. kra-external-certs-step1.cfg) with the following changes:

```
pki_external_step_two=True
```

Specify the external certificates with the following parameters:

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

A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/kra-external-certs-step2.cfg](../../../base/server/examples/installation/kra-external-certs-step2.cfg).

Finally, execute the following command:

```
$ pkispawn -f kra-external-certs-step2.cfg -s KRA
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

Import the CA certificate chain:

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

Verifying KRA Connector
-----------------------

Verify that the KRA connector is configured in the CA subsystem:

```
$ pki -c Secret.123 -n caadmin ca-kraconnector-show

Host: kra.example.com:8443
Enabled: true
Local: false
Timeout: 30
URI: /kra/agent/kra/connector
Transport Cert:

<base-64 certificate>
```
