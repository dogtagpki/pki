Installing KRA
==============

Overview
--------

This page describes the process to install a KRA subsystem.

KRA Subsystem Installation
--------------------------

Prepare a file (e.g. kra.cfg) that contains the deployment configuration.
A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/kra.cfg](../../../base/server/examples/installation/kra.cfg).

Then execute the following command:

```
$ pkispawn -f kra.cfg -s KRA
```

It will install KRA subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/kra/alias

**Note**: When KRA is installed on a new system without any other subsystems,
it is necessary to provide the CA's root certificate. Specify the path to
the CA PKCS#7 PEM file in the `pki_cert_chain_path`. This will allow the server
to verify the CA's SSL server certificate when contacting the security domain.
It is up to the administrator to securely transport the CA root certificate
(public key only!) to the system prior to KRA installation.

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
kra_transport                                                u,u,u
kra_storage                                                  u,u,u
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
