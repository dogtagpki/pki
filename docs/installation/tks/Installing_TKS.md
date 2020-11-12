Installing TKS
==============

Overview
--------

This page describes the process to install a TKS subsystem.

TKS Subsystem Installation
--------------------------

Prepare a file (e.g. tks.cfg) that contains the deployment configuration.
A sample deployment configuration is available at [/usr/share/pki/server/examples/installation/tks.cfg](../../../base/server/examples/installation/tks.cfg).

Then execute the following command:

```
$ pkispawn -f tks.cfg -s TKS
```

It will install TKS subsystem in a Tomcat instance (default is pki-tomcat) and create the following NSS databases:
* server NSS database: /etc/pki/pki-tomcat/alias
* admin NSS database: ~/.dogtag/pki-tomcat/tks/alias

**Note**: When TKS is installed on a new system without any other subsystems,
it is necessary to provide the CA's root certificate. Specify the path to
the CA PKCS#7 PEM file in the `pki_cert_chain_path`. This will allow the server
to verify the CA's SSL server certificate when contacting the security domain.
It is up to the administrator to securely transport the CA root certificate
(public key only!) to the system prior to TKS installation.

Verifying System Certificates
-----------------------------

Verify that the server NSS database contains the following certificates:

```
$ certutil -L -d /etc/pki/pki-tomcat/alias

Certificate Nickname                                         Trust Attributes
                                                             SSL,S/MIME,JAR/XPI

ca_signing                                                   CT,C,C
subsystem                                                    u,u,u
tks_audit_signing                                            u,u,Pu
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

Verify that the admin certificate can be used to access the TKS subsystem by executing the following command:

```
$ pki -c Secret.123 -n caadmin tks-user-show tksadmin
---------------
User "tksadmin"
---------------
  User ID: tksadmin
  Full name: tksadmin
  Email: tksadmin@example.com
  Type: adminType
  State: 1
```
